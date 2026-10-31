#!/usr/bin/env python3
"""Read-only inventory, exact duplicate, and file growth evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socketserver
import stat
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
STATE_DIR = Path.home() / ".disk-evidence"
SETTINGS_FILE = STATE_DIR / "settings.json"
HISTORY_FILE = STATE_DIR / "scan-history.json"
MAX_REQUEST = 12_000
DEFAULT_LIMITS = {"max_files":5000,"max_bytes":500_000_000,"max_seconds":10}
HARD_LIMITS = {"max_files":20_000,"max_bytes":2_000_000_000,"max_seconds":25}
CHUNK_SIZE = 1024 * 1024
DEFAULT_EXCLUDES = {".git",".svn",".hg","node_modules",".venv","venv","__pycache__"}
STATE_LOCK = threading.RLock()
SAFE_NAME = re.compile(r"^[^/\\\x00]{1,120}$")


class ScanLimit(Exception):
    pass


def checked_root(raw: str | Path) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute(): path = Path.cwd() / path
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode): raise ValueError("Scan roots cannot contain symbolic links.")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode): raise ValueError("Scan root must be a directory.")
    return path


def validate_exclusions(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 50: raise ValueError("Use at most 50 relative exclusions.")
    result=[]
    for item in value:
        if not isinstance(item,str) or len(item)>180 or not item or item.startswith(("/","\\")) or "\\" in item:
            raise ValueError("Exclusions must be relative paths within the selected folder.")
        parsed=PurePosixPath(item)
        if any(part in ("..",".") for part in item.split("/")) or parsed.is_absolute():
            raise ValueError("Exclusions cannot leave the selected folder.")
        if item not in result: result.append(item)
    return result


def validate_limits(value: object) -> dict:
    if not isinstance(value,dict): raise ValueError("Scan limits must be an object.")
    result={}
    for key in DEFAULT_LIMITS:
        raw=value.get(key,DEFAULT_LIMITS[key])
        if isinstance(raw,bool) or not isinstance(raw,int): raise ValueError(f"{key} must be a whole number.")
        minimum=1
        if raw<minimum or raw>HARD_LIMITS[key]: raise ValueError(f"{key} must be between {minimum} and {HARD_LIMITS[key]}.")
        result[key]=raw
    return result


def _private_state() -> None:
    if STATE_DIR.is_symlink(): raise OSError("Private state folder cannot be a symbolic link.")
    STATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True);STATE_DIR.chmod(0o700)


def _read_json(path: Path, default):
    if path.parent == STATE_DIR:
        _private_state()
    if path.is_symlink() or not path.is_file(): return default
    try:
        with path.open(encoding="utf-8") as stream: data=json.load(stream)
        return data
    except (OSError,json.JSONDecodeError): return default


def _write_json(path: Path, value) -> None:
    _private_state();tmp=path.with_suffix(path.suffix+".tmp")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as stream:json.dump(value,stream,indent=2)
    os.replace(tmp,path);path.chmod(0o600)


def root_id(root: Path) -> str:
    return hashlib.sha256(str(root).encode()).hexdigest()


def load_config(root: Path) -> dict:
    with STATE_LOCK:
        data=_read_json(SETTINGS_FILE,{})
        entry=data.get(root_id(root),{}) if isinstance(data,dict) else {}
        try:
            excludes=validate_exclusions(entry.get("exclusions",[]));limits=validate_limits(entry.get("limits",DEFAULT_LIMITS))
        except (ValueError,AttributeError): excludes=[];limits=DEFAULT_LIMITS.copy()
        return {"exclusions":excludes,"limits":limits}


def save_config(root: Path, exclusions: object, limits: object) -> dict:
    values={"exclusions":validate_exclusions(exclusions),"limits":validate_limits(limits)}
    with STATE_LOCK:
        data=_read_json(SETTINGS_FILE,{})
        if not isinstance(data,dict):data={}
        data[root_id(root)]=values;_write_json(SETTINGS_FILE,data)
    return values


def _open_root(root: Path) -> int:
    before=root.lstat()
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode): raise ValueError("Scan root changed or is a link.")
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(root,flags)
    after=os.fstat(fd)
    if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):os.close(fd);raise ValueError("Scan root changed during the scan.")
    return fd


def _safe_hash_at(root_fd: int, relative: str, byte_budget: int | None = None, deadline: float | None = None) -> tuple[str,int,int]:
    parts=PurePosixPath(relative).parts
    if not parts or any(part in (".","..") for part in parts): raise ValueError("Invalid relative file path.")
    directory=os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=directory)
            os.close(directory);directory=child
        fd=os.open(parts[-1],os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0),dir_fd=directory)
    finally:os.close(directory)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):raise ValueError("Only regular files can be read.")
        hasher=hashlib.sha256();total=0
        while True:
            if deadline is not None and time.monotonic()>deadline: raise ScanLimit("Time limit reached while reading a file.")
            chunk=os.read(fd,CHUNK_SIZE)
            if not chunk:break
            total+=len(chunk)
            if byte_budget is not None and total>byte_budget:raise ScanLimit("Byte limit reached while reading a file.")
            hasher.update(chunk)
        after=os.fstat(fd)
        changed=(before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino)
        if changed:raise ValueError("File changed during read.")
        return hasher.hexdigest(),total,before.st_mtime_ns
    finally:os.close(fd)


def _path_is_excluded(relative: str, exclusions: set[str]) -> bool:
    return any(relative==exclude or relative.startswith(exclude.rstrip("/")+"/") for exclude in exclusions)


def _history_for(root: Path) -> dict:
    data=_read_json(HISTORY_FILE,{})
    return data.get(root_id(root),{}) if isinstance(data,dict) else {}


def _store_history(root: Path, rows: dict) -> None:
    with STATE_LOCK:
        data=_read_json(HISTORY_FILE,{})
        if not isinstance(data,dict):data={}
        data[root_id(root)]={"saved_at":datetime.now(timezone.utc).isoformat(),"files":rows}
        _write_json(HISTORY_FILE,data)


def scan(root: Path, exclusions: object = None, limits: object = None) -> dict:
    root=checked_root(root)
    cfg=load_config(root)
    excluded=validate_exclusions(cfg["exclusions"] if exclusions is None else exclusions)
    bounds=validate_limits(cfg["limits"] if limits is None else limits)
    excluded_set=DEFAULT_EXCLUDES|set(excluded)
    started=time.monotonic();deadline=started+bounds["max_seconds"]
    root_fd=_open_root(root)
    files=[];excluded_count=0;errors=[];incomplete=[];bytes_read=0
    def walk(dir_fd: int, prefix: str=""):
        nonlocal excluded_count,bytes_read
        try: entries=os.scandir(dir_fd)
        except OSError as exc:
            errors.append({"path":prefix or ".","reason":"Directory could not be read."});incomplete.append("directory access");return
        with entries:
            for entry in entries:
                if time.monotonic()>deadline:incomplete.append("time limit");return
                rel=f"{prefix}/{entry.name}" if prefix else entry.name
                if _path_is_excluded(rel,excluded_set) or entry.name in DEFAULT_EXCLUDES:
                    excluded_count+=1;continue
                try: info=entry.stat(follow_symlinks=False)
                except OSError:
                    errors.append({"path":rel,"reason":"Entry metadata changed during scan."});incomplete.append("filesystem changes");continue
                if stat.S_ISLNK(info.st_mode):excluded_count+=1;continue
                if stat.S_ISDIR(info.st_mode):
                    try:child=os.open(entry.name,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=dir_fd)
                    except OSError:
                        errors.append({"path":rel,"reason":"Directory changed or could not be opened safely."});incomplete.append("filesystem changes");continue
                    try:walk(child,rel)
                    finally:os.close(child)
                    if incomplete and ("time limit" in incomplete or "file limit" in incomplete or "byte limit" in incomplete):return
                elif stat.S_ISREG(info.st_mode):
                    if len(files)>=bounds["max_files"]:incomplete.append("file limit");return
                    if info.st_size>bounds["max_bytes"]-bytes_read:incomplete.append("byte limit");return
                    try:
                        digest,size,mtime=_safe_hash_at(root_fd,rel,bounds["max_bytes"]-bytes_read,deadline)
                    except ScanLimit:
                        incomplete.append("time limit" if time.monotonic()>deadline else "byte limit");return
                    except (OSError,ValueError):
                        errors.append({"path":rel,"reason":"File changed, exceeded the byte limit, or could not be read safely."});incomplete.append("file read");continue
                    bytes_read+=size
                    files.append({"path":rel,"name":entry.name,"size":size,"sha256":digest,"mtime_ns":mtime})
        return
    try:walk(root_fd)
    finally:os.close(root_fd)
    previous=_history_for(root)
    old_files=previous.get("files",{}) if isinstance(previous,dict) else {}
    growth=[]
    for item in files:
        old=old_files.get(item["path"]) if isinstance(old_files,dict) else None
        if isinstance(old,dict) and isinstance(old.get("size"),int) and item["size"]>old["size"]:
            growth.append({"path":item["path"],"previous_size":old["size"],"current_size":item["size"],"growth_bytes":item["size"]-old["size"],"sha256":item["sha256"]})
    hash_groups={}
    name_groups={}
    for item in files:
        hash_groups.setdefault(item["sha256"],[]).append(item)
        name_groups.setdefault(item["name"],[]).append(item)
    duplicates=[{"sha256":digest,"size":rows[0]["size"],"paths":[row["path"] for row in rows]} for digest,rows in hash_groups.items() if len(rows)>1]
    same_name=[{"name":name,"files":[{"path":row["path"],"size":row["size"],"sha256":row["sha256"]} for row in rows]} for name,rows in name_groups.items() if len(rows)>1 and len({r["sha256"] for r in rows})>1]
    completed=not incomplete and not errors
    if completed:_store_history(root,{item["path"]:{"size":item["size"],"sha256":item["sha256"]} for item in files})
    now=datetime.now(timezone.utc).isoformat()
    return {"scan_id":secrets.token_hex(10),"scanned_at":now,"root_label":root.name or str(root),"scope":"Explicit startup folder; relative paths only. Symbolic links are skipped.","complete":completed,"incomplete_reasons":sorted(set(incomplete+(["read errors"] if errors else []))),"limits":bounds,"exclusions":sorted(excluded_set),"summary":{"files":len(files),"bytes_hashed":bytes_read,"excluded_entries":excluded_count,"exact_duplicate_groups":len(duplicates),"same_name_different_content_groups":len(same_name),"growth_paths":len(growth),"errors":len(errors),"elapsed_seconds":round(time.monotonic()-started,3)},"files":files,"duplicates":duplicates,"same_name_different_content":same_name,"growth":growth,"errors":errors,"history_status":"updated" if completed else "not updated because scan was incomplete"}


def draft_plan(root: Path, result: dict, selections: object) -> dict:
    if not isinstance(selections,list) or len(selections)>500:raise ValueError("Duplicate group selections are invalid.")
    by_hash={group["sha256"]:group for group in result.get("duplicates",[]) if isinstance(group,dict)}
    root_fd=_open_root(checked_root(root));plans=[]
    max_bytes=min(int(result.get("limits",{}).get("max_bytes",DEFAULT_LIMITS["max_bytes"])),HARD_LIMITS["max_bytes"])
    deadline=time.monotonic()+min(int(result.get("limits",{}).get("max_seconds",DEFAULT_LIMITS["max_seconds"])),HARD_LIMITS["max_seconds"])
    remaining=max_bytes
    try:
        for choice in selections:
            if not isinstance(choice,dict):raise ValueError("Each plan choice must be an object.")
            digest=choice.get("sha256");retain=choice.get("retain")
            group=by_hash.get(digest)
            if group is None or retain not in group["paths"]:raise ValueError("Plan selection does not match this scan.")
            status="passed";reason="All files still match the scanned digest."
            for path in group["paths"]:
                try: current,size,_mtime=_safe_hash_at(root_fd,path,min(remaining,group["size"]+1),deadline)
                except (OSError,ValueError):status="stale";reason="A file is missing or no longer safe to read.";break
                except ScanLimit:status="stale";reason="The recheck reached its byte or time limit.";break
                remaining-=size
                if current!=digest or size!=group["size"]:status="stale";reason="A file changed since the scan.";break
            plans.append({"sha256":digest,"size":group["size"],"retained_copy":retain,"proposed_duplicates":[path for path in group["paths"] if path!=retain],"recheck_status":status,"reason":reason,"action":"review only; no file changes made"})
    finally:os.close(root_fd)
    return {"created_at":datetime.now(timezone.utc).isoformat(),"root_label":result.get("root_label"),"source_scan_id":result.get("scan_id"),"plan_type":"dry-run cleanup proposal","entries":plans,"deletion_performed":False}


def grow_demo_log(root: Path) -> dict:
    root=checked_root(root);root_fd=_open_root(root)
    try:
        logs_fd=os.open("logs",os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=root_fd)
        try:
            fd=os.open("activity.log",os.O_WRONLY|os.O_APPEND|getattr(os,"O_NOFOLLOW",0),dir_fd=logs_fd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):raise ValueError("Demo log is not a regular file.")
                os.write(fd,b"synthetic growth event\n")
            finally:os.close(fd)
        finally:os.close(logs_fd)
    finally:os.close(root_fd)
    return {"grown":True,"message":"Added one synthetic line to the demo log."}


def seed_demo(root: Path) -> None:
    if root.exists():return
    root.mkdir(mode=0o700,parents=True)
    content=b"synthetic duplicate fixture\n"
    (root/"exports").mkdir();(root/"copies").mkdir();(root/"projects/a").mkdir(parents=True);(root/"projects/b").mkdir(parents=True);(root/"logs").mkdir()
    (root/"exports/snapshot.txt").write_bytes(content);(root/"copies/snapshot-copy.dat").write_bytes(content)
    (root/"projects/a/config.json").write_text('{"mode":"demo-a"}\n');(root/"projects/b/config.json").write_text('{"mode":"demo-b"}\n')
    (root/"logs/activity.log").write_text("synthetic demo log start\n")


class Handler(BaseHTTPRequestHandler):
    server_version="DiskEvidence/1.0"
    def log_message(self,fmt,*args):return
    def send_json(self,status,data):
        raw=json.dumps(data,ensure_ascii=False).encode();self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff");self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'");self.end_headers();self.wfile.write(raw)
    def allowed_host(self):
        port=self.server.server_port
        return self.headers.get("Host") in (f"127.0.0.1:{port}",f"localhost:{port}")
    def state_allowed(self):
        port=self.server.server_port
        origins=(f"http://127.0.0.1:{port}",f"http://localhost:{port}")
        return self.allowed_host() and self.headers.get("Origin") in origins and secrets.compare_digest(self.headers.get("X-Disk-Evidence-Request",""),self.server.request_token)
    def do_GET(self):
        if not self.allowed_host():return self.send_error(403)
        route=urlsplit(self.path).path
        if route=="/":
            page=(ROOT/"index.html").read_text(encoding="utf-8").replace("__TOKEN__",self.server.request_token).replace("__DEMO__","true" if self.server.is_demo else "false")
            raw=page.encode();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-store");self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'");self.end_headers();self.wfile.write(raw);return
        for filename,kind in (("app.css","text/css"),("app.js","text/javascript")):
            if route=="/"+filename:
                raw=(ROOT/filename).read_bytes();self.send_response(200);self.send_header("Content-Type",kind);self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw);return
        return self.send_error(404)
    def do_POST(self):
        with self.server.state_lock:
            return self._do_post_locked()

    def _do_post_locked(self):
        if not self.state_allowed():return self.send_json(403,{"error":"Local request check failed."})
        try:size=int(self.headers.get("Content-Length","0"))
        except ValueError:return self.send_json(400,{"error":"Invalid request size."})
        if size<1 or size>MAX_REQUEST:return self.send_json(413,{"error":"Request is too large."})
        try:
            data=json.loads(self.rfile.read(size))
            if not isinstance(data,dict):raise ValueError("Request body must be a JSON object.")
            if self.path=="/api/config":return self.send_json(200,load_config(self.server.scan_root))
            if self.path=="/api/settings":
                result=save_config(self.server.scan_root,data.get("exclusions"),data.get("limits"));self.server.last_scan=None;self.server.last_plan=None;return self.send_json(200,result)
            if self.path=="/api/scan":
                result=scan(self.server.scan_root);self.server.last_scan=result;self.server.last_plan=None;return self.send_json(200,result)
            if self.path=="/api/plan":
                if not isinstance(self.server.last_scan,dict):raise ValueError("Run a scan before drafting a plan.")
                result=draft_plan(self.server.scan_root,self.server.last_scan,data.get("selections"));self.server.last_plan=result;return self.send_json(200,result)
            if self.path=="/api/demo/grow":
                if not self.server.is_demo:raise ValueError("Demo actions are disabled for an explicitly selected folder.")
                return self.send_json(200,grow_demo_log(self.server.scan_root))
            if self.path=="/api/export":
                scan_data=self.server.last_scan
                if not isinstance(scan_data,dict):raise ValueError("Run a scan before export.")
                return self.send_json(200,{"scan":scan_data,"plan":self.server.last_plan})
            return self.send_json(404,{"error":"Unknown action."})
        except (ValueError,TypeError,ScanLimit) as exc:return self.send_json(400,{"error":str(exc)})
        except OSError:return self.send_json(400,{"error":"A file changed or could not be read safely."})


def make_server(root_arg: str | Path | None = None, port: int = 8315) -> ThreadingHTTPServer:
    is_demo=root_arg is None
    if is_demo:
        root=STATE_DIR/"demo";seed_demo(root);root=checked_root(root)
    else:root=checked_root(root_arg)
    class LocalServer(ThreadingHTTPServer):
        daemon_threads = True
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name = "127.0.0.1"
            self.server_port = self.socket.getsockname()[1]
    server=LocalServer(("127.0.0.1",port),Handler);server.request_token=secrets.token_urlsafe(32);server.scan_root=root;server.is_demo=is_demo;server.last_scan=None;server.last_plan=None;server.state_lock=threading.RLock()
    return server


def serve(root_arg: str | None):
    server=make_server(root_arg,8315)
    print(f"Disk Evidence: http://127.0.0.1:{server.server_port} ({'synthetic demo' if server.is_demo else 'selected folder'})",flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--root",help="Explicit folder to scan. Omit to use the synthetic demo.");parser.add_argument("serve",nargs="?",choices=("serve",),default="serve");args=parser.parse_args();serve(args.root)


if __name__=="__main__":main()
