#!/usr/bin/env python3
# 115 云下载中转服务（带网页登录）
# 依赖：fastapi uvicorn p115client segno
import hashlib
import hmac
import io
import json
import os
import random
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

import segno
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from pydantic import BaseModel
from p115client import P115Client

BASE = Path(os.environ.get("DATA_DIR", "/opt/115dl"))
COOKIE_FILE = BASE / "cookies.txt"
SETTINGS_FILE = BASE / "settings.json"
TOKEN = os.environ.get("API_TOKEN", "")
AI_BASE = os.environ.get("AI_BASE_URL", "").rstrip("/")
AI_KEY = os.environ.get("AI_API_KEY", "")
AI_MODEL = os.environ.get("AI_MODEL", "deepseek-v4.1-flash")

# 改名限流（防 115 风控）
RENAME_MIN_INTERVAL = float(os.environ.get("RENAME_MIN_INTERVAL", "2.5"))
RENAME_MAX_PER_MIN = int(os.environ.get("RENAME_MAX_PER_MIN", "20"))
RENAME_MAX_PER_HOUR = int(os.environ.get("RENAME_MAX_PER_HOUR", "180"))

_rename_lock = threading.Lock()
_rename_times: deque[float] = deque()
_rename_block_until = 0.0


def rename_gate():
    now = time.time()
    if _rename_block_until > now:
        left = _rename_block_until - now
        raise HTTPException(
            429, {"message": "115 触发风控，改名暂时停用", "retry_after": round(left, 1)}
        )
    while _rename_times and now - _rename_times[0] > 3600:
        _rename_times.popleft()
    if _rename_times:
        wait = RENAME_MIN_INTERVAL - (now - _rename_times[-1])
        if wait > 0:
            raise HTTPException(
                429, {"message": "操作太快了，缓一下", "retry_after": round(wait, 1)}
            )
    per_min = sum(1 for t in _rename_times if now - t < 60)
    if per_min >= RENAME_MAX_PER_MIN:
        raise HTTPException(
            429, {"message": "每分钟改名次数已达上限", "retry_after": 60}
        )
    if len(_rename_times) >= RENAME_MAX_PER_HOUR:
        raise HTTPException(
            429, {"message": "每小时改名次数已达上限", "retry_after": 600}
        )
SESSION_TTL = 10 * 365 * 86400  # 登录保持 10 年（等同永久）
START_TS = time.time()

app = FastAPI(title="115 cloud download relay")
_client: P115Client | None = None
_login_state: dict = {}
_folder_cache: dict[str, tuple[float, dict]] = {}
FOLDER_TTL = 600  # 文件夹列表缓存 10 分钟


# ---------- 设置与口令 ----------
def read_settings() -> dict:
    try:
        return json.loads(SETTINGS_FILE.read_text())
    except Exception:  # noqa: BLE001
        return {}


def write_settings(data: dict):
    BASE.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(SETTINGS_FILE)


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 120_000
    ).hex()
    return salt, digest


def get_secret() -> str:
    s = read_settings()
    if not s.get("secret"):
        s["secret"] = secrets.token_hex(32)
        write_settings(s)
    return s["secret"]


def ensure_auth():
    s = read_settings()
    if s.get("auth"):
        get_secret()
        return
    password = secrets.token_urlsafe(9)
    salt, digest = hash_password(password)
    s["auth"] = {"user": "admin", "salt": salt, "hash": digest}
    write_settings(s)
    get_secret()
    (BASE / "initial_password.txt").write_text(f"admin / {password}\n")
    print(f"[init] web login: admin / {password}", flush=True)


def verify_password(user: str, password: str) -> bool:
    s = read_settings().get("auth") or {}
    if not s or user != s.get("user"):
        return False
    _, digest = hash_password(password, s.get("salt", ""))
    return hmac.compare_digest(digest, s.get("hash", ""))


def set_password(user: str, password: str):
    salt, digest = hash_password(password)
    s = read_settings()
    s["auth"] = {"user": user, "salt": salt, "hash": digest}
    write_settings(s)


# ---------- 会话 ----------
def make_session(user: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    msg = f"{user}:{exp}"
    sig = hmac.new(get_secret().encode(), msg.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{msg}:{sig}"


def check_session(cookie: str | None) -> str | None:
    if not cookie:
        return None
    try:
        user, exp, sig = cookie.split(":")
        if int(exp) < time.time():
            return None
        msg = f"{user}:{exp}"
        good = hmac.new(
            get_secret().encode(), msg.encode(), hashlib.sha256
        ).hexdigest()[:32]
        return user if hmac.compare_digest(sig, good) else None
    except Exception:  # noqa: BLE001
        return None


def authed(request: Request) -> bool:
    token = request.query_params.get("token") or request.headers.get("x-token")
    if TOKEN and token == TOKEN:
        return True
    return check_session(request.cookies.get("sess")) is not None


def client_info(request: Request) -> dict:
    ip = (
        request.headers.get("cf-connecting-ip")
        or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        or (request.client.host if request.client else "")
    )
    return {
        "time": int(time.time()),
        "ip": ip,
        "ua": (request.headers.get("user-agent") or "")[:200],
    }


def record_login(request: Request):
    s = read_settings()
    old = s.get("web_login") or {}
    s["web_login"] = {
        "current": client_info(request),
        "previous": old.get("current"),
        "count": int(old.get("count") or 0) + 1,
    }
    write_settings(s)


# ---------- 访问控制 ----------
PUBLIC = {"/login", "/health", "/favicon.ico", "/login/qr.png"}
API_PREFIX = (
    "/folders",
    "/add",
    "/tasks",
    "/task/",
    "/default",
    "/cookie",
    "/rename",
    "/login/start",
    "/login/status",
)


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC:
        return await call_next(request)
    if authed(request):
        return await call_next(request)
    if path.startswith(API_PREFIX):
        return JSONResponse({"detail": "login required"}, status_code=401)
    return RedirectResponse("/login", status_code=303)

PAGE_CSS = """
:root{--blue:#0a84ff;--bg:#f2f2f7;--card:#fff;--text:#111;--sub:#8e8e93;--line:#e5e5ea}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 -apple-system,
BlinkMacSystemFont,"PingFang SC","Helvetica Neue",sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.card{background:var(--card);border-radius:16px;padding:26px 22px;width:100%;max-width:360px;
box-shadow:0 6px 24px rgba(0,0,0,.06)}
h1{font-size:21px;margin:0 0 4px}
p.sub{color:var(--sub);font-size:13px;margin:0 0 18px}
label{display:block;font-size:13px;color:var(--sub);margin:12px 0 6px}
input{width:100%;font:16px inherit;padding:13px 14px;border:1px solid var(--line);
border-radius:11px;outline:none;background:#fafafa}
input:focus{border-color:var(--blue);background:#fff}
button{width:100%;margin-top:18px;padding:15px;border:none;border-radius:12px;
background:var(--blue);color:#fff;font:16px inherit;font-weight:600}
button:active{opacity:.85}
.err{color:#e5484d;font-size:13px;min-height:18px;margin-top:10px;text-align:center}
.foot{text-align:center;font-size:12px;color:var(--sub);margin-top:16px}
a{color:var(--blue);text-decoration:none}
img.qr{display:block;width:240px;height:240px;margin:0 auto;background:#fff;
border-radius:12px;padding:10px;box-shadow:0 4px 18px rgba(0,0,0,.08)}
#s{margin-top:14px;font-size:14px;color:#0a7;text-align:center;min-height:20px}
"""

LOGIN_TMPL = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 115 云下载</title><style>__CSS__</style></head><body>
<form class="card" method="post" action="/login">
  <h1>115 云下载</h1>
  <p class="sub">请输入访问账号和密码</p>
  <label>账号</label>
  <input name="username" autocapitalize="off" autocorrect="off" placeholder="admin">
  <label>密码</label>
  <input name="password" type="password" placeholder="密码">
  <button type="submit">登录</button>
  <div class="err">__ERR__</div>
</form>
</body></html>"""

PWD_TMPL = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>修改密码 · 115 云下载</title><style>__CSS__</style></head><body>
<form class="card" method="post" action="/password">
  <h1>修改密码</h1>
  <p class="sub">__USER__</p>
  <label>当前密码</label>
  <input name="old" type="password">
  <label>新密码（至少 6 位）</label>
  <input name="new" type="password">
  <label>再输一次</label>
  <input name="new2" type="password">
  <button type="submit">保存</button>
  <div class="err">__ERR__</div>
  <div class="foot"><a href="/app">返回</a></div>
</form>
</body></html>"""

QR_HTML = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>115 扫码登录</title><style>__CSS__</style></head><body>
<div class="card" style="text-align:center">
  <h1>115 扫码登录</h1>
  <p class="sub">用 115 App 扫一扫，登录态会保存在服务器上</p>
  <img class="qr" id="q" alt="二维码">
  <div id="s">等待扫码…</div>
  <div class="foot"><a href="/app">返回</a></div>
</div>
<script>
let uid=null, timer=null;
async function start(){
  const r=await fetch("/login/start",{method:"POST"}).then(r=>r.json());
  uid=r.uid; document.getElementById("q").src="/login/qr.png?uid="+uid;
  document.getElementById("s").textContent="等待扫码…";
}
async function poll(){
  if(!uid) return;
  const r=await fetch("/login/status").then(r=>r.json());
  if(r.status===1){document.getElementById("s").textContent="已扫码，请在手机上确认…";}
  else if(r.status===2||r.logged_in){
    document.getElementById("s").textContent="✓ 登录成功，正在返回…";
    clearInterval(timer); setTimeout(()=>location.href="/app", 900); return;
  }
  else if(r.status===3||r.status===4){document.getElementById("s").textContent="二维码已失效，正在更换…"; start();}
}
start().then(()=>{timer=setInterval(poll,2000);});
</script></body></html>"""


# ---------- 网页登录 ----------
@app.get("/login")
def login_page(request: Request):
    if check_session(request.cookies.get("sess")):
        return RedirectResponse("/app", status_code=303)
    return HTMLResponse(LOGIN_TMPL.replace("__CSS__", PAGE_CSS).replace("__ERR__", ""))


@app.post("/login")
async def do_login(request: Request):
    form = urllib.parse.parse_qs((await request.body()).decode())
    user = (form.get("username") or [""])[0].strip()
    pwd = (form.get("password") or [""])[0]
    if not verify_password(user, pwd):
        time.sleep(0.4)
        html = (
            LOGIN_TMPL.replace("__CSS__", PAGE_CSS)
            .replace("__ERR__", "账号或密码不对")
        )
        return HTMLResponse(html, status_code=401)
    record_login(request)
    resp = RedirectResponse("/app", status_code=303)
    resp.set_cookie(
        "sess", make_session(user), max_age=SESSION_TTL,
        httponly=True, samesite="lax", secure=True,
    )
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("sess")
    return resp


@app.get("/password")
def password_page(request: Request):
    user = check_session(request.cookies.get("sess")) or ""
    html = (
        PWD_TMPL.replace("__CSS__", PAGE_CSS)
        .replace("__USER__", user)
        .replace("__ERR__", "")
    )
    return HTMLResponse(html)


@app.post("/password")
async def do_password(request: Request):
    form = urllib.parse.parse_qs((await request.body()).decode())
    old = (form.get("old") or [""])[0]
    new = (form.get("new") or [""])[0]
    new2 = (form.get("new2") or [""])[0]
    user = check_session(request.cookies.get("sess")) or (read_settings().get("auth") or {}).get("user", "admin")
    err = ""
    if not verify_password(user, old):
        err = "当前密码不对"
    elif len(new) < 6:
        err = "新密码至少 6 位"
    elif new != new2:
        err = "两次输入不一致"
    if err:
        html = (
            PWD_TMPL.replace("__CSS__", PAGE_CSS)
            .replace("__USER__", user)
            .replace("__ERR__", err)
        )
        return HTMLResponse(html, status_code=400)
    set_password(user, new)
    return RedirectResponse("/app", status_code=303)


# ---------- 115 扫码 ----------
@app.get("/qr")
def qr_page():
    return HTMLResponse(QR_HTML.replace("__CSS__", PAGE_CSS))


@app.get("/app")
def app_page(token: str = ""):
    resp = FileResponse(BASE / "ui.html", media_type="text/html")
    if token and token == TOKEN:
        user = (read_settings().get("auth") or {}).get("user", "admin")
        resp.set_cookie(
            "sess", make_session(user), max_age=SESSION_TTL,
            httponly=True, samesite="lax", secure=True,
        )
    return resp

# ---------- 115 扫码接口 ----------
@app.post("/login/start")
def login_start():
    c = _client or P115Client("")
    data = c.login_qrcode_token()["data"]
    uid = data["uid"]
    _login_state.clear()
    _login_state.update({"token": data, "uid": uid, "status": 0, "error": ""})

    def poll():
        while _login_state.get("uid") == uid:
            try:
                st = c.login_qrcode_scan_status(data)
                code = int(st.get("data", {}).get("status", 0))
                _login_state["status"] = code
                if code == 2:
                    res = c.login_qrcode_scan_result(uid)
                    cookie = res["data"]["cookie"]
                    line = "; ".join(f"{k}={v}" for k, v in cookie.items())
                    BASE.mkdir(parents=True, exist_ok=True)
                    COOKIE_FILE.write_text(line)
                    global _client
                    _client = P115Client(line)
                    _login_state["error"] = "ok"
                    return
                if code in (3, 4, 5):
                    _login_state["error"] = f"status {code}"
                    return
            except Exception as e:  # noqa: BLE001
                _login_state["error"] = str(e)
                return
            time.sleep(2)

    threading.Thread(target=poll, daemon=True).start()
    return {
        "uid": uid,
        "qrcode": data.get("qrcode") or f"https://115.com/scan/dg-{uid}",
        "qr": f"/login/qr.png?uid={uid}",
    }


@app.get("/login/qr.png")
def login_qr(uid: str):
    tok = _login_state.get("token") or {}
    url = tok.get("qrcode") or f"https://115.com/scan/dg-{uid}"
    buf = io.BytesIO()
    segno.make(url, error="m").save(buf, kind="png", scale=8, border=2)
    return Response(content=buf.getvalue(), media_type="image/png")


@app.get("/login/status")
def login_status():
    return {
        "status": _login_state.get("status", 0),
        "logged_in": COOKIE_FILE.exists(),
        "error": _login_state.get("error", ""),
    }


@app.get("/config")
def get_config():
    return {"github": os.environ.get("GITHUB_URL", "")}


# ---------- 保存位置 ----------
class DefaultReq(BaseModel):
    cid: str = "0"
    name: str = "根目录"
    path: list[dict] = []


@app.get("/default")
def get_default():
    d = read_settings().get("default") or {}
    return {
        "cid": d.get("cid", "0"),
        "name": d.get("name", "根目录"),
        "path": d.get("path", []),
    }


@app.put("/default")
def set_default(req: DefaultReq):
    s = read_settings()
    s["default"] = {"cid": req.cid, "name": req.name, "path": req.path}
    write_settings(s)
    return {"ok": True}


@app.delete("/default")
def clear_default():
    s = read_settings()
    s.pop("default", None)
    write_settings(s)
    return {"ok": True}


# ---------- 目录 ----------
@app.get("/folders")
def folders(cid: str = "0", refresh: int = 0):
    now = time.time()
    if not refresh:
        hit = _folder_cache.get(cid)
        if hit and now - hit[0] < FOLDER_TTL:
            return {**hit[1], "cached": True}
    c = get_client()
    r = c.fs_files({"cid": cid, "limit": 1150, "offset": 0, "show_dir": 1})
    if not r.get("state"):
        raise HTTPException(400, str(r))
    items = r.get("data") or []
    dirs = [
        {"cid": str(it["cid"]), "name": it["n"]}
        for it in items
        if not it.get("sha")
    ]
    data = {"cid": str(cid), "folders": dirs}
    _folder_cache[cid] = (now, data)
    return {**data, "cached": False}


class MkdirReq(BaseModel):
    cid: str = "0"
    name: str


@app.post("/mkdir")
def mkdir(req: MkdirReq):
    name = req.name.strip()
    if not name:
        raise HTTPException(400, "文件夹名不能为空")
    if len(name) > 255:
        raise HTTPException(400, "名称太长（最多 255 字符）")
    c = get_client()
    r = c.fs_mkdir({"cname": name, "pid": req.cid})
    if not r.get("state"):
        raise HTTPException(400, str(r.get("error") or r))
    _folder_cache.pop(req.cid, None)
    return {"ok": True, "cid": str(r.get("cid") or ""), "name": name}


# ---------- 改名 ----------
_EXT_MAX = 6
_BRACKET_AD = re.compile(
    r"[\[【(（][^\]】)）]{0,40}(?:www\.|\.com|\.la|\.net|发布|字幕组|高清剧集网)[^\]】)）]{0,40}[\]】)）]",
    re.I,
)


def split_ext(name: str) -> tuple[str, str]:
    stem, dot, ext = name.rpartition(".")
    if dot and 0 < len(ext) <= _EXT_MAX and " " not in ext:
        return stem, "." + ext
    return name, ""


def clean_name(name: str) -> str:
    stem, ext = split_ext(name)
    s = stem
    s = re.sub(r"^\[[^\]]{1,24}\]\s*", "", s)
    s = re.sub(r"^【[^】]{1,24}】\s*", "", s)
    s = re.sub(r"^[\w.-]{2,40}@", "", s)
    s = _BRACKET_AD.sub("", s)
    s = s.replace("_", " ")
    s = re.sub(r"\s{2,}", " ", s).strip(" -_.")
    return (s + ext) if s else name


def ai_clean(name: str) -> str | None:
    if not (AI_BASE and AI_KEY):
        return None
    payload = {
        "model": AI_MODEL,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是文件命名助手。把用户给的影视/资源文件名改写成规范名称："
                    "保留作品名、年份、分辨率、片源、编码、字幕等有用信息；"
                    "删除网址、站点名、广告语、@前缀和无意义符号；"
                    "把下划线替换成空格；"
                    "保持原有扩展名不变；不要加引号或解释；只输出一行文件名。"
                ),
            },
            {"role": "user", "content": name},
        ],
    }
    req = urllib.request.Request(
        AI_BASE + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + AI_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
    except Exception:  # noqa: BLE001
        return None
    text = text.strip().splitlines()[0].strip().strip('"').strip("`")
    text = re.sub(r'[<>|*?"\\/:]', "", text).strip()
    if not text:
        return None
    stem, ext = split_ext(name)
    if ext and not text.lower().endswith(ext.lower()):
        text = split_ext(text)[0] + ext
    return text[:255]


class RenameSuggestReq(BaseModel):
    name: str


@app.post("/rename/suggest")
def rename_suggest(req: RenameSuggestReq):
    src = (req.name or "").strip()
    if not src:
        raise HTTPException(400, "缺少文件名")
    ai_name = ai_clean(src)
    return {"suggested": ai_name or clean_name(src), "ai": bool(ai_name)}


class RenameApplyReq(BaseModel):
    file_id: str
    name: str


@app.post("/rename/apply")
def rename_apply(req: RenameApplyReq):
    fid = (req.file_id or "").strip()
    name = (req.name or "").strip()
    if not fid or not name:
        raise HTTPException(400, "参数不完整")
    if len(name) > 255:
        raise HTTPException(400, "名称太长")
    global _rename_block_until
    c = get_client()
    with _rename_lock:
        rename_gate()
        time.sleep(random.uniform(0.15, 0.45))  # 轻微抖动，避免机械节奏
        try:
            r = c.fs_rename((fid, name))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(400, str(e)) from e
        err = str(r.get("error") or "")
        if not r.get("state"):
            if any(k in err for k in ("频繁", "过快", "稍后", "风控", "限制")):
                _rename_block_until = time.time() + 120
                raise HTTPException(
                    429,
                    {"message": "115 提示操作频繁，已暂停改名 2 分钟", "retry_after": 120},
                )
            raise HTTPException(400, err or str(r))
        _rename_times.append(time.time())
        per_min = sum(1 for t in _rename_times if time.time() - t < 60)
    return {"ok": True, "name": name, "remaining": max(0, RENAME_MAX_PER_MIN - per_min)}


# ---------- 任务 ----------
class AddReq(BaseModel):
    urls: list[str]
    cid: str = "0"
    savepath: str = ""


@app.post("/add")
def add(req: AddReq):
    c = get_client()
    out = []
    for url in req.urls:
        payload = {"url": url.strip(), "wp_path_id": req.cid}
        if req.savepath:
            payload["savepath"] = req.savepath
        try:
            r = c.clouddownload_task_add_url(payload)
            out.append({"url": url, "state": r.get("state", False), "raw": r})
        except Exception as e:  # noqa: BLE001
            out.append({"url": url, "state": False, "error": str(e)})
    return {"results": out}


@app.get("/tasks")
def tasks(page: int = 1, stat: int = 0):
    c = get_client()
    r = c.clouddownload_task_list({"page": page, "page_size": 30, "stat": stat})
    if not r.get("state"):
        raise HTTPException(400, str(r))
    return {
        "page": r.get("page"),
        "page_count": r.get("page_count"),
        "count": r.get("count"),
        "tasks": [
            {
                "info_hash": t.get("info_hash"),
                "name": t.get("name"),
                "size": t.get("size"),
                "percent": t.get("percentDone"),
                "status": t.get("status"),
                "add_time": t.get("add_time"),
                "last_update": t.get("last_update"),
                "file_id": t.get("file_id"),
                "actions": t.get("available_actions"),
            }
            for t in (r.get("tasks") or [])
        ],
    }


@app.post("/task/{info_hash}/{action}")
def task_action(info_hash: str, action: str, del_source: int = 0):
    c = get_client()
    if action == "retry":
        r = c.clouddownload_task_restart(info_hash)
    elif action == "pause":
        r = c.clouddownload_task_pause(info_hash)
    elif action == "resume":
        r = c.clouddownload_task_resume(info_hash)
    elif action == "delete":
        r = c.clouddownload_task_del({"hash[0]": info_hash, "flag": del_source})
    else:
        raise HTTPException(400, "action must be retry/pause/resume/delete")
    return {"state": r.get("state", False), "raw": r}


# ---------- 客户端 ----------
def get_client() -> P115Client:
    global _client
    if _client is None:
        if not COOKIE_FILE.exists():
            raise HTTPException(401, "not logged in")
        _client = P115Client(COOKIE_FILE.read_text().strip())
    return _client


class CookieReq(BaseModel):
    cookie: str


@app.put("/cookie")
def set_cookie(req: CookieReq):
    global _client
    line = req.cookie.strip()
    if "UID=" not in line:
        raise HTTPException(400, "cookie 需包含 UID")
    BASE.mkdir(parents=True, exist_ok=True)
    COOKIE_FILE.write_text(line)
    _client = P115Client(line)
    _folder_cache.clear()
    return {"ok": True}

# ---------- 后台 ----------
ADMIN_HTML = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>后台 · 115 云下载</title>
<style>
:root{--blue:#0a84ff;--bg:#f2f2f7;--card:#fff;--sub:#8e8e93;--line:#e5e5ea}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);font:16px/1.5 -apple-system,BlinkMacSystemFont,
"PingFang SC","Helvetica Neue",sans-serif;color:#111;padding:env(safe-area-inset-top) 0 30px}
.wrap{padding:0 14px}
.top{display:flex;align-items:baseline;justify-content:space-between;padding:18px 4px 10px}
.top h1{font-size:24px;margin:0}
.top a{font-size:14px;color:var(--blue);text-decoration:none}
.card{background:var(--card);border-radius:14px;padding:16px;margin-bottom:14px}
.who{display:flex;gap:14px;align-items:center}
.avatar{width:56px;height:56px;border-radius:50%;background:#e9e9ef;object-fit:cover;
display:flex;align-items:center;justify-content:center;font-size:22px;color:#8e8e93;flex:none}
.name{font-size:18px;font-weight:600;word-break:break-all}
.uid{font-size:13px;color:var(--sub);margin-top:2px}
.badge{display:inline-block;font-size:11px;padding:2px 8px;border-radius:20px;
background:#fff2e0;color:#c26a00;margin-left:6px;vertical-align:2px}
.kv{display:flex;justify-content:space-between;font-size:14px;padding:7px 0;gap:12px}
.kv span:first-child{color:var(--sub);flex:none}
.kv span:last-child{text-align:right;word-break:break-all}
.ua{font-size:12px;color:var(--sub);max-width:62%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{height:8px;background:#eee;border-radius:4px;overflow:hidden;margin:10px 0 6px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#0a84ff,#4fb0ff);width:0}
.spaceTop{display:flex;justify-content:space-between;font-size:13px;color:var(--sub)}
.skel{color:var(--sub);font-size:14px}
h2{font-size:13px;color:var(--sub);font-weight:500;margin:0 0 6px;padding-left:4px}
</style></head><body>
<div class="wrap">
  <div class="top"><h1>后台</h1><a href="/app">返回</a></div>
  <h2>115 账号</h2>
  <div class="card" id="who"><div class="skel">加载中…</div></div>
  <h2>空间</h2>
  <div class="card" id="space"><div class="skel">加载中…</div></div>
  <h2>网站登录</h2>
  <div class="card" id="web"><div class="skel">加载中…</div></div>
  <h2>服务</h2>
  <div class="card" id="meta"><div class="skel">加载中…</div></div>
</div>
<script>
const pad = n => String(n).padStart(2,"0");
const day = ts => { if(!ts) return "—"; const d=new Date(ts*1000);
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`; };
const dur = s => { if(!s) return "刚刚"; const d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
  return d? `${d} 天 ${h} 小时` : (h? `${h} 小时 ${m} 分` : `${m} 分`); };
const uaShort = s => {
  if(!s) return "—";
  const os = /iPhone/.test(s) ? "iPhone" : /iPad/.test(s) ? "iPad" :
    /Android/.test(s) ? "Android" : /Mac OS X/.test(s) ? "Mac" :
    /Windows/.test(s) ? "Windows" : "其它";
  const br = s.includes("Edg/") ? "Edge" :
    (s.includes("CriOS") || s.includes("Chrome/")) ? "Chrome" :
    (s.includes("FxiOS") || s.includes("Firefox/")) ? "Firefox" :
    s.includes("Safari/") ? "Safari" : "";
  return br ? `${os} · ${br}` : os;
};
async function load(){
  const r = await fetch("/account").then(x=>x.json());
  const u = r.user || {}, sp = r.space || {}, web = r.web || {}, sv = r.service || {};
  const vip = u.vip ? `<span class="badge">VIP</span>` : "";
  document.getElementById("who").innerHTML = `
    <div class="who">
      ${u.face ? `<img class="avatar" src="${u.face}" alt="">` : `<div class="avatar">👤</div>`}
      <div>
        <div class="name">${u.name || "未知"}${vip}</div>
        <div class="uid">UID ${u.display_uid || u.id || "—"}${u.phone ? " · " + u.phone : ""}</div>
        <div class="uid">${u.expire ? "会员至 " + day(u.expire) : ""}</div>
      </div>
    </div>`;
  document.getElementById("space").innerHTML = `
    <div class="spaceTop"><span>已用 ${sp.used || "—"}</span><span>共 ${sp.total || "—"}</span></div>
    <div class="bar"><i style="width:${sp.percent || 0}%"></i></div>
    <div class="spaceTop"><span>${sp.percent || 0}%</span><span>剩余 ${sp.remain || "—"}</span></div>`;
  const lg = web.login || {}, cur = lg.current || {}, prev = lg.previous || {};
  document.getElementById("web").innerHTML = `
    <div class="kv"><span>当前账号</span><span>${web.user || "—"}</span></div>
    <div class="kv"><span>本次登录</span><span>${day(cur.time)}</span></div>
    <div class="kv"><span>登录 IP</span><span>${cur.ip || "—"}</span></div>
    <div class="kv"><span>设备</span><span class="ua">${uaShort(cur.ua)}</span></div>
    <div class="kv"><span>上次登录</span><span>${prev.time ? day(prev.time) + " · " + (prev.ip || "") : "—"}</span></div>
    <div class="kv"><span>累计登录</span><span>${lg.count || 0} 次</span></div>`;
  document.getElementById("meta").innerHTML = `
    <div class="kv"><span>网页账号</span><span>${web.user || "—"}</span></div>
    <div class="kv"><span>登录有效期</span><span>10 年</span></div>
    <div class="kv"><span>115 登录态更新</span><span>${day(sv.cookie_mtime)}</span></div>
    <div class="kv"><span>服务已运行</span><span>${dur(sv.uptime)}</span></div>`;
}
load().catch(e=>{document.getElementById("who").innerHTML='<div class="skel">读取失败：'+e.message+'</div>';});
</script></body></html>"""


@app.get("/admin")
def admin_page():
    return HTMLResponse(ADMIN_HTML)


@app.get("/account")
def account(request: Request):
    c = get_client()
    info: dict = {}
    try:
        info = (c.user_info3() or {}).get("data") or {}
    except Exception:  # noqa: BLE001
        pass
    phone = ""
    try:
        phone = (c.user_info4() or {}).get("data") or ""
    except Exception:  # noqa: BLE001
        pass
    space: dict = {}
    try:
        d = (c.user_space_info() or {}).get("data") or {}
        total = int((d.get("all_total") or {}).get("size") or 0)
        used = int((d.get("all_use") or {}).get("size") or 0)
        space = {
            "total": (d.get("all_total") or {}).get("size_format", ""),
            "used": (d.get("all_use") or {}).get("size_format", ""),
            "remain": (d.get("all_remain") or {}).get("size_format", ""),
            "percent": round(used * 100 / total, 1) if total else 0,
        }
    except Exception:  # noqa: BLE001
        pass
    return {
        "user": {
            "id": info.get("user_id"),
            "name": info.get("user_name"),
            "display_uid": info.get("display_uid"),
            "vip": info.get("vip") or 0,
            "expire": info.get("expire") or 0,
            "face": info.get("face") or "",
            "phone": phone,
        },
        "space": space,
        "web": {
            "user": check_session(request.cookies.get("sess")) or "token",
            "login": read_settings().get("web_login") or {},
            "session_exp": SESSION_TTL,
        },
        "service": {
            "uptime": int(time.time() - START_TS),
            "cookie_mtime": int(COOKIE_FILE.stat().st_mtime) if COOKIE_FILE.exists() else 0,
        },
    }


ensure_auth()


def _warm_folders():
    """启动后预热根目录缓存，第一次打开文件夹选择器就能秒开"""
    time.sleep(1)
    try:
        folders("0")
    except Exception:  # noqa: BLE001
        pass


threading.Thread(target=_warm_folders, daemon=True).start()
