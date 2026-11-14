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


def wait_rename_slot():
    """后台任务用：阻塞直到可以安全发一次改名请求"""
    while True:
        now = time.time()
        if _rename_block_until > now:
            time.sleep(min(5.0, _rename_block_until - now))
            continue
        while _rename_times and now - _rename_times[0] > 3600:
            _rename_times.popleft()
        if _rename_times:
            wait = RENAME_MIN_INTERVAL - (now - _rename_times[-1])
            if wait > 0:
                time.sleep(wait)
                continue
        if sum(1 for t in _rename_times if now - t < 60) >= RENAME_MAX_PER_MIN:
            time.sleep(5)
            continue
        if len(_rename_times) >= RENAME_MAX_PER_HOUR:
            time.sleep(30)
            continue
        return


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


def ai_enabled() -> bool:
    return bool(read_settings().get("ai_enabled", True))


def ai_config() -> dict:
    s = read_settings().get("ai") or {}
    return {
        "base": (s.get("base") or AI_BASE).rstrip("/"),
        "key": s.get("key") or AI_KEY,
        "model": s.get("model") or AI_MODEL,
    }


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
    "/ai",
    "/chat",
    "/auto_rename",
    "/jobs",
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


class AIReq(BaseModel):
    base: str = ""
    key: str = ""
    model: str = ""


@app.get("/ai")
def get_ai():
    cfg = ai_config()
    key = cfg["key"]
    return {
        "base": cfg["base"],
        "model": cfg["model"],
        "has_key": bool(key),
        "key_hint": ("****" + key[-4:]) if key else "",
    }


@app.put("/ai")
def set_ai(req: AIReq):
    s = read_settings()
    cur = s.get("ai") or {}
    base = req.base.strip().rstrip("/")
    if not base:
        s.pop("ai", None)
        write_settings(s)
        return {"ok": True, "cleared": True}
    s["ai"] = {
        "base": base,
        "model": req.model.strip() or AI_MODEL,
        "key": req.key.strip() or cur.get("key") or AI_KEY,
    }
    write_settings(s)
    return {"ok": True}


class ToggleReq(BaseModel):
    enabled: bool


@app.get("/ai/status")
def ai_status():
    return {"enabled": ai_enabled()}


@app.put("/ai/status")
def set_ai_status(req: ToggleReq):
    s = read_settings()
    s["ai_enabled"] = bool(req.enabled)
    write_settings(s)
    return {"ok": True, "enabled": bool(req.enabled)}


@app.get("/ai/models")
def ai_models():
    cfg = ai_config()
    if not (cfg["base"] and cfg["key"]):
        raise HTTPException(400, "还没配置接口地址或密钥")
    req = urllib.request.Request(
        cfg["base"] + "/models",
        headers={"Authorization": "Bearer " + cfg["key"]},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            d = json.loads(resp.read().decode())
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"获取失败：{e}") from e
    ids = [m.get("id") for m in (d.get("data") or []) if m.get("id")]
    return {"models": ids, "current": cfg["model"], "count": len(ids)}


@app.post("/ai/test")
def test_ai():
    cfg = ai_config()
    if not (cfg["base"] and cfg["key"]):
        raise HTTPException(400, "还没配置接口地址或密钥")
    payload = {
        "model": cfg["model"],
        "messages": [{"role": "user", "content": "只回复两个字：正常"}],
        "max_tokens": 16,
    }
    req = urllib.request.Request(
        cfg["base"] + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + cfg["key"],
        },
    )
    try:
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=20) as resp:
            d = json.loads(resp.read().decode())
        ms = int((time.time() - t0) * 1000)
        if not d.get("choices"):
            raise ValueError("响应里没有 choices")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"连接失败：{e}") from e
    return {"ok": True, "ms": ms, "model": cfg["model"]}


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
    items = list_dir_items(cid, 1150, 0)
    dirs = [{"cid": it["id"], "name": it["name"]} for it in items if it["is_dir"]]
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
    if not ai_enabled():
        return None
    cfg = ai_config()
    if not (cfg["base"] and cfg["key"]):
        return None
    payload = {
        "model": cfg["model"],
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
        cfg["base"] + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + cfg["key"],
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


# ---------- 批量改名任务 ----------
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
JOBS_FILE = BASE / "jobs.json"


def save_jobs():
    try:
        JOBS_FILE.write_text(json.dumps(_jobs, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass


def load_jobs():
    try:
        data = json.loads(JOBS_FILE.read_text())
        if isinstance(data, dict):
            _jobs.update(data)
    except Exception:  # noqa: BLE001
        pass


_DIR_ORDER = ["web", "app", "aps"]


def list_dir_items(cid: str, limit: int = 300, offset: int = 0) -> list[dict]:
    """统一目录读取：web → app → aps，逐个降级，成功的排到前面"""
    global _DIR_ORDER
    c = get_client()
    last = None
    funcs = {
        "web": lambda: c.fs_files({"cid": cid, "limit": limit, "offset": offset, "show_dir": 1}),
        "app": lambda: c.fs_files_app({"cid": cid, "limit": limit, "offset": offset, "show_dir": 1}),
        "aps": lambda: c.fs_files_aps({"cid": cid, "limit": limit, "offset": offset, "show_dir": 1}),
    }
    for key in list(_DIR_ORDER):
        try:
            r = funcs[key]()
            if r.get("state"):
                if _DIR_ORDER[0] != key:
                    _DIR_ORDER.remove(key)
                    _DIR_ORDER.insert(0, key)
                return [
                    {
                        "id": str(x.get("fid") or x.get("cid")),
                        "name": x.get("n") or x.get("fn") or "",
                        "is_dir": not x.get("sha"),
                        "size": x.get("s") or 0,
                    }
                    for x in (r.get("data") or [])
                ]
            last = r
        except Exception as e:  # noqa: BLE001
            last = e
    raise HTTPException(503, f"目录读取失败：{last}")


def collect_files(cid: str, recursive: bool, cap: int = 3000) -> list[dict]:
    out: list[dict] = []
    q = deque([cid])
    while q and len(out) < cap:
        cur = q.popleft()
        off = 0
        while len(out) < cap:
            items = list_dir_items(cur, 1150, off)
            for it in items:
                if it["is_dir"]:
                    if recursive:
                        q.append(it["id"])
                else:
                    out.append({"fid": it["id"], "name": it["name"], "cid": cur})
            if len(items) < 1150:
                break
            off += len(items)
        if not recursive:
            break
        time.sleep(0.15)
    return out


def plan_pairs(cid: str, recursive: bool, cap: int = 3000):
    files = collect_files(cid, recursive, cap)
    pairs = []
    for f in files:
        nn = re.sub(r'[<>|*?"\\/:]', "", clean_name(f["name"])).strip()
        if nn and f["fid"] and nn != f["name"]:
            pairs.append((f, nn))
    return files, pairs


def _run_rename_job(job_id: str, cid: str, recursive: bool, dry_run: bool, cap: int = 3000):
    j = _jobs[job_id]
    try:
        files, pairs = plan_pairs(cid, recursive, cap)
        j["total"] = len(files)
        j["planned"] = len(pairs)
        j["preview"] = [{"old": a["name"], "new": b} for a, b in pairs[:50]]
        if dry_run:
            j["status"] = "preview"
            save_jobs()
            return
        j["status"] = "running"
        for a, b in pairs:
            if j.get("cancel"):
                j["status"] = "cancelled"
                return
            try:
                with _rename_lock:
                    wait_rename_slot()
                    time.sleep(random.uniform(0.15, 0.35))
                    r = get_client().fs_rename((a["fid"], b))
                    err = str(r.get("error") or "")
                    if not r.get("state"):
                        if any(k in err for k in ("频繁", "过快", "稍后", "风控", "限制")):
                            global _rename_block_until
                            _rename_block_until = time.time() + 120
                            j["status"] = "paused"
                            j["error"] = "115 提示操作频繁，已暂停"
                            return
                        j["failed"] += 1
                        continue
                    _rename_times.append(time.time())
                j["done"] += 1
                if j["done"] % 20 == 0:
                    save_jobs()
            except HTTPException as e:
                if getattr(e, "status_code", 400) == 429:
                    j["status"] = "paused"
                    j["error"] = str(e.detail)
                    return
                j["failed"] += 1
            except Exception:  # noqa: BLE001
                j["failed"] += 1
        j["status"] = "done"
        save_jobs()
    except HTTPException as e:
        j["status"] = "paused"
        j["error"] = str(e.detail)
        save_jobs()
    except Exception as e:  # noqa: BLE001
        j["status"] = "paused"
        j["error"] = str(e)
        save_jobs()


class JobReq(BaseModel):
    cid: str = "0"
    recursive: bool = False
    dry_run: bool = True


def start_job(cid: str, recursive: bool, dry_run: bool = False) -> dict:
    job_id = secrets.token_hex(4)
    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id, "cid": cid, "recursive": recursive, "dry_run": dry_run,
            "status": "queued", "total": 0, "planned": 0, "done": 0, "failed": 0,
            "preview": [], "error": "", "created": int(time.time()),
        }
    save_jobs()
    threading.Thread(
        target=_run_rename_job, args=(job_id, cid, recursive, dry_run), daemon=True
    ).start()
    return {"job_id": job_id}


@app.post("/jobs/rename")
def start_rename_job(req: JobReq):
    return {"ok": True, **start_job(req.cid, req.recursive, req.dry_run)}


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    j = _jobs.get(job_id)
    if not j:
        raise HTTPException(404, "任务不存在")
    return dict(j)


@app.post("/jobs/{job_id}/resume")
def resume_job(job_id: str):
    j = _jobs.get(job_id)
    if not j:
        raise HTTPException(404, "任务不存在")
    return {"ok": True, **start_job(j["cid"], j["recursive"], False)}


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    j = _jobs.get(job_id)
    if not j:
        raise HTTPException(404, "任务不存在")
    j["cancel"] = True
    if j.get("status") in ("paused", "queued"):
        j["status"] = "cancelled"
    save_jobs()
    return {"ok": True}


# ---------- 新文件自动改名 ----------
_auto_state = {"seen": None, "renamed": 0, "last": 0, "last_name": ""}


def auto_seen_init():
    try:
        r = get_client().clouddownload_task_list({"page": 1, "page_size": 50, "stat": 11})
        _auto_state["seen"] = {t.get("info_hash") for t in (r.get("tasks") or [])}
    except Exception:  # noqa: BLE001
        _auto_state["seen"] = set()


def auto_watcher():
    time.sleep(5)
    if _auto_state["seen"] is None:
        auto_seen_init()
    while True:
        try:
            if (read_settings().get("auto_rename") or {}).get("enabled"):
                r = get_client().clouddownload_task_list(
                    {"page": 1, "page_size": 30, "stat": 11}
                )
                for t in reversed(r.get("tasks") or []):
                    h = t.get("info_hash")
                    if not h or h in _auto_state["seen"]:
                        continue
                    _auto_state["seen"].add(h)
                    fid = t.get("file_id")
                    src = t.get("name") or ""
                    if not fid or not src:
                        continue
                    new = ai_clean(src) or clean_name(src)
                    new = re.sub(r'[<>|*?"\\/:]', "", new).strip()
                    if not new or new == src:
                        continue
                    with _rename_lock:
                        wait_rename_slot()
                        time.sleep(random.uniform(0.15, 0.35))
                        rr = get_client().fs_rename((str(fid), new))
                        if rr.get("state"):
                            _rename_times.append(time.time())
                            _auto_state["renamed"] += 1
                            _auto_state["last"] = int(time.time())
                            _auto_state["last_name"] = new
        except Exception:  # noqa: BLE001
            pass
        time.sleep(120)


class AutoReq(BaseModel):
    enabled: bool


@app.get("/auto_rename")
def get_auto():
    return {
        "enabled": bool((read_settings().get("auto_rename") or {}).get("enabled")),
        "renamed": _auto_state["renamed"],
        "last": _auto_state["last"],
        "last_name": _auto_state["last_name"],
    }


@app.put("/auto_rename")
def set_auto(req: AutoReq):
    s = read_settings()
    s["auto_rename"] = {"enabled": req.enabled}
    write_settings(s)
    if req.enabled and _auto_state["seen"] is None:
        auto_seen_init()
    return {"ok": True, "enabled": req.enabled}


# ---------- AI 文件管理 ----------
CHAT_SYS = (
    "你是 115 网盘的文件管理助手，通过工具查看目录、搜索、改名、新建文件夹、添加下载任务。"
    "规则：先查清楚再操作；不确定目录 id 就从根目录开始列。"
    "批量改名只能调用 auto_rename：confirm=false 预览，confirm=true 执行。"
    "两者都在后台跑，不要轮询 job_status，页面会自动显示进度。"
    "不要在回复里粘贴具体文件名（可能有敏感内容），只报告数量、目录和操作结果。"
    "单个文件改名可以用 clean_name 生成建议后调用 rename_file。"
    "不提供删除功能；不要编造文件或 id。"
)

AI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "列出某个目录下的文件夹和文件（默认根目录）",
            "parameters": {
                "type": "object",
                "properties": {"cid": {"type": "string", "description": "目录 id，根目录为 0"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "按文件名关键词搜索全盘文件",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "clean_name",
            "description": "为单个文件名生成规范化的新名字（不实际改名）",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_file",
            "description": "重命名一个文件或文件夹（需要 file_id）",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_id": {"type": "string"},
                    "new_name": {"type": "string", "description": "完整文件名，含扩展名"},
                },
                "required": ["file_id", "new_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mkdir",
            "description": "在指定目录下新建文件夹",
            "parameters": {
                "type": "object",
                "properties": {
                    "cid": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_download",
            "description": "把链接（磁力/HTTP/FTP/电驴）加入云下载",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "cid": {"type": "string", "description": "保存目录 id，默认 0"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "auto_rename",
            "description": (
                "批量整理某个目录下的文件名，作为后台任务执行。"
                "先 confirm=false 预览改动，用户确认后再 confirm=true 真正执行。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cid": {"type": "string", "description": "目录 id"},
                    "recursive": {"type": "boolean", "description": "是否包含子目录，只有用户明确要求时才传 true"},
                    "confirm": {"type": "boolean", "description": "false=只预览，true=执行"},
                },
                "required": ["cid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "job_status",
            "description": "查询后台改名任务的进度",
            "parameters": {
                "type": "object",
                "properties": {"job_id": {"type": "string"}},
                "required": ["job_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_tasks",
            "description": "查看云下载任务列表",
            "parameters": {
                "type": "object",
                "properties": {
                    "stat": {"type": "integer", "description": "0 全部 9 失败 11 完成 12 进行中"}
                },
            },
        },
    },
]


def _tool_list_dir(a: dict) -> dict:
    cid = str(a.get("cid") or "0")
    items = list_dir_items(cid, 300, 0)
    dirs = [{"id": it["id"], "name": it["name"]} for it in items if it["is_dir"]][:80]
    files = [
        {"id": it["id"], "name": it["name"], "size": it["size"]}
        for it in items
        if not it["is_dir"]
    ][:80]
    return {"cid": cid, "total": len(items), "dirs": dirs, "files": files}


def _tool_search(a: dict) -> dict:
    q = str(a.get("query") or "").strip()
    if not q:
        return {"error": "缺少关键词"}
    r = get_client().fs_search({"search_value": q, "limit": 40})
    if not r.get("state"):
        return {"error": str(r)}
    items = r.get("data") or []
    return {
        "count": r.get("count"),
        "items": [
            {
                "id": str(x.get("fid") or x.get("cid")),
                "name": x.get("n"),
                "is_dir": not x.get("sha"),
                "parent": str(x.get("pid") or ""),
            }
            for x in items[:40]
        ],
    }


def _tool_rename(a: dict) -> dict:
    global _rename_block_until
    fid = str(a.get("file_id") or "").strip()
    name = str(a.get("new_name") or "").strip()
    if not fid or not name:
        return {"error": "参数不完整"}
    with _rename_lock:
        rename_gate()
        time.sleep(random.uniform(0.15, 0.4))
        r = get_client().fs_rename((fid, name))
        err = str(r.get("error") or "")
        if not r.get("state"):
            if any(k in err for k in ("频繁", "过快", "稍后", "风控", "限制")):
                _rename_block_until = time.time() + 120
                return {"error": "115 提示操作频繁，改名暂停 2 分钟"}
            return {"error": err or str(r)}
        _rename_times.append(time.time())
    return {"ok": True, "file_id": fid, "name": name}


def _tool_mkdir(a: dict) -> dict:
    name = str(a.get("name") or "").strip()
    if not name:
        return {"error": "缺少名称"}
    r = get_client().fs_mkdir({"cname": name, "pid": str(a.get("cid") or "0")})
    if not r.get("state"):
        return {"error": str(r.get("error") or r)}
    _folder_cache.pop(str(a.get("cid") or "0"), None)
    return {"ok": True, "cid": str(r.get("cid") or ""), "name": name}


def _tool_download(a: dict) -> dict:
    url = str(a.get("url") or "").strip()
    if not url:
        return {"error": "缺少链接"}
    r = get_client().clouddownload_task_add_url(
        {"url": url, "wp_path_id": str(a.get("cid") or "0")}
    )
    return {"ok": bool(r.get("state")), "raw": r.get("data") or r.get("error")}


def _tool_tasks(a: dict) -> dict:
    stat = int(a.get("stat") or 0)
    r = get_client().clouddownload_task_list({"page": 1, "page_size": 15, "stat": stat})
    if not r.get("state"):
        return {"error": str(r)}
    return {
        "count": r.get("count"),
        "tasks": [
            {
                "name": t.get("name"),
                "percent": t.get("percentDone"),
                "status": t.get("status"),
                "id": t.get("info_hash"),
            }
            for t in (r.get("tasks") or [])[:15]
        ],
    }


def run_tool(name: str, args: dict) -> dict:
    try:
        if name == "list_dir":
            return _tool_list_dir(args)
        if name == "search_files":
            return _tool_search(args)
        if name == "clean_name":
            src = str(args.get("name") or "")
            ai_name = ai_clean(src)
            return {"suggested": ai_name or clean_name(src), "ai": bool(ai_name)}
        if name == "rename_file":
            return _tool_rename(args)
        if name == "mkdir":
            return _tool_mkdir(args)
        if name == "add_download":
            return _tool_download(args)
        if name == "list_tasks":
            return _tool_tasks(args)
        if name == "auto_rename":
            cid = str(args.get("cid") or "0")
            rec = bool(args.get("recursive"))
            confirm = bool(args.get("confirm"))
            r = start_job(cid, rec, dry_run=not confirm)
            jid = r["job_id"]
            if not confirm:
                for _ in range(15):
                    time.sleep(1)
                    j = _jobs.get(jid) or {}
                    if j.get("status") in ("preview", "error"):
                        break
                j = _jobs.get(jid) or {}
                return {
                    "job_id": jid,
                    "status": j.get("status"),
                    "total": j.get("total", 0),
                    "planned": j.get("planned", 0),
                    "note": "预览只返回数量，具体文件名在页面上显示",
                }
            return {"job_id": jid, "status": "queued", "note": "后台执行中，进度在页面显示"}
        if name == "job_status":
            j = _jobs.get(str(args.get("job_id") or ""))
            if not j:
                return {"error": "任务不存在"}
            return {
                k: j.get(k)
                for k in ("status", "total", "planned", "done", "failed", "preview", "error")
            }
        return {"error": f"未知工具 {name}"}
    except HTTPException as e:
        return {"error": e.detail}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def _summ(result: dict) -> str:
    if result.get("preview"):
        return f"预览 {result.get('planned', 0)}/{result.get('total', 0)} 个可改"
    if result.get("error"):
        return "错误：" + str(result["error"])[:120]
    if "dirs" in result or "files" in result:
        return f"目录 {len(result.get('dirs', []))} 个，文件 {len(result.get('files', []))} 个"
    if "items" in result:
        return f"命中 {result.get('count', len(result['items']))} 条"
    if "job_id" in result:
        return "后台任务已创建"
    if "status" in result and "planned" in result:
        return f"{result.get('status')} {result.get('done', 0)}/{result.get('planned', 0)}"
    if result.get("ok"):
        return "成功"
    return "完成"


class ChatReq(BaseModel):
    messages: list[dict] = []
    text: str = ""


@app.post("/chat")
def chat(req: ChatReq):
    if not ai_enabled():
        raise HTTPException(403, "AI 功能已在后台关闭")
    cfg = ai_config()
    if not (cfg["base"] and cfg["key"]):
        raise HTTPException(400, "还没配置 AI 接口")
    msgs: list[dict] = [{"role": "system", "content": CHAT_SYS}]
    for m in (req.messages or [])[-10:]:
        role = m.get("role")
        content = str(m.get("content") or "")[:2000]
        if role in ("user", "assistant") and content:
            msgs.append({"role": role, "content": content})
    text = (req.text or "").strip()
    if text:
        msgs.append({"role": "user", "content": text[:2000]})
    if len(msgs) < 2:
        raise HTTPException(400, "没有内容")

    steps: list[dict] = []
    for _ in range(6):
        payload = {
            "model": cfg["model"],
            "messages": msgs,
            "tools": AI_TOOLS,
            "tool_choice": "auto",
            "temperature": 0.2,
        }
        req_ai = urllib.request.Request(
            cfg["base"] + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + cfg["key"],
            },
        )
        try:
            with urllib.request.urlopen(req_ai, timeout=90) as resp:
                data = json.loads(resp.read().decode())
            msg = (data.get("choices") or [{}])[0].get("message") or {}
        except Exception as e:  # noqa: BLE001
            raise HTTPException(400, f"模型请求失败：{e}") from e

        calls = msg.get("tool_calls") or []
        if not calls:
            reply = (msg.get("content") or "").strip()
            return {"reply": reply or "（模型没有返回内容）", "steps": steps}

        msgs.append(
            {
                "role": "assistant",
                "content": msg.get("content") or "",
                "tool_calls": calls,
            }
        )
        for call in calls[:4]:
            fn = (call.get("function") or {}).get("name") or ""
            try:
                args = json.loads((call.get("function") or {}).get("arguments") or "{}")
            except Exception:  # noqa: BLE001
                args = {}
            result = run_tool(fn, args)
            steps.append({"tool": fn, "args": args, "summary": _summ(result), "job_id": result.get("job_id")})
            msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id"),
                    "content": json.dumps(result, ensure_ascii=False)[:4000],
                }
            )

    return {"reply": "（工具调用轮次过多，先停在这里，可以让我继续）", "steps": steps}


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
.card input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;
 font:14px inherit;outline:none;background:#fafafa;margin-top:4px}
.card input:focus{border-color:var(--blue);background:#fff}
.card .row{display:flex;gap:10px;margin-top:12px}
.card .row button{flex:1;padding:11px;border:none;border-radius:10px;background:var(--blue);
 color:#fff;font:15px inherit;font-weight:600}
.card .row button.ghost{background:#f2f2f7;color:var(--blue)}
.kv.col{display:block;padding:6px 0}
.kv.col span.top{display:block;font-size:12px;color:var(--sub);margin-bottom:2px}
#aiMsg{font-size:12px;color:var(--sub);margin-top:8px;min-height:16px}
.link{color:var(--blue);text-decoration:none;font-size:12px;margin-left:8px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chip{font-size:12px;padding:5px 9px;border-radius:8px;background:#f2f2f7;color:#333}
.chip.on{background:#eaf4ff;color:var(--blue);font-weight:600}
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
  <h2>自动改名</h2>
  <div class="card" id="autoCard">
    <div class="kv"><span>新任务完成后自动清理文件名</span><span id="autoState">—</span></div>
    <div class="kv"><span>已自动改名</span><span id="autoCount">0 个</span></div>
    <div class="row"><button id="autoToggle">开启</button></div>
    <div id="autoMsg" class="skel"></div>
  </div>
  <h2>AI 功能</h2>
  <div class="card" id="aiSwitch">
    <div class="kv"><span>对话与 AI 改名</span><span id="aiOn">—</span></div>
    <div class="row"><button id="aiToggle">关闭</button></div>
    <div class="skel" id="aiSwitchMsg"></div>
  </div>
  <h2>AI 配置</h2>
  <div class="card" id="ai">
    <div class="kv col"><span class="top">接口地址（OpenAI 兼容）</span>
      <input id="aiBase" placeholder="http://127.0.0.1:7864/v1" autocapitalize="off" autocorrect="off"></div>
    <div class="kv col"><span class="top">模型 <u id="aiModelsBtn" class="link">检测可用模型</u></span>
      <input id="aiModel" placeholder="deepseek-v4.1-flash" autocapitalize="off" autocorrect="off">
      <div id="aiModels" class="chips"></div></div>
    <div class="kv col"><span class="top">密钥</span>
      <input id="aiKey" type="password" placeholder="未配置"></div>
    <div class="row"><button id="aiTest" class="ghost">测试</button><button id="aiSave">保存</button></div>
    <div id="aiMsg"></div>
  </div>
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

async function loadAI(){
  try{
    const a = await fetch("/ai").then(r=>r.json());
    document.getElementById("aiBase").value = a.base || "";
    document.getElementById("aiModel").value = a.model || "";
    const k = document.getElementById("aiKey");
    k.value = "";
    k.placeholder = a.has_key ? ("已配置 " + a.key_hint + "，留空不修改") : "未配置";
  }catch(e){}
}

document.getElementById("aiSave").onclick = async () => {
  const msg = document.getElementById("aiMsg");
  msg.textContent = "保存中…";
  const body = {
    base: document.getElementById("aiBase").value.trim(),
    model: document.getElementById("aiModel").value.trim(),
    key: document.getElementById("aiKey").value.trim()
  };
  try{
    const r = await fetch("/ai", {method:"PUT", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)});
    const d = await r.json();
    msg.textContent = r.ok ? "已保存，立即生效" : ("保存失败：" + (d.detail || r.status));
    if(r.ok) loadAI();
  }catch(e){ msg.textContent = "保存失败：" + e.message; }
};

document.getElementById("aiTest").onclick = async () => {
  const msg = document.getElementById("aiMsg");
  msg.textContent = "测试中…";
  try{
    const r = await fetch("/ai/test", {method:"POST"});
    const d = await r.json();
    msg.textContent = r.ok ? ("连接正常，用时 " + (d.ms || "?") + " ms") : ("失败：" + (d.detail || r.status));
  }catch(e){ msg.textContent = "失败：" + e.message; }
};

document.getElementById("aiModelsBtn").onclick = async () => {
  const box = document.getElementById("aiModels");
  box.innerHTML = '<span class="chip">检测中…</span>';
  try{
    const r = await fetch("/ai/models");
    const d = await r.json();
    if(!r.ok){ box.innerHTML = '<span class="chip">' + (d.detail || r.status) + '</span>'; return; }
    const cur = document.getElementById("aiModel").value.trim();
    box.innerHTML = d.models.map(m =>
      '<span class="chip' + (m === cur ? ' on' : '') + '" data-m="' + m + '">' + m + '</span>'
    ).join("") || '<span class="chip">没有可用模型</span>';
    box.querySelectorAll(".chip[data-m]").forEach(c => {
      c.onclick = () => {
        document.getElementById("aiModel").value = c.dataset.m;
        box.querySelectorAll(".chip").forEach(x => x.classList.remove("on"));
        c.classList.add("on");
        document.getElementById("aiMsg").textContent = "已选择 " + c.dataset.m + "，点保存生效";
      };
    });
  }catch(e){ box.innerHTML = '<span class="chip">检测失败</span>'; }
};

async function loadAuto(){
  try{
    const a = await fetch("/auto_rename").then(r=>r.json());
    document.getElementById("autoState").textContent = a.enabled ? "已开启" : "已关闭";
    document.getElementById("autoCount").textContent = (a.renamed || 0) + " 个";
    document.getElementById("autoToggle").textContent = a.enabled ? "关闭" : "开启";
    document.getElementById("autoToggle").dataset.on = a.enabled ? "1" : "0";
    document.getElementById("autoMsg").textContent = a.last
      ? ("上次：" + day(a.last) + " · " + (a.last_name || ""))
      : "";
  }catch(e){}
}

document.getElementById("autoToggle").onclick = async () => {
  const btn = document.getElementById("autoToggle");
  const next = btn.dataset.on !== "1";
  try{
    const r = await fetch("/auto_rename", {method:"PUT", headers:{"Content-Type":"application/json"}, body: JSON.stringify({enabled: next})});
    if(r.ok){ await loadAuto(); document.getElementById("autoMsg").textContent = next ? "已开启：新完成的任务会自动改名" : "已关闭"; }
  }catch(e){}
};

async function loadAiSwitch(){
  try{
    const a = await fetch("/ai/status").then(r=>r.json());
    document.getElementById("aiOn").textContent = a.enabled ? "已开启" : "已关闭";
    const b = document.getElementById("aiToggle");
    b.textContent = a.enabled ? "关闭" : "开启";
    b.dataset.on = a.enabled ? "1" : "0";
  }catch(e){}
}

document.getElementById("aiToggle").onclick = async () => {
  const b = document.getElementById("aiToggle");
  const next = b.dataset.on !== "1";
  try{
    const r = await fetch("/ai/status", {method:"PUT", headers:{"Content-Type":"application/json"}, body: JSON.stringify({enabled: next})});
    if(r.ok){
      await loadAiSwitch();
      document.getElementById("aiSwitchMsg").textContent = next ? "已开启" : "已关闭：对话入口隐藏，改名退回规则清洗";
    }
  }catch(e){}
};

load().then(loadAI).then(loadAuto).then(loadAiSwitch).catch(e=>{document.getElementById("who").innerHTML='<div class="skel">读取失败：'+e.message+'</div>';});
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
threading.Thread(target=auto_watcher, daemon=True).start()


def job_retry_loop():
    """被 115 限流的任务，每 15 分钟试一次，能读了就自动续跑"""
    while True:
        time.sleep(900)
        try:
            paused = [
                j
                for j in _jobs.values()
                if j.get("status") == "paused" and "405" in (j.get("error") or "")
            ]
            if not paused:
                continue
            list_dir_items("0", 5, 0)
        except Exception:  # noqa: BLE001
            continue
        for j in paused:
            j["status"] = "queued"
            j["error"] = ""
            save_jobs()
            threading.Thread(
                target=_run_rename_job,
                args=(j["id"], j["cid"], j["recursive"], False),
                daemon=True,
            ).start()


threading.Thread(target=job_retry_loop, daemon=True).start()
load_jobs()
for _jid, _j in list(_jobs.items()):
    if _j.get("status") in ("queued", "running"):
        _j["status"] = "queued"
        threading.Thread(
            target=_run_rename_job,
            args=(_jid, _j["cid"], _j["recursive"], False),
            daemon=True,
        ).start()
