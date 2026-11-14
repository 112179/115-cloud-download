# 115 云下载中转

给 iOS 浏览器 / 快捷指令用的 **115 网盘云下载面板**。

115 网页版的写接口（添加、删除任务）要求 Cookie 鉴权 + 自研的 ECDH/AES 加密，`/lixianssp/` 还需要整包 RSA，在浏览器或快捷指令里直接调用基本不现实。这个项目把加密和登录态收在服务端，前端只发普通 JSON。

## 功能

- 粘贴磁力 / HTTP / FTP / 电驴链接，一次可多条
- 逐级浏览文件夹，选择保存位置
- 记住默认目录，下次打开自动定位
- 在选择器里直接新建文件夹
- 「进行中的任务」实时进度
- 「历史记录」已完成 / 失败筛选，可折叠、分页加载
- 后台页：115 账号、会员、空间占用、网站登录记录
- 网页账号密码登录，登录保持 10 年
- 文件夹列表双层缓存（服务端内存 + 浏览器 localStorage），根目录秒开
- 兼容 `X-Token` 调用，方便快捷指令

## 架构

```
浏览器 / 快捷指令
      │ HTTPS
      ▼
 Cloudflare 隧道 (cloudflared)
      ▼
 FastAPI (uvicorn, 127.0.0.1:7875)
      ▼
 p115client ──► clouddownload.115.com
```

## 快速开始

要求：Python 3.12+，一个能访问 115 的服务器（境外 IP 可能触发风控）。

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt

export API_TOKEN=$(openssl rand -hex 16)   # 快捷指令/API 用
venv/bin/uvicorn app:app --host 127.0.0.1 --port 7875
```

首次启动会生成网页登录账号，密码写在 `initial_password.txt`：

```
admin / xxxxxxxxx
```

### 登录 115 账号

浏览器打开 `/qr`，用 115 App 扫码。登录态保存在 `cookies.txt`，重启不丢。

扫码被风控时，可以在已登录的电脑浏览器里复制 Cookie，然后：

```bash
curl -X PUT http://127.0.0.1:7875/cookie \
  -H "X-Token: $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"cookie":"UID=...; CID=...; SEID=...; KID=..."}'
```

## 部署（systemd + Cloudflare 隧道）

```bash
# 服务
cp 115dl.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now 115dl

# 隧道（在 /etc/cloudflared/config.yml 增加一段）
#   - hostname: your-domain.example.com
#     service: http://127.0.0.1:7875
cloudflared tunnel route dns <TUNNEL_ID> your-domain.example.com
systemctl restart cloudflared
```

服务只监听 `127.0.0.1:7875`，不要直接暴露到公网。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `API_TOKEN` | 空 | 快捷指令用的令牌，空则不校验（不建议） |
| `DATA_DIR` | `/opt/115dl` | 数据目录（cookies、settings） |

## 数据文件

| 文件 | 内容 |
|---|---|
| `cookies.txt` | 115 登录态 |
| `settings.json` | 密码哈希、会话密钥、默认目录、登录记录 |
| `initial_password.txt` | 初始密码，改完可删 |
| `env` | `API_TOKEN`，权限 600 |

这些都在 `.gitignore` 里，不会进仓库。

## 主要接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 存活探针（公开） |
| GET | `/folders?cid=0&refresh=1` | 子文件夹，默认缓存 10 分钟 |
| POST | `/mkdir` | 新建文件夹 `{cid, name}` |
| POST | `/add` | 添加任务 `{urls, cid, savepath}` |
| GET | `/tasks?page=1&stat=11` | 任务列表（0 全部 / 11 完成 / 9 失败 / 12 进行中） |
| POST | `/task/{info_hash}/{action}` | retry / pause / resume / delete |
| GET/PUT/DELETE | `/default` | 记住的保存位置 |
| GET | `/account` | 115 账号与空间信息 |

鉴权：网页会话 Cookie，或 `X-Token` 头 / `?token=` 参数。

## 安全提示

- 只用 `API_TOKEN` 即可访问全部接口，泄露等于接管网盘操作，务必妥善保管
- 网页密码用 PBKDF2-SHA256（12 万轮 + 随机盐）存储
- 会话 Cookie 为 HMAC 签名，HttpOnly + Secure + SameSite=Lax
- 建议放在 Cloudflare Access 或反向代理后面再加一层保护

## License

MIT
