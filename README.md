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
- 点击历史记录可改文件名；配置 AI 后用模型重写，没配置则用规则清洗
- AI 对话框：用自然语言查目录、搜索、改名、新建文件夹、添加下载
- 后台页：115 账号、会员、空间占用、网站登录记录、AI 总开关与模型配置
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

## 部署方式

项目本身只是一个常驻的 Python 进程，硬性要求只有两点：**能长期在线**、**能访问 115**。VPS 不是必须的。

| 方案 | 可行性 | 说明 |
|---|---|---|
| 家里的 NAS / 软路由 / 树莓派 / 旧电脑 | ✅ 推荐 | 国内网络访问 115 最快，也没有境外 IP 风控；配合 Cloudflare Tunnel 不需要公网 IP |
| 云服务器（VPS） | ✅ 可以 | 随时可用，但跨境到 115 的延迟 1–2 秒，扫码登录偶尔触发风控 |
| 免费 PaaS（Render / Railway / Fly.io） | ⚠️ 能用但别扭 | 免费实例会休眠，冷启动几十秒；数据中心 IP 更容易被 115 拦 |
| Cloudflare Workers | ❌ 不行 | 跑不了 Python 和 p115client，除非把 ECDH/RSA 整套重写成 JS |
| iPhone 上的 iSH | ⚠️ 仅临时 | iOS 会挂起后台进程，快捷指令调用时服务可能已经睡了 |

最低配置：1 核 / 512MB 内存 / 100MB 磁盘，不需要数据库，全部状态就是 `cookies.txt` + `settings.json` 两个文件。

没有公网 IP 也没关系：Cloudflare Tunnel 由内网机器主动向外连接，不需要路由器开端口，免费。

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
| `GITHUB_URL` | 空 | 填了会在页面底部显示 GitHub 链接 |
| `AI_BASE_URL` | 空 | OpenAI 兼容地址，例如 `http://127.0.0.1:7863/v1` |
| `AI_API_KEY` | 空 | 上面的 API Key |
| `AI_MODEL` | `deepseek-v4.1-flash` | 模型名 |
| `RENAME_MIN_INTERVAL` | `2.5` | 两次改名之间的最小间隔（秒） |
| `RENAME_MAX_PER_MIN` | `20` | 每分钟改名上限 |
| `RENAME_MAX_PER_HOUR` | `180` | 每小时改名上限 |

## AI 改文件名

后台页「AI 功能」有一个总开关：关闭后对话入口隐藏、`/chat` 返回 403、改名自动退回规则清洗。

接口地址、模型、密钥可以直接在后台页 `/admin` 的「AI 配置」里填，保存即生效，优先级高于环境变量。

- 「检测可用模型」：向网关请求 `/v1/models`，列出全部可用模型，点一下就能填入，再保存
- 「测试」：发一次最小请求验证连通性，返回耗时

历史记录里点任意一条已完成任务，会弹出改名框：

- 配了接口地址 + 密钥（后台页可直接填，或写环境变量）：调用模型重写文件名，弹窗里显示 `AI` 标记
- 没配：自动降级为规则清洗，显示 `规则` 标记

规则清洗做这几件事：去掉 `www.xxx.com@` 前缀、去掉 `【站点名发布】` 和含网址的方括号、下划线转空格、清理多余空格，保留原扩展名。

AI 与规则的输出都会做一层兜底：剥离 `<>|*?"\/:` 等 115 不允许的字符，扩展名跟原名保持一致。

### 防 115 风控

改名是写操作，频繁调用容易触发限制，所以加了三层保护：

- 两次请求之间强制最小间隔（默认 2.5 秒），并叠加 0.15–0.45 秒随机抖动
- 每分钟 20 次、每小时 180 次上限，超出返回 `429` 和 `retry_after`
- 一旦 115 返回「操作频繁 / 稍后 / 风控」之类的提示，自动停用改名 2 分钟

前端收到 `429` 会把「应用」按钮变成倒计时，等冷却结束才能再点。

## 数据文件

| 文件 | 内容 |
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

## AI 文件助手

主界面右下角的「AI」按钮打开对话框，模型通过 function calling 调用这些工具：

| 工具 | 作用 |
| `list_dir` | 列出目录下的文件夹和文件 |
| `search_files` | 按关键词全盘搜索 |
| `clean_name` | 为文件名生成规范化建议（不落盘） |
| `rename_file` | 重命名文件 / 文件夹 |
| `mkdir` | 新建文件夹 |
| `add_download` | 添加云下载任务 |
| `list_tasks` | 查看下载任务 |

没有提供删除工具。改名会走前面那套限流，触发风控会返回错误让模型自己停手。
模型调用的每一步都会在气泡下方显示（如 `🔧 list_dir → 目录 11 个`），方便确认它做了什么。

## 安全提示

- 只用 `API_TOKEN` 即可访问全部接口，泄露等于接管网盘操作，务必妥善保管
- 网页密码用 PBKDF2-SHA256（12 万轮 + 随机盐）存储
- 会话 Cookie 为 HMAC 签名，HttpOnly + Secure + SameSite=Lax
- 建议放在 Cloudflare Access 或反向代理后面再加一层保护

## License

MIT
