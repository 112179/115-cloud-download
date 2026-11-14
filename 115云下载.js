// 115 云下载（Scriptable）
// 用法：把脚本放进 Scriptable，改好 BASE / TOKEN，
//      复制磁力/直链后在 Scriptable 里运行，或从分享菜单运行。

const BASE = "https://your-domain.example.com";
const TOKEN = "YOUR_API_TOKEN";

async function api(path, method = "GET", body) {
  const req = new Request(BASE + path);
  req.method = method;
  req.headers = { "X-Token": TOKEN, "Content-Type": "application/json" };
  req.timeoutInterval = 30;
  if (body) req.body = JSON.stringify(body);
  const data = await req.loadJSON();
  if (!String(req.response.statusCode).startsWith("2")) {
    throw new Error(data.detail || JSON.stringify(data));
  }
  return data;
}

function choose(title, items) {
  const table = new UITable();
  const head = new UITableRow();
  head.addText(title);
  head.dismissOnSelect = false;
  table.addRow(head);
  return new Promise((resolve) => {
    for (const it of items) {
      const row = new UITableRow();
      row.addText(it.label, it.sub || "");
      row.dismissOnSelect = true;
      row.onSelect = () => resolve(it.value);
      table.addRow(row);
    }
    table.present();
  });
}

async function pickFolder() {
  let cid = "0";
  const stack = [{ cid: "0", name: "根目录" }];
  while (true) {
    const { folders } = await api(`/folders?cid=${cid}`);
    const here = stack.map((s) => s.name).join(" / ");
    const items = [
      { label: "✅ 下载到「" + stack[stack.length - 1].name + "」", value: "__pick__" },
      ...folders.map((f) => ({ label: "📁 " + f.name, value: f.cid })),
    ];
    if (stack.length > 1) items.push({ label: "⬆️ 上一级", value: "__up__" });
    items.push({ label: "❌ 取消", value: "__cancel__" });

    const picked = await choose("选择保存位置\n" + here, items);
    if (picked === "__cancel__") return null;
    if (picked === "__pick__") return { cid, path: stack.map((s) => s.name).join("/") };
    if (picked === "__up__") {
      stack.pop();
      cid = stack[stack.length - 1].cid;
      continue;
    }
    const f = folders.find((x) => x.cid === picked);
    stack.push({ cid: picked, name: f ? f.name : picked });
    cid = picked;
  }
}

function inputUrl() {
  if (args.plainTexts && args.plainTexts.length) return args.plainTexts.join("\n").trim();
  if (args.urls && args.urls.length) return args.urls[0];
  const text = pasteboard.text;
  if (text && /^(https?:\/\/|magnet:|ed2k:)/i.test(text.trim())) return text.trim();
  return "";
}

async function main() {
  let url = inputUrl();
  if (!url) {
    const a = new Alert();
    a.title = "115 云下载";
    a.addTextField("链接（HTTP/FTP/磁力/电驴）", "");
    a.addAction("下一步");
    a.addCancelAction("取消");
    if ((await a.presentAlert()) === -1) return;
    url = a.textFieldValue(0).trim();
  }
  if (!url) return;

  let target;
  try {
    target = await pickFolder();
  } catch (e) {
    const a = new Alert();
    a.title = "读取目录失败";
    a.message = String(e.message || e);
    a.addAction("好");
    await a.presentAlert();
    return;
  }
  if (!target) return;

  const confirm = new Alert();
  confirm.title = "确认添加";
  confirm.message = `保存到：${target.path}\n\n${url.slice(0, 120)}`;
  confirm.addAction("开始下载");
  confirm.addCancelAction("取消");
  if ((await confirm.presentAlert()) === -1) return;

  try {
    const res = await api("/add", "POST", { urls: [url], cid: target.cid });
    const r = res.results[0];
    const ok = r && r.state;
    const a = new Alert();
    a.title = ok ? "已添加 ✓" : "添加失败";
    a.message = ok ? `保存到：${target.path}` : JSON.stringify(r && (r.raw || r.error), null, 2);
    a.addAction("好");
    await a.presentAlert();
  } catch (e) {
    const a = new Alert();
    a.title = "请求失败";
    a.message = String(e.message || e);
    a.addAction("好");
    await a.presentAlert();
  }
}

await main();
Script.complete();
