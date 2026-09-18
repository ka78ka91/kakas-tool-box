"""内置浏览器的 HTML 界面（多标签 + 地址栏 + 快捷入口）"""

HTML = r"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>隔离浏览器</title>
<style>
  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0; height: 100%;
    font-family: "Microsoft YaHei", sans-serif;
    background: #f5f6f8; color: #1a1a1a;
    user-select: none;
  }

  #tabbar {
    display: flex; align-items: flex-end;
    height: 36px; padding: 0 8px;
    background: #e8eaee; border-bottom: 1px solid #d5d8dd;
  }
  .tab {
    display: flex; align-items: center;
    height: 28px; padding: 0 10px 0 12px;
    margin-right: 2px;
    background: #d5d8dd; border-radius: 6px 6px 0 0;
    font-size: 12px; cursor: pointer; max-width: 200px;
  }
  .tab.active {
    background: #ffffff;
    font-weight: bold;
  }
  .tab .title {
    flex: 1; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tab .close {
    margin-left: 8px; color: #777;
    font-size: 14px; line-height: 1;
  }
  .tab .close:hover { color: #c00; }
  #addtab {
    width: 28px; height: 28px; line-height: 26px; text-align: center;
    font-size: 18px; cursor: pointer; color: #555;
    border-radius: 6px 6px 0 0;
  }
  #addtab:hover { background: #d5d8dd; }

  #toolbar {
    display: flex; align-items: center; gap: 6px;
    height: 44px; padding: 0 10px;
    background: #ffffff; border-bottom: 1px solid #e2e5ea;
  }
  button {
    height: 30px; min-width: 34px; padding: 0 10px;
    border: 1px solid #d5d8dd; border-radius: 6px;
    background: #f7f8fa; cursor: pointer;
    font-family: inherit; font-size: 13px;
  }
  button:hover { background: #eef3ff; border-color: #2d6cdf; }
  button:disabled {
    opacity: 0.4; cursor: not-allowed;
    background: #f0f0f0; border-color: #ddd;
  }
  #url {
    flex: 1; height: 30px; padding: 0 10px;
    border: 1px solid #d5d8dd; border-radius: 6px;
    font-family: "Consolas", monospace; font-size: 12px;
    background: #fff;
  }
  #url:focus { outline: none; border-color: #2d6cdf; }

  #quick {
    display: flex; align-items: center; gap: 6px;
    height: 36px; padding: 0 10px;
    background: #fafbfc; border-bottom: 1px solid #e2e5ea;
    font-size: 12px;
  }
  .quick-btn {
    padding: 4px 10px; border-radius: 4px;
    background: #eef3ff; color: #2d6cdf;
    cursor: pointer; font-size: 12px;
  }
  .quick-btn:hover { background: #dbe7ff; }

  #content {
    position: absolute;
    top: 116px; left: 0; right: 0; bottom: 0;
    background: #fff;
  }
  #frame {
    width: 100%; height: 100%; border: none;
  }

  #status {
    position: absolute; bottom: 0; left: 0; right: 0;
    height: 22px; line-height: 22px; padding: 0 10px;
    background: #2d6cdf; color: #fff; font-size: 11px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    z-index: 10;
  }
  #status.error { background: #c00; }
  #status.warn { background: #d89000; }

  #fallback {
    display: none;
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center; color: #555;
    font-size: 14px;
  }
  #fallback button {
    margin-top: 12px;
    padding: 8px 16px; font-size: 14px;
  }
</style>
</head>
<body>

<div id="tabbar">
  <div id="tabs"></div>
  <div id="addtab" title="新建标签页">+</div>
</div>

<div id="toolbar">
  <button id="back" title="后退">←</button>
  <button id="forward" title="前进">→</button>
  <button id="reload" title="刷新">⟳</button>
  <button id="home" title="主页">🏠</button>
  <input id="url" type="text" placeholder="输入 URL 或搜索关键词">
  <button id="go" title="转到">转到</button>
  <button id="open_ext" title="在系统浏览器打开">🌐</button>
</div>

<div id="quick">
  <span style="color:#888;">快捷:</span>
  <span class="quick-btn" data-url="https://www.virustotal.com">VirusTotal</span>
  <span class="quick-btn" data-url="https://urlscan.io">URLScan</span>
  <span class="quick-btn" data-url="https://ip.sb">IP 查询</span>
  <span class="quick-btn" data-url="https://www.baidu.com">百度</span>
  <span class="quick-btn" data-url="https://www.bing.com">Bing</span>
  <span class="quick-btn" data-url="about:blank">空白页</span>
</div>

<div id="content">
  <iframe id="frame" sandbox="allow-scripts allow-same-origin allow-forms allow-popups"></iframe>
  <div id="fallback">
    <div>⚠ 该网站拒绝被嵌入，无法在此显示。</div>
    <div style="font-size:12px;color:#888;margin-top:8px;">
      （X-Frame-Options / CSP 限制）
    </div>
    <button id="open_sys">在系统浏览器中打开</button>
  </div>
</div>

<div id="status">就绪</div>

<script>
const HOME = "about:blank";
const tabs = [];
let active_id = null;
let next_id = 1;

const tabsEl = document.getElementById("tabs");
const frame = document.getElementById("frame");
const urlInput = document.getElementById("url");
const statusEl = document.getElementById("status");
const fallback = document.getElementById("fallback");
const btnBack = document.getElementById("back");
const btnForward = document.getElementById("forward");

function setStatus(text, level="") {
  statusEl.textContent = text;
  statusEl.className = level;
}

function getActive() {
  return tabs.find(t => t.id === active_id);
}

function renderTabs() {
  tabsEl.innerHTML = "";
  tabs.forEach(t => {
    const div = document.createElement("div");
    div.className = "tab" + (t.id === active_id ? " active" : "");
    div.innerHTML = `<span class="title">${escapeHtml(t.title || "新标签页")}</span>
                     <span class="close" data-close="${t.id}">×</span>`;
    div.addEventListener("click", e => {
      if (e.target.dataset.close) {
        closeTab(parseInt(e.target.dataset.close));
      } else {
        switchTab(t.id);
      }
    });
    tabsEl.appendChild(div);
  });
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",
    '"':"&quot;","'":"&#39;"
  }[c]));
}

function updateNavBtns() {
  const t = getActive();
  if (!t) return;
  btnBack.disabled = t.hist_idx <= 0;
  btnForward.disabled = t.hist_idx >= t.history.length - 1;
}

function normalizeUrl(input) {
  input = (input || "").trim();
  if (!input) return HOME;
  if (input === "about:blank") return input;
  if (/^https?:\/\//i.test(input)) return input;
  if (/^[\w-]+(\.[\w-]+)+/.test(input)) return "https://" + input;
  return "https://www.baidu.com/s?wd=" + encodeURIComponent(input);
}

function loadInTab(tab, url, push=true) {
  tab.url = url;
  if (push) {
    tab.history = tab.history.slice(0, tab.hist_idx + 1);
    tab.history.push(url);
    tab.hist_idx = tab.history.length - 1;
  }
  urlInput.value = url === "about:blank" ? "" : url;
  setStatus("加载中: " + url);

  fallback.style.display = "none";
  frame.style.display = "block";
  if (url === "about:blank") {
    frame.src = "about:blank";
  } else {
    frame.src = url;
  }

  tab.title = url === "about:blank" ? "新标签页" : url;
  renderTabs();
  updateNavBtns();
  setStatus("已加载: " + url);
}

function createTab(url = HOME, switchTo = true) {
  const t = { id: next_id++, title: "新标签页", url: HOME,
              history: [], hist_idx: -1 };
  tabs.push(t);
  loadInTab(t, url);
  if (switchTo) {
    active_id = t.id;
    renderTabs();
    updateNavBtns();
  }
  return t;
}

function closeTab(id) {
  const idx = tabs.findIndex(t => t.id === id);
  if (idx < 0) return;
  tabs.splice(idx, 1);
  if (tabs.length === 0) {
    createTab();
    return;
  }
  if (active_id === id) {
    const newIdx = Math.min(idx, tabs.length - 1);
    active_id = tabs[newIdx].id;
    const t = tabs[newIdx];
    loadInTab(t, t.url, false);
  }
  renderTabs();
}

function switchTab(id) {
  const t = tabs.find(x => x.id === id);
  if (!t) return;
  active_id = id;
  loadInTab(t, t.url, false);
  renderTabs();
}

document.getElementById("addtab").onclick = () => createTab();

document.getElementById("go").onclick = () => {
  const url = normalizeUrl(urlInput.value);
  const t = getActive();
  if (t) loadInTab(t, url);
};

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") document.getElementById("go").click();
});

btnBack.onclick = () => {
  const t = getActive();
  if (t && t.hist_idx > 0) {
    t.hist_idx--;
    loadInTab(t, t.history[t.hist_idx], false);
    updateNavBtns();
  }
};

btnForward.onclick = () => {
  const t = getActive();
  if (t && t.hist_idx < t.history.length - 1) {
    t.hist_idx++;
    loadInTab(t, t.history[t.hist_idx], false);
    updateNavBtns();
  }
};

document.getElementById("reload").onclick = () => {
  const t = getActive();
  if (t) loadInTab(t, t.url, false);
};

document.getElementById("home").onclick = () => {
  const t = getActive();
  if (t) loadInTab(t, HOME);
};

document.getElementById("open_ext").onclick = () => {
  const t = getActive();
  if (t && t.url && t.url !== "about:blank") {
    pywebview.api.open_external(t.url);
  }
};

document.getElementById("open_sys").onclick = () => {
  const t = getActive();
  if (t && t.url) pywebview.api.open_external(t.url);
};

document.querySelectorAll(".quick-btn").forEach(el => {
  el.onclick = () => {
    const url = el.dataset.url;
    const t = getActive();
    if (t) loadInTab(t, url);
  };
});

frame.addEventListener("load", () => {
  const t = getActive();
  if (!t) return;
  setStatus("已加载: " + t.url);
});

createTab("about:blank");
</script>
</body>
</html>
"""