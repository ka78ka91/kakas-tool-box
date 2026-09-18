"""隔离浏览器的独立进程入口。"""

import os
import sys
import webbrowser

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import webview
from tool._browser_ui import HTML


class BrowserApi:
    def open_external(self, url):
        try:
            webbrowser.open(url)
        except Exception:
            pass


def main(initial_url="about:blank"):
    api = BrowserApi()
    window = webview.create_window(
        "隔离浏览器 - 打开可疑链接时请勿登录任何账号",
        html=HTML,
        js_api=api,
        width=1100, height=750,
        min_size=(700, 450),
        confirm_close=False,
    )

    def on_loaded():
        if initial_url and initial_url != "about:blank":
            try:
                window.load_url(initial_url)
            except Exception:
                pass

    window.events.loaded += on_loaded
    webview.start(
        gui="edgechromium",
        debug=False,
        private_mode=True,
        storage_path=os.path.join(
            os.environ.get("TEMP", "."),
            "toolbox_browser_profile"),
    )


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "about:blank"
    main(url)