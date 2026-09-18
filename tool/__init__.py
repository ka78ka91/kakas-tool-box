class Tool:
    """所有工具的基类。"""

    name = "tool"              # 内部标识，唯一
    display_name = "工具"      # 主页显示名
    description = ""           # 主页描述
    icon = "🔧"                # 主页图标（Emoji 或单字符）

    def __init__(self, app):
        self.app = app
        self._visible = False

    def build(self, parent):
        """在 parent 中创建 UI。子类必须实现。"""
        raise NotImplementedError

    def on_show(self):
        """工具被显示时调用（可用于启动定时器、懒加载）。"""
        self._visible = True

    def on_hide(self):
        """工具被隐藏时调用（可用于取消定时器）。"""
        self._visible = False