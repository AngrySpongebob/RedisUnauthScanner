import sys
from PyQt6.QtWidgets import QApplication
from ui.main_window import RedisScannerGUI


def main():
    """程序主入口（PyQt6 兼容版）"""
    # 移除所有过时的高DPI适配代码，PyQt6默认启用高DPI缩放
    app = QApplication(sys.argv)
    window = RedisScannerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
