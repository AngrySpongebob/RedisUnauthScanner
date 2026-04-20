import sys
from PyQt6.QtWidgets import QApplication
from ui.main_window import RedisScannerGUI


def main():
    """程序主入口"""
    app = QApplication(sys.argv)
    window = RedisScannerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
