import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
    QTextEdit, QPushButton, QLabel, QProgressBar, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from core.worker import ScanWorker
from core.database import ScanRecordDB


class RedisScannerGUI(QMainWindow):
    """主窗口类"""

    def __init__(self):
        super().__init__()
        self.worker = None
        self.db = ScanRecordDB()
        # 设置主窗口唯一ID
        self.setObjectName("main_window")
        self._init_ui()

    def _init_ui(self):
        """初始化界面（所有控件设置唯一ID）"""
        # 窗口基础设置
        self.setWindowTitle("Redis 未授权访问批量扫描器（ID控样式版）")
        self.setGeometry(100, 100, 1000, 700)
        self.setMinimumSize(800, 500)

        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # 1. 输入区域
        self.input_label = QLabel("目标列表 (IP:Port 或 IP，一行一个，#开头为注释):")
        self.input_label.setObjectName("input_label")  # 唯一ID
        main_layout.addWidget(self.input_label)

        self.target_textarea = QTextEdit()
        self.target_textarea.setObjectName("target_textarea")  # 唯一ID
        self.target_textarea.setPlaceholderText(
            "192.168.1.100\n"
            "10.0.0.1:6380\n"
            "example.com\n"
            "172.16.0.50:6379\n"
            "# 这是注释行，不会被扫描"
        )
        main_layout.addWidget(self.target_textarea)

        # 2. 控制按钮区域
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        # 开始扫描按钮（唯一ID）
        self.start_button = QPushButton("开始扫描")
        self.start_button.setObjectName("start_button")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)

        # 停止扫描按钮（唯一ID）
        self.stop_button = QPushButton("停止扫描")
        self.stop_button.setObjectName("stop_button")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)

        # 清空结果按钮（唯一ID）
        self.clear_result_btn = QPushButton("清空结果")
        self.clear_result_btn.setObjectName("clear_result_btn")
        self.clear_result_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_result_btn)

        # 清空记录按钮（唯一ID）
        self.clear_record_btn = QPushButton("清空扫描记录")
        self.clear_record_btn.setObjectName("clear_record_btn")
        self.clear_record_btn.clicked.connect(self.clear_scan_records)
        button_layout.addWidget(self.clear_record_btn)

        # 重新加载样式按钮（唯一ID）
        self.reload_style_btn = QPushButton("重新加载样式")
        self.reload_style_btn.setObjectName("reload_style_btn")
        self.reload_style_btn.clicked.connect(lambda: self.load_style_sheet("styles/main_style.qss"))
        button_layout.addWidget(self.reload_style_btn)

        main_layout.addLayout(button_layout)

        # 3. 进度条（唯一ID）
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progress_bar")
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # 4. 结果区域
        self.result_label = QLabel("扫描结果:")
        self.result_label.setObjectName("result_label")  # 唯一ID
        main_layout.addWidget(self.result_label)

        self.result_textarea = QTextEdit()
        self.result_textarea.setObjectName("result_textarea")  # 唯一ID
        self.result_textarea.setReadOnly(True)
        main_layout.addWidget(self.result_textarea)

        # 状态栏（唯一ID）
        self.status_bar = self.statusBar()
        self.status_bar.setObjectName("status_bar")
        self.status_bar.showMessage("就绪 | 未加载任何目标", 5000)

        # 加载外部QSS（仅通过ID生效）
        self.load_style_sheet("styles/main_style.qss")

    def load_style_sheet(self, qss_path: str):
        """加载外部QSS样式文件（仅ID控样式）"""
        try:
            with open(qss_path, 'r', encoding='utf-8') as f:
                qss_style = f.read()
                self.setStyleSheet(qss_style)
        except FileNotFoundError:
            QMessageBox.warning(self, "警告", f"样式文件未找到：{qss_path}\n请检查styles文件夹是否存在")
        except Exception as e:
            QMessageBox.warning(self, "警告", f"加载样式失败：{str(e)}")

    def parse_targets(self) -> list:
        """解析目标列表，过滤无效格式"""
        text = self.target_textarea.toPlainText().strip()
        if not text:
            return []

        # 正则表达式：匹配IP/域名+可选端口
        valid_ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?$'
        )
        valid_domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(?::\d{1,5})?$'
        )

        targets = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            line = line.strip()
            # 忽略空行、注释行
            if not line or line.startswith('#'):
                continue
            # 验证格式
            if valid_ip_pattern.match(line) or valid_domain_pattern.match(line):
                targets.append(line)
            else:
                self.result_textarea.append(f"[第{idx}行警告] 无效目标格式: {line}")

        return targets

    def start_scan(self):
        """启动扫描"""
        targets = self.parse_targets()
        if not targets:
            QMessageBox.warning(self, "警告", "请输入至少一个有效的目标！")
            return

        # 初始化扫描状态
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(len(targets))
        self.progress_bar.setValue(0)
        self.status_bar.showMessage(f"正在扫描... (0/{len(targets)})")

        # 输出扫描开始信息
        self.result_textarea.append("=" * 80)
        self.result_textarea.append(f"开始扫描 {len(targets)} 个目标（已扫描目标将自动跳过）...")
        self.result_textarea.append("=" * 80)

        # 创建并启动扫描线程
        self.worker = ScanWorker(targets, max_threads=20, timeout=20)
        self.worker.result_signal.connect(self.update_result)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.start()

    def update_result(self, target: str, is_vulnerable: bool, detail: str, is_skipped: bool):
        """更新扫描结果到界面"""
        # 设置文字颜色：漏洞(红)、跳过(蓝)、安全(绿)
        if is_skipped:
            color = "#2196F3"  # 蓝色（跳过）
            status = "【已扫描】"
        elif is_vulnerable:
            color = "#F44336"  # 红色（漏洞）
            status = "【漏洞存在】"
        else:
            color = "#4CAF50"  # 绿色（安全）
            status = "【安全】"

        # 输出结果
        self.result_textarea.append(
            f'<span style="color:{color}; font-weight:bold;">{status} {target}</span> - {detail}'
        )

        # 更新进度条和状态栏
        current = self.progress_bar.value() + 1
        self.progress_bar.setValue(current)
        self.status_bar.showMessage(f"正在扫描... ({current}/{self.progress_bar.maximum()})")

    def scan_finished(self):
        """扫描完成回调"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("扫描完成", 5000)
        self.result_textarea.append("\n" + "=" * 80)
        self.result_textarea.append("扫描任务完成！")
        self.result_textarea.append("=" * 80 + "\n")
        QMessageBox.information(self, "完成", "扫描已完成！")

    def stop_scan(self):
        """停止扫描"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage("扫描已停止", 5000)
            self.result_textarea.append("\n[信息] 扫描已被用户手动停止！\n")

    def clear_results(self):
        """清空结果显示区域"""
        self.result_textarea.clear()
        self.status_bar.showMessage("结果已清空", 3000)

    def clear_scan_records(self):
        """清空数据库中的扫描记录"""
        confirm = QMessageBox.question(
            self,
            "确认",
            "是否确定清空所有扫描记录？此操作不可恢复！",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.db.clear_all_records()
            self.status_bar.showMessage("扫描记录已清空", 5000)
            QMessageBox.information(self, "完成", "所有扫描记录已清空！")
