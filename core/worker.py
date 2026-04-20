from PyQt6.QtCore import QThread, pyqtSignal
from concurrent.futures import ThreadPoolExecutor, as_completed
from .scanner import RedisScanner, ScanResult
from .database import ScanRecordDB


class ScanWorker(QThread):
    """扫描线程类（封装线程池+数据库查询）"""
    # 信号定义：目标字符串、是否漏洞、详情、是否跳过
    result_signal = pyqtSignal(str, bool, str, bool)
    finished_signal = pyqtSignal()

    def __init__(self, targets: list, max_threads: int = 10, timeout: int = 20):
        super().__init__()
        self.targets = targets  # 原始目标列表（IP/IP:Port）
        self.max_threads = max_threads
        self.timeout = timeout
        self.scanner = RedisScanner(timeout=timeout)
        self.db = ScanRecordDB()
        self.running = True

    def _parse_target(self, target_str: str) -> tuple:
        """解析目标字符串为(host, port)"""
        if ':' in target_str:
            host, port = target_str.rsplit(':', 1)
            port = port.strip()
        else:
            host = target_str.strip()
            port = "6379"
        return host, port

    def run(self):
        """执行批量扫描（含已扫描目标跳过逻辑）"""

        def scan_single(target_str: str) -> ScanResult:
            """扫描单个目标（内部函数，供线程池调用）"""
            if not self.running:
                raise RuntimeError("扫描已停止")
            host, port = self._parse_target(target_str)

            # 先检查数据库：已扫描则直接返回记录
            scanned, record = self.db.check_scanned(host, port)
            if scanned:
                return ScanResult(
                    host=host,
                    port=port,
                    is_vulnerable=record["is_vulnerable"],
                    detail=f"[已扫描] {record['detail']} (扫描时间: {record['scan_time']})",
                    target_str=target_str
                )

            # 未扫描则执行检测
            result = self.scanner.check_redis_unauth(host, port)
            # 保存结果到数据库
            self.db.save_scan_result(host, port, result.is_vulnerable, result.detail)
            return result

        # 线程池执行扫描
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_single, t): t for t in self.targets}

            for future in as_completed(futures):
                if not self.running:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    result = future.result()
                    # 判断是否是跳过的记录
                    is_skipped = "[已扫描]" in result.detail
                    self.result_signal.emit(
                        result.target_str,
                        result.is_vulnerable,
                        result.detail,
                        is_skipped
                    )
                except Exception as e:
                    self.result_signal.emit(
                        "未知目标",
                        False,
                        f"扫描异常: {str(e)}",
                        False
                    )

        self.finished_signal.emit()

    def stop(self):
        """停止扫描"""
        self.running = False
