import sqlite3
from datetime import datetime
from typing import Optional, Tuple


class ScanRecordDB:
    """扫描记录数据库管理类（轻量化SQLite）"""

    def __init__(self, db_path: str = "redis_scan_records.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # 创建扫描记录表：唯一约束（host+port）避免重复
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS scan_records
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           host
                           TEXT
                           NOT
                           NULL,
                           port
                           TEXT
                           NOT
                           NULL,
                           is_vulnerable
                           INTEGER
                           NOT
                           NULL,
                           detail
                           TEXT
                           NOT
                           NULL,
                           scan_time
                           TEXT
                           NOT
                           NULL,
                           UNIQUE
                       (
                           host,
                           port
                       )
                           )
                       ''')
        conn.commit()
        conn.close()

    def check_scanned(self, host: str, port: str) -> Tuple[bool, Optional[dict]]:
        """
        检查目标是否已扫描过
        :return: (是否已扫描, 扫描记录字典/None)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT is_vulnerable, detail, scan_time
                       FROM scan_records
                       WHERE host = ?
                         AND port = ?
                       ''', (host, port))
        result = cursor.fetchone()
        conn.close()

        if result:
            record = {
                "is_vulnerable": bool(result[0]),
                "detail": result[1],
                "scan_time": result[2]
            }
            return True, record
        return False, None

    def save_scan_result(self, host: str, port: str, is_vulnerable: bool, detail: str):
        """保存/更新扫描结果到数据库"""
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # 插入新记录
            cursor.execute('''
                           INSERT INTO scan_records
                               (host, port, is_vulnerable, detail, scan_time)
                           VALUES (?, ?, ?, ?, ?)
                           ''', (host, port, int(is_vulnerable), detail, scan_time))
        except sqlite3.IntegrityError:
            # 已存在则更新
            cursor.execute('''
                           UPDATE scan_records
                           SET is_vulnerable=?,
                               detail=?,
                               scan_time=?
                           WHERE host = ?
                             AND port = ?
                           ''', (int(is_vulnerable), detail, scan_time, host, port))
        finally:
            conn.commit()
            conn.close()

    def clear_all_records(self):
        """清空所有扫描记录（谨慎使用）"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scan_records')
        conn.commit()
        conn.close()
