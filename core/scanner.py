import socket
from dataclasses import dataclass

@dataclass
class ScanResult:
    """扫描结果数据类，统一返回格式"""
    host: str
    port: str
    is_vulnerable: bool
    detail: str
    target_str: str  # 原始目标字符串（IP:Port/IP）

class RedisScanner:
    """Redis未授权访问扫描核心类"""
    def __init__(self, timeout: int = 20):
        self.timeout = timeout

    def check_redis_unauth(self, host: str, port: str = "6379") -> ScanResult:
        """
        检查单个Redis目标是否存在未授权访问
        :param host: 目标主机（IP/域名）
        :param port: 目标端口
        :return: ScanResult 对象
        """
        target_str = f"{host}:{port}"
        try:
            # 创建socket连接
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, int(port)))

            # 发送INFO命令检测未授权
            s.send(b'*1\r\n$4\r\ninfo\r\n')
            response = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()

            # 结果判断
            if response and response.startswith('-NOAUTH'):
                return ScanResult(host, port, False, "需要认证", target_str)
            elif response and len(response) > 10:
                return ScanResult(host, port, True, f"存在未授权访问 (响应长度: {len(response)})", target_str)
            else:
                return ScanResult(host, port, False, f"无法确认 (响应: {response[:50]}...)", target_str)

        except socket.timeout:
            return ScanResult(host, port, False, "连接超时", target_str)
        except ConnectionRefusedError:
            return ScanResult(host, port, False, "连接被拒绝", target_str)
        except Exception as e:
            return ScanResult(host, port, False, f"连接失败 ({str(e)})", target_str)