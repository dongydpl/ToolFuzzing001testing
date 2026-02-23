import requests
from collections import deque
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from PyQt6.QtCore import QThread, pyqtSignal


class CrawlerThread(QThread):
    tin_nhan = pyqtSignal(str)
    tim_thay_link = pyqtSignal(str)
    hoan_thanh = pyqtSignal()

    def __init__(self, start_url: str, max_depth: int):
        super().__init__()
        self.start_url = start_url
        self.max_depth = max_depth
        self.is_running = True

    def run(self):
        target = self.start_url
        if not target.startswith("http"):
            target = "http://" + target

        queue = deque([(target, 0)])

        visited = set([target])

        self.tin_nhan.emit(f"Bắt đầu quét: {target}")

        while queue and self.is_running:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            self.tin_nhan.emit(f"[*] Đang quét (Depth {depth}): {url}")

            try:
                res = requests.get(url, timeout=3)

                if res.status_code != 200:
                    continue

                parsed = urlparse(url)
                if parsed.query:
                    self.tin_nhan.emit(f"<b style='color:blue;'>[+] MỤC TIÊU: {url}</b>")
                    self.tim_thay_link.emit(url)


                if depth < self.max_depth:
                    soup = BeautifulSoup(res.text, "html.parser")

                    for tag in soup.find_all("a"):
                        href = tag.get("href")
                        if not href: continue
                        
                        full_url = urljoin(url, href)

                        if urlparse(full_url).netloc == urlparse(target).netloc:
                            if full_url not in visited:
                                visited.add(full_url)
                                queue.append((full_url, depth + 1))

            except Exception:
                pass

        self.tin_nhan.emit("<b>--- ĐÃ CRAWL XONG ---</b>")
        self.hoan_thanh.emit()

    def stop(self):
        self.is_running = False