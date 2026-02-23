import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMessageBox, QHeaderView
from PyQt6.QtCore import Qt

# --- IMPORT CÁC FILE CỦA BẠN ---
from GUICrawl import Ui_MainWindow       # Import Giao diện
from feature_crawl import CrawlerThread  # Import logic nút Crawl
from feature_lfi import LFIThread        # Import logic nút Tấn công

class PhanMemLFI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.danh_sach_muc_tieu = []

        # --- CẤU HÌNH BẢNG (tableWidget) ---
        self.ui.tableWidget.setColumnCount(4)
        self.ui.tableWidget.setHorizontalHeaderLabels(["STT", "URL Mục Tiêu", "Payload", "Kết Quả"])
        header = self.ui.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        # --- KẾT NỐI NÚT BẤM VỚI CÁC HÀM BÊN DƯỚI ---
        self.ui.jBntScan.clicked.connect(self.xu_ly_crawl)
        self.ui.pushButton.clicked.connect(self.xu_ly_lfi)
        self.ui.pushButton.setEnabled(False)

    # ==========================================
    # PHẦN XỬ LÝ NÚT CRAWL (GỌI FILE 1)
    # ==========================================
    def xu_ly_crawl(self):
        # 1. Lấy link từ ô nhập liệu
        url = self.ui.txtGetLink.toPlainText().strip()

        # 2. Kiểm tra đầu vào
        if not url:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập URL!")
            return

        # Tự động thêm http:// nếu người dùng quên
        if not url.startswith("http"):
            url = "http://" + url
            self.ui.txtGetLink.setPlainText(url)

        # 3. Reset giao diện về trạng thái ban đầu
        self.danh_sach_muc_tieu = []
        self.ui.textBrowser.clear()
        self.ui.jBntScan.setEnabled(False)  # Khóa nút quét
        self.ui.jBntScan.setText("Đang chạy...")  # Đổi tên nút

        # 4. Khởi tạo "Công nhân" Crawler (Độ sâu 2 để test cho nhanh)
        self.crawler = CrawlerThread(url, 3)

        # --- [QUAN TRỌNG] KẾT NỐI TÍN HIỆU (TÊN TIẾNG VIỆT) ---
        # Đảm bảo file feature_crawl.py cũng dùng tên: tin_nhan, tim_thay_link, hoan_thanh
        self.crawler.tin_nhan.connect(self.ui.textBrowser.append)
        self.crawler.tim_thay_link.connect(self.luu_link_ngon)
        self.crawler.hoan_thanh.connect(self.crawl_xong)

        # 5. Ra lệnh chạy
        self.crawler.start()

    def luu_link_ngon(self, url):
        if url not in self.danh_sach_muc_tieu:
            self.danh_sach_muc_tieu.append(url)

    def crawl_xong(self):
        self.ui.jBntScan.setEnabled(True)
        if len(self.danh_sach_muc_tieu) > 0:
            self.ui.pushButton.setEnabled(True)
            QMessageBox.information(self, "Thông báo", f"Tìm thấy {len(self.danh_sach_muc_tieu)} link ngon!\nSẵn sàng tấn công.")
        else:
            QMessageBox.warning(self, "Thông báo", "Không tìm thấy link nào.")

    # ==========================================
    # PHẦN XỬ LÝ NÚT LFI (GỌI FILE 2)
    # ==========================================
    def xu_ly_lfi(self):
        self.ui.tableWidget.setRowCount(0)

        # Gọi "Công nhân" LFI từ file feature_lfi.py
        self.attacker = LFIThread(self.danh_sach_muc_tieu)

        # Kết nối dây tin nhắn
        self.attacker.log_process.connect(self.ui.textBrowser.append)
        self.attacker.ket_qua_scan.connect(self.dien_vao_bang)

        # Bắt đầu làm việc
        self.attacker.start()

    def dien_vao_bang(self, url, payload, status):
        row = self.ui.tableWidget.rowCount()
        self.ui.tableWidget.insertRow(row)

        self.ui.tableWidget.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.ui.tableWidget.setItem(row, 1, QTableWidgetItem(url))
        self.ui.tableWidget.setItem(row, 2, QTableWidgetItem(payload))

        item_status = QTableWidgetItem(status)
        item_status.setForeground(Qt.GlobalColor.red)
        self.ui.tableWidget.setItem(row, 3, item_status)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PhanMemLFI()
    window.show()
    sys.exit(app.exec())