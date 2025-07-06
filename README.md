1.GIỚI THIỆU

Trong bối cảnh công nghệ phát triển, nhu cầu truyền tải tin nhắn văn bản nhanh chóng và an toàn trở nên cấp thiết. Tuy nhiên, việc thiếu biện pháp bảo mật khiến tin nhắn có thể bị chặn, đọc trộm, giả mạo hoặc chỉnh sửa.

Đề tài này xây dựng một hệ thống nhắn tin bảo mật với các mục tiêu:
- Bảo mật nội dung tin nhắn bằng TripleDES.
- Xác thực người gửi/người nhận bằng chữ ký số RSA 2048-bit.
- Đảm bảo tính toàn vẹn bằng SHA-256.
- Hệ thống hoạt động mô phỏng trên mô hình P2P.

2.TRÌNH BÀY KỸ THUẬT

a.Kiến trúc hệ thống
- Mô hình: Client–Server (Alice & Bob), mô phỏng truyền tin nhắn an toàn.
- Quy trình truyền tin:
  - Handshake: trao đổi khóa RSA.
  - Trao đổi khóa phiên 3DES (mã hóa bằng RSA).
  - Truyền tin an toàn: mã hóa bằng 3DES, kèm chữ ký số.
<img src="C:/Users/NguyenThao/Pictures/so_do_hoat_dong_chi_tiet.png" alt="So do hoat dong chi tiet cua ung dung chat bao mat" width="250">
