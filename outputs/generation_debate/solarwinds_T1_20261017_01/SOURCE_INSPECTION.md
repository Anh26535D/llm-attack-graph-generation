# Đối chiếu một số thay đổi với nguồn

Đây là ghi chú đọc nguồn do assistant hỗ trợ, **không phải gold chuyên gia
độc lập** và không dùng để tính accuracy. Locator là các paragraph nguyên
bản trong `paragraphs.json`/`report.txt`; dữ liệu không được biên thêm.

## Thay đổi có căn cứ trực tiếp để xem xét

1. **Bổ sung kiểm tra kết nối:** P044 nói sau khi qua blocklist, sample thử
   resolve `api.solarwinds.com`. P046 nói vòng DGA bắt đầu khi blocklist và
   connectivity checks đều pass. Node mới của debate và self-refine thể
   hiện điều kiện này rõ hơn cạnh nối thẳng cũ.
2. **Nhánh dừng:** P046 mô tả IP thuộc những dải blocklist làm malware dừng
   và cập nhật `ReportWatcherRetry` để ngăn thực thi tiếp. Node mới của debate
   nêu nhánh kết thúc; không coi nó là hành động luôn xảy ra trên mọi victim.
3. **Chủ thể kỹ thuật C2:** P018 nói “the actor” đặt hostname, P024 nói actor
   chọn VPS/IP cùng nước victim. Baseline vẽ BEACON → C2 masquerading như một
   bước tiếp; debate chuyển quan hệ sang UNC2452 → C2 masquerading. Đây là
   cách thể hiện chủ thể sát nguồn hơn; không chứng minh mọi hoạt động khác
   trong graph đã được nối đúng.
4. **Cleanup:** P032 nêu việc thường xuyên gỡ tools/backdoors sau khi đạt
   legitimate remote access. Node cleanup của debate có căn cứ mô tả này.
5. **Phạm vi TEARDROP:** P012 nói nhiều sample có các payload khác nhau và
   TEARDROP được triển khai ít nhất một trường hợp; câu tiếp theo giữ “We
   believe” khi nói customized BEACON. Nhãn được sửa để giữ các giới hạn đó.

## Còn cần duyệt, không tự coi debate là đúng

- **Config field:** P006 nói reconnaissance được lưu trong plugin config;
  P044 nói danh sách service bị dừng được bit-pack vào `ReportWatcherPostpone`.
  Cạnh debate đang nói cả reconnaissance lẫn stopped services đều nằm trong
  riêng khóa đó. Hai phát biểu có quote khớp chữ vẫn chưa đủ để chứng minh
  cách gộp này. Cần tách hoặc diễn đạt thận trọng hơn nếu đưa vào graph đã duyệt.
- **Jobs → TEARDROP:** debate đã thêm “at least one instance” nhưng vẫn nối
  từ node gộp steganographic jobs sang TEARDROP. P012 nói các SUNBURST sample
  deliver payload và actor deploy TEARDROP; không mô tả rõ job/dispatch node
  này là cầu nối cụ thể. Cần xem lại endpoint hoặc mức trừu tượng của cạnh.
- **Coverage:** Figure 2 có các nhánh detection signatures, MITRE ATT&CK,
  mitigation và malware analysis. Graph hiện tại tập trung vào luồng tấn
  công và evasion, chưa tái hiện đủ mọi nhánh đó. Có coi chúng là thiếu hay
  nằm ngoài phạm vi phải được chốt trong rubric trước khi chấm.
- **Node gộp:** `steganography_jobs`, `credential_abuse` và
  `initial_dormant_period` vẫn gộp nhiều hành vi/điều kiện. Số node/edge không
  đo được độ đầy đủ hoặc độ đúng của tất cả chi tiết bên trong.

Các ghi chú này giải thích vì sao cần chấm độc lập cả nội dung cạnh lẫn
source coverage; không thể đổi số quote đúng hoặc số node tăng thành accuracy.
