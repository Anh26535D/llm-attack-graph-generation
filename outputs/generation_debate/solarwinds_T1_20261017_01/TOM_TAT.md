# SolarWinds trong bài gốc — pilot multi-agent

Đã chạy **T1: toàn bộ báo cáo SolarWinds ở Appendix C.1, input của Figure 2**.
Không dùng dữ liệu C2 tự biên, không cho trước danh sách node/cạnh, không ép
graph đạt số lượng nào. Baseline nhận đúng prompt đã trích và chuẩn hóa từ
PDF, kiểm bằng hash `2a84c0a9579144a58d2cd1e0b6085bda1ac9d05190593776f50fd8809d8842af`.

Model cho mọi vai trò là Gemini `gemini-3.8-flash`, khác GPT-4 trong bài.
Đây là tái hiện input/phương pháp với model hiện tại, không phải tái tạo
đúng từng node/cạnh của hình paper. Figure 2 gốc giữ riêng để tham khảo.

| Cách sinh | Node | Cạnh | Cặp cạnh thêm/bỏ so baseline | Token provider gồm reasoning |
|---|---:|---:|---|---:|
| Baseline: một lần theo prompt bài | 19 | 19 | 0 / 0 | 7.324 |
| Single-agent tự sửa ba lượt | 20 | 20 | 7 / 6 | 74.152 |
| Multi-agent debate rồi tổng hợp | 23 | 23 | 9 / 5 | 65.171 |

Debate còn sửa nội dung sáu cặp cạnh được giữ. Các cặp thêm/bỏ tính theo ID;
không mặc định mỗi cặp thêm là đúng hoặc mỗi cặp bỏ là sai. Không có node
cũ bị bỏ trong lượt này. Ba nhánh dùng cùng graph baseline và cùng nguồn.

**Debate có thay đổi nội dung cụ thể để người đọc đối chiếu nguồn:**

- Bổ sung bốn node: kiểm tra kết nối `api.solarwinds.com`, nhánh dừng khi IP
  thuộc blocklist, lưu thông tin trong config, và gỡ tool/backdoor sau khi
  có truy cập hợp lệ.
- Đổi nhánh cấu hình C2 giả danh từ đầu ra của BEACON thành kỹ thuật của
  UNC2452, phù hợp chủ thể được mô tả ở P018/P024.
- Giữ phạm vi “ít nhất một trường hợp” và sắc thái “tin rằng” cho tuyến
  TEARDROP → BEACON thay vì trình bày như bước luôn xảy ra.

**Chưa thể kết luận accuracy tăng.** Trích dẫn đúng chữ không chứng minh
quan hệ đúng. [Các điểm vẫn cần kiểm tra](SOURCE_INSPECTION.md) gồm gán
reconnaissance vào riêng khóa `ReportWatcherPostpone`, cầu nối Jobs → TEARDROP,
và coverage các nhánh detection/mitigation/MITRE. Chưa có người chấm độc lập:
accuracy, precision, recall, F1 đều N/A.

- [Ảnh debate có nhãn đầy đủ](analysis/paper_style/r01_debate/graph.png)
- [Ảnh baseline có nhãn đầy đủ](analysis/paper_style/r01_single/graph.png)
- [Ba graph cùng vị trí node](analysis/r01_comparison.png)
- [Bản xem tương tác và bảng chi tiết](analysis/index.html)
- [Report so sánh và trích dẫn thay đổi](analysis/COMPARISON.md)
- [Hình Figure 2 trong bài gốc](paper_references/figure_02.png)

Các vai trò đều là cùng model với prompt riêng. Defender và Skeptic nhận
cùng draft, không xem phản hồi hiện tại của nhau. Editor có đầy đủ báo cáo
để xem lại. Một reviewer dùng một quote không khớp nguyên văn; quote đó được
đánh dấu và giữ khỏi phần bằng chứng gửi editor. Hai review chọn lọc, không
audit mọi cạnh. 21 bản ghi thay đổi cuối có ít nhất một quote khớp văn bản;
đây là kiểm tra nguồn trích dẫn, không phải 21 quyết định được chứng minh đúng.

Tự sửa và debate mỗi nhánh bốn calls tính cả draft; cùng cap 32.768 token,
reasoning medium. Cùng calls/cap không có nghĩa cùng input length/chi phí.
Pilot gồm **bảy request riêng biệt, 131.999 token**; draft chỉ thực hiện một
lần, nên không cộng trực tiếp ba hàng token trong bảng. Không có truncation
hay API retry. JSON được chấp nhận một lớp Markdown fence từ trước khi chạy;
raw giữ nguyên. Không có dữ liệu số tiền chi phí từ provider.

Một pilot chưa đo ổn định. Nếu tiếp tục đo chính thức, chốt rubric source
coverage/entailment trước, tạo run mới 10 repeat T1 với cùng cấu hình, chấm
theo từng cặp graph và giữ cả lỗi. Không dùng validator tám CVE cho graph này.
T2 là case khác (Appendix C.2 / Figure 8), chưa gọi API trong lượt này.

Code đã kiểm bằng **251 tests pass**, tests không gọi API. Input, raw
response và baseline được kiểm hash không thay đổi; code snapshot lưu cùng run.
