# Gửi sang ChatGPT web để chấm SolarWinds

Không có API call mới. Gói chỉ dùng nguồn và graph đã lưu của pilot T1.

1. Giải nén UPLOAD_FILES.zip hoặc mở thư mục UPLOAD_THESE.
2. Mở cuộc trò chuyện mới; lần đầu CHỈ tải source_report.md, dán toàn bộ
   PROMPT_1_SOURCE.txt. Chờ model chốt checklist nguồn.
3. Cùng chat đó tải graph_A.json, graph_B.json, graph_C.json và dán toàn bộ
   PROMPT_2_GRAPHS.txt. Lưu đầy đủ kết quả chấm cạnh, coverage và tổng hợp.
4. Giữ tên A/B/C trong kết quả. Chỉ giải mã bằng PRIVATE_KEY_DO_NOT_UPLOAD.json
   SAU khi chấm xong. Không tải private key sang chat chấm.

Không gửi TOM_TAT.md, SOURCE_INSPECTION.md, changes/reviews/validator labels,
prompt generation/debate hay ảnh có tiêu đề phương pháp: chúng có thể neo
nhận xét. Không chỉ gửi ảnh để chấm ngữ nghĩa; JSON giữ đủ cạnh và label.
Nếu muốn chấm bố cục ảnh, làm bước riêng sau khi chấm nội dung xong.

Đây là prompt do project thiết kế. OpenAI Docs khuyến nghị rubric rõ,
so sánh theo cặp và lưu ý thiên lệch thứ tự/độ dài:
https://developers.openai.com/api/docs/guides/evaluation-best-practices

Để kiểm độ ổn định, có thể chấm lại trong chat mới với cùng source, checklist,
rubric và model/thiết lập, đổi thứ tự file trình bày C/B/A. Không giải mã tên
phương pháp trước khi chốt. So sánh bất đồng thay vì chọn lượt chấm thuận ý.
Ghi tên model và chế độ mà giao diện hiển thị, thời điểm, thứ tự file, mọi
prompt/lượt tiếp tục. Kết quả vẫn là AI judge, không thay thế người chấm độc lập.

Các nhãn ở prompt này là đánh giá ngữ nghĩa threat-report theo nguồn; không
phải output validator tám CVE và không chứng minh exploit trên hệ thống thật.
supported_rate và coverage do AI chấm không được đổi tên thành accuracy/recall.

Ba graph giữ nguyên byte. Chỉ ẩn tên phương pháp trong tên file; số lượng,
nội dung và độ hạt vẫn khác nhau, nên không đảm bảo loại hết mọi thiên lệch.
