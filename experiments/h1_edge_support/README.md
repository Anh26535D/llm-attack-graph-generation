# H1 — cạnh do LLM sinh có được nguồn hỗ trợ không?

Đo **tính bám nguồn** (mức 1), không đo khai thác được thật. "Nguồn" = chính các mô tả CVE trong prompt. Xem giới hạn ở cuối.

## Quy trình
1. `prepare` — prompt Appendix A (C2) của bài CrystalBall, chỉ thêm ID CVE trước mỗi mô tả (khác biệt duy nhất so với prompt gốc).
2. Sinh response bằng `experiments.env_consistency.generate` (ngoài repo này không gọi API).
3. `extract` — liệt kê cạnh CVE→CVE. Node nào không ghi ID CVE thì ánh xạ bằng từ khóa nhận diện trên *label* và chỉ nhận khi đúng một CVE khớp (bổ sung sau lần chạy đầu, vì một run bỏ hết ID).
4. Gán nhãn từng cặp có hướng trong `labels.json`, kèm bằng chứng trích từ mô tả CVE.
5. `score` — tính tỷ lệ.

## Tiêu chí nhãn (viết trước khi gán nhãn)
Chỉ xét văn bản của hai mô tả CVE; đánh giá *cơ chế* mà cạnh khẳng định (A cung cấp gì cho điều kiện tiên quyết của B).

- **supported:** hai mô tả cùng thiết lập được bước chuyển mà không cần dữ kiện nào không được nêu.
- **conditional:** nhất quán với văn bản và có ý nghĩa nếu có thêm một dữ kiện không được nêu (ví dụ cùng một thiết bị, file chứa credential).
- **unsupported:** văn bản không thiết lập mối liên hệ (khác sản phẩm/thiết bị, cơ chế không có trong nguồn), hoặc B đã khả thi mà không cần A nên cạnh không "làm B khả thi".
- **contradicted:** văn bản mâu thuẫn với cạnh.

Khi cùng một cặp xuất hiện với nhiều cơ chế khác nhau, chọn cách đọc **thuận lợi nhất cho LLM** (để ước lượng tỷ lệ không-hỗ-trợ ở mức thận trọng).

## Giả thuyết và ngưỡng (đặt trước)
H1: tỷ lệ cạnh không phải `supported` ≥ 0,30 và ổn định giữa các lần chạy thì **đi**; < 0,10 thì **dừng**.

## Giới hạn — đọc trước khi dùng số liệu
- **Sàn thấp của tiêu chí chính.** Mô tả CVE là độc lập, hầu như không bao giờ nêu mối quan hệ giữa hai lỗ hổng, nên `supported` gần như không thể xảy ra. Vì vậy "không-supported ≥ 0,30" gần như tự động đạt; chỉ số đáng nhìn hơn là tỷ lệ `unsupported` (cơ chế không có trong nguồn) so với `conditional`.
- **Một người gán nhãn (tôi), nhãn sơ bộ.** Chưa có người thứ hai nên chưa có độ đồng thuận (κ). Cần chuyên gia gán độc lập trước khi trích số liệu.
- **Nhãn được gán sau khi thấy cạnh.** Dù tiêu chí được viết trước, người gán đã biết cơ chế của LLM. Thêm phân tích độ nhạy với hai cặp ranh giới.
- **Mẫu rất nhỏ:** một model, 3 lần chạy, 24 cạnh, 15 cặp.
- **Chỉ đo mức 1.** Bám nguồn khác với đúng ngoài đời.
