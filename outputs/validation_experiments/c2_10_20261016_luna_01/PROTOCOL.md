# Thí nghiệm C2 lặp 10 lần: generation → offline → hybrid

Một prompt Appendix A cố định, cùng model và cấu hình trong mọi repeat. Không
ép graph phải có số node/cạnh cụ thể. Không chọn lại graph đẹp hoặc lớn nhất.
Mỗi response mới được lưu trước khi parse; lỗi, truncation và repair ghi riêng.
Không coi JSON parse được là graph đúng về ngữ nghĩa. SDK không tự retry.

A = toàn bộ graph sinh ra; B = kiểm tra offline; C = offline + selective LLM
review + deterministic recheck. B và C nhận cùng bằng chứng, không có quan sát
môi trường trong pilot này. Rule/policy hiện có được giữ nguyên. Original JSON
giữ nguyên byte; ảnh original/validated dùng cùng renderer, layout và edge IDs.
Cache chỉ trong repeat để resume không gọi lại các review đã thành công.
Mỗi review prompt và raw response đều được lưu để kiểm toán.

## Thang đo đã xác định trước khi gọi API

Chỉ số chính nếu có nhãn độc lập là candidate-edge precision:
100 × số cạnh đúng được giữ / số cạnh được giữ đã gán nhãn. Báo cáo kèm
candidate recall, F1, số cạnh đúng bị loại nhầm và số cạnh sai còn giữ.
Recall chỉ xét các cạnh đúng có trong graph gốc, không đo cạnh generator bỏ sót.
Policy retained chỉ bỏ unsupported/contradicted; strict chỉ giữ supported.
Unknown/conditional không được tự chuyển thành gold false.

Nhãn chuyên gia chưa có: các chỉ số precision/recall/F1 để null (N/A), không
lấy nhãn offline, LLM review hoặc nhãn AI tự tạo thay gold độc lập. Có thể gán
nhãn bằng annotation_blind.json, lưu riêng gold/rNN.json theo schema hiện có.
Không thay đổi annotation sau khi xem quyết định của validator.

Khi chưa có gold vẫn đo được: tỷ lệ parse/schema thành công, coverage 8 CVE,
số node/cạnh, conditional/unknown/negative rates, retained/strict fractions,
thay đổi nhãn B→C, review completion/disagreement, latency và usage thực tế.
Các tỷ lệ trạng thái là mô tả hành vi, không phải điểm accuracy.

Tổng hợp từng repeat và mean/min/max; đơn vị lặp là graph, không xem các cạnh
trong cùng graph là các quan sát độc lập. Pilot cùng một prompt không đại diện
cho mọi case/project, không xác nhận exploit thực tế. 10 repeat chưa dùng để
xếp hạng model. Chi phí tiền chỉ báo khi provider trả số liệu, không ước giá.

## Lượt review mới theo .env

Tái sử dụng nguyên byte 10 graph từ `D:\AHUST\An ninh mạng\llm-attack-graph-generation\outputs\validation_experiments\c2_10_20261016_01`; không gọi lại generation. Reviewer openai/gpt-5.6-luna, reasoning high, output cap 9999, tối đa 10 calls/repeat. Nhãn review cũ không được nhập vào lượt mới. API usage của lượt mới tách khỏi chi phí generation/lượt review trước. Không có dữ liệu môi trường host/version/reachability mới.
