# Kết quả pilot validation C2

Đã parse 10/10 graph; lưu 10 report validation; toàn bộ review qua recheck ở 8/10 graph.

Các review lỗi được phép retry với output cap 16384; reasoning giữ nguyên. Review đã thành công được tái sử dụng từ cache. First-pass metrics vẫn giữ các lỗi lần đầu.


Dùng lại 10 generation đã lưu từ `D:\AHUST\An ninh mạng\llm-attack-graph-generation\outputs\validation_experiments\c2_10_20261016_01`. Lượt này chỉ gọi validation; reviewer deepseek/deepseek-v4.1-flash, high, output cap 9999.


Mỗi repeat dùng đúng prompt đã freeze, cùng model/config. Original giữ nguyên byte; before/after cùng renderer/layout.

**Chưa có gold độc lập: precision/recall/F1 = N/A, không báo phần trăm accuracy.**

| Repeat | Nodes | Edges | CVE coverage | Offline C/U | Hybrid C/U | B→C đổi nhãn |
|---|---:|---:|---:|---|---|---:|
| 01 | 9 | 5 | 88% | 3/2 | 3/2 | 0 |
| 02 | 8 | 5 | 100% | 4/1 | 4/1 | 0 |
| 03 | 8 | 7 | 100% | 5/2 | 5/2 | 0 |
| 04 | 8 | 5 | 100% | 3/2 | 3/2 | 0 |
| 05 | 11 | 10 | 100% | 4/6 | 4/6 | 0 |
| 06 | 8 | 5 | 75% | 3/2 | 3/2 | 0 |
| 07 | 8 | 5 | 88% | 3/2 | 3/2 | 0 |
| 08 | 8 | 5 | 88% | 3/2 | 3/2 | 0 |
| 09 | 8 | 5 | 100% | 4/1 | 4/1 | 0 |
| 10 | 8 | 6 | 75% | 3/3 | 3/3 | 0 |

API calls: generation 0, review 65. Usage tính cả attempt lỗi, cache hit không tính token lịch sử.

First-pass review qua parse/identity/quote recheck: 50/58. Review lỗi giữ nhãn offline (fallback), không xem đó là kết quả semantic review hoàn tất.

Topology CVE được ánh xạ: 8 cấu trúc khác nhau. Jaccard trung bình giữa các cặp repeat: 0.4755026455026455. Chỉ đo ổn định các cặp CVE có mapping, không đo độ đúng và không xét nội dung claim.

C/U = conditional/unknown. Đây là distribution của validator, không phải nhãn chuẩn về đúng/sai.

Để chấm precision, dùng annotation_blind.json cho người đánh giá độc lập, chỉ gán true/false cho cạnh đã đủ căn cứ; bỏ qua cạnh chưa thể phân xử. Không dùng nhãn hybrid làm gold.

Xem PROTOCOL.md, metrics.csv và summary.json. Một case lặp nhiều lần chỉ đo biến thiên của case đó.
