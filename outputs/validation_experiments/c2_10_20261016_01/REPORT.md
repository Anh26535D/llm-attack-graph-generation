# Kết quả pilot validation C2

Đã parse 10/10 graph; hybrid hoàn tất 1/10.

Mỗi repeat dùng đúng prompt đã freeze, cùng model/config. Original giữ nguyên byte; before/after cùng renderer/layout.

**Chưa có gold độc lập: precision/recall/F1 = N/A, không báo phần trăm accuracy.**

| Repeat | Nodes | Edges | CVE coverage | Offline C/U | Hybrid C/U | B→C đổi nhãn |
|---|---:|---:|---:|---|---|---:|
| 01 | 9 | 5 | 88% | 3/2 | 3/2 | 0 |
| 02 | 8 | 5 | 100% | 4/1 | 4/1 | 0 |
| 03 | 8 | 7 | 100% | —/— | —/— | — |
| 04 | 8 | 5 | 100% | —/— | —/— | — |
| 05 | 11 | 10 | 100% | —/— | —/— | — |
| 06 | 8 | 5 | 75% | —/— | —/— | — |
| 07 | 8 | 5 | 88% | —/— | —/— | — |
| 08 | 8 | 5 | 88% | —/— | —/— | — |
| 09 | 8 | 5 | 100% | —/— | —/— | — |
| 10 | 8 | 6 | 75% | —/— | —/— | — |

API calls: generation 10, review 10. Usage tính cả attempt lỗi, cache hit không tính token lịch sử.

C/U = conditional/unknown. Đây là distribution của validator, không phải nhãn chuẩn về đúng/sai.

Để chấm precision, dùng annotation_blind.json cho người đánh giá độc lập, chỉ gán true/false cho cạnh đã đủ căn cứ; bỏ qua cạnh chưa thể phân xử. Không dùng nhãn hybrid làm gold.

Xem PROTOCOL.md, metrics.csv và summary.json. Một case lặp nhiều lần chỉ đo biến thiên của case đó.
