# Kết luận thí nghiệm C2 lặp 10 lần

Mười response generation mới đã được sinh bằng Gemini `gemini-3.8-flash`,
reasoning medium, output cap 8192, cùng prompt Appendix A nguyên byte. Graph
có 8–11 node, 5–10 cạnh; tổng 58 edge instances. Không ép số node/cạnh và
không chọn bỏ repeat. Generation nằm ở run `c2_10_20261016_01` và được sao
chép byte-exact sang đây; lượt review này không gọi lại generation.

Validation dùng Gemini high, cap 9999 ở first pass. Sau khi người dùng tăng
giới hạn trong `.env`, chỉ các review lỗi được retry một lần với cap 16384;
review đã thành công được lấy từ cache. Các request có override được ghi rõ.
Code kiểm chứng và parser ngữ nghĩa không đổi giữa các repeat.

| Chỉ số | Kết quả | Cách hiểu |
|---|---:|---|
| Graph parse được | 10/10 | Thành công kỹ thuật, chưa xác nhận nội dung |
| Review qua parse/ID/quote recheck ở first pass | 49/58 = 84,5% | Không phải accuracy ngữ nghĩa |
| Review qua recheck sau một vòng retry | 57/58 = 98,3% | Còn một lỗi JSON bọc Markdown ở r01/edge-0002 |
| Cạnh đổi nhãn offline → hybrid | 0/58 | Hybrid chưa thay đổi quyết định cuối trong pilot này |
| Nhãn cuối | 35 conditional, 23 unknown | Thiếu bằng chứng/điều kiện, không đồng nghĩa mọi cạnh sai |
| Cạnh được giữ theo retained policy | 58/58 | Không có unsupported/contradicted được rule xác nhận |
| Cạnh trong strict graph | 0/58 | Không có supported; không chứng minh mọi attack path bất khả thi |
| Precision, recall, F1 | N/A | Chưa có gold độc lập |

First pass có 8 MAX_TOKENS và 1 STOP nhưng JSON bọc Markdown. Sau retry,
một review vẫn bọc Markdown nên parser strict từ chối; nhãn offline được giữ.
Không strip/repair để làm tăng chỉ số pass của bộ kiểm chứng đang đánh giá.

Trong 57 review qua recheck, LLM đề xuất 48 conditional, 5 unknown và
4 unsupported. Tổng 17 đề xuất khác baseline: 13 đề xuất conditional chưa
vượt được giới hạn bằng chứng offline, 4 đề xuất negative thiếu deterministic
evidence nên không được dùng để bác cạnh. Không có thay đổi nhãn cuối.

## Có thể kết luận gì?

Pipeline tạo và kiểm chứng graph đã chạy trên 10 repeat cùng case. Graph sinh
ra có biến thiên: trên các cặp CVE ánh xạ được có 8 topology khác nhau, Jaccard
trung bình giữa 45 cặp repeat khoảng 0,476. Chỉ số này không xét nội dung nhãn,
không bao gồm endpoint chưa mapping, và không đo độ đúng.

Hybrid bổ sung nhận xét và missing conditions, nhưng chưa thể hiện cải thiện
quyết định giữ/loại cạnh so với rule-only trong case này. Không có observations
độc lập về host/version/credentials/reachability; `.env` chỉ cấu hình API.
Policy hiện tại không cho phép ý kiến LLM tự nâng supported hoặc tự bác cạnh
khi chưa có rule/bằng chứng xác nhận. Vì vậy không diễn giải nhãn không đổi
thành “graph đã chính xác 100%” hoặc “LLM có accuracy 0%”.

## Thang chấm để có điểm 0–100

Chỉ số chính đề xuất: candidate-edge precision = 100 × số cạnh đúng được giữ
/ số cạnh được giữ đã được gán nhãn độc lập. Báo cáo đồng thời candidate recall,
F1, false removals, false retentions và độ phủ annotation. Recall chỉ tính các
candidate của original, không đo các quan hệ đúng generator đã bỏ sót.

Người đánh giá độc lập dùng `runs/rNN/annotation_blind.json` (58 candidates),
đọc claim và nguồn trước khi xem nhãn validator. Chỉ điền true/false cho cạnh
có đủ căn cứ phân xử, bỏ ID chưa rõ khỏi labels; không tự coi conditional hoặc
unknown là false. Lưu thành `gold/rNN.json` với provenance và graph hash khớp,
rồi chạy lại lệnh `report` để tính điểm hoàn toàn offline, không gọi thêm API.
Không dùng chính reviewer LLM hoặc rule của validator làm gold.

## Chi phí và tính bảo toàn

Lượt high này dùng 67 API requests = 58 first-pass + 9 retries. Provider báo
460.079 total tokens, gồm thinking và các request lỗi. Không cộng cache-hit
usage lịch sử vào usage hiện tại. Số này không gồm 10 generation trước đó
hoặc lượt low/4096 bị ngắt; không quy đổi thành tiền khi provider chưa trả cost.

`AUDIT.json` kiểm tra source graph, original copy, từng edge instance, layout,
baseline offline qua retry và ảnh. Các artifact ban đầu được giữ nguyên.
Code có 209 tests qua, bao gồm resume không gọi trùng, cấu hình fork-review,
retry cap mới chỉ áp dụng cho edge lỗi và không tự gán accuracy khi thiếu gold.

Xem `REPORT.md`, `metrics.csv`, `summary.json`, `manifest.json`,
`retry_profile_16384.json` và `runs/rNN/validation/call_journal/` để kiểm toán.
