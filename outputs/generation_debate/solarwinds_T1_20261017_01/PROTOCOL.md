# SolarWinds T1/T2: tái hiện input trong bài + debate

T1 = Figure 2 / Appendix C.1 full SolarWinds report. T2 = Figure 8 / Appendix C.2 evasion excerpt.
Baseline gọi đúng prompt trích từ bài (hash khóa trong data/reproduction/manifest.json).
Không có dữ liệu mô phỏng, host giả, node/cạnh cho trước hoặc ép số lượng.
Tái hiện nguồn và phương pháp, không cam kết ảnh giống GPT-4 trong bài vì model/lần sinh khác.

Ba nhánh: single = draft gốc; self_refine = ba lượt tự sửa; debate = bảo vệ + phản biện + tổng hợp.
Cùng draft, nguồn, model và output cap; refinement/debate cùng bốn calls gồm draft.
Một repeat dùng bảy calls riêng biệt. Cùng calls/output cap không có nghĩa cùng chi phí/token thực tế.
Hai reviewer không xem câu trả lời hiện tại của nhau; judge xem đầy đủ nguồn.
Review chọn tối đa 12 findings + 6 omissions, không phải kiểm tra toàn bộ cạnh.
Chỉ kiểm quote là substring nguyên văn đúng paragraph; không coi quote/đồng thuận là semantic gold.
JSON được bóc tối đa một whole-response Markdown fence ở mọi stage, không sửa/truncation recovery.
Giữ raw, usage và journal trước/sau; không tự retry request lỗi/chưa rõ kết quả.

Không dùng validator tám CVE cho graph threat-report. Không lấy Figure 2 làm nhãn đầy đủ tuyệt đối.
Đánh giá tự động: parse/schema, kích thước, coverage mô tả, thay đổi ID/pairs, quote xác thực, usage/latency.
Precision/recall/F1 accuracy để N/A khi chưa có người chấm độc lập. Nhãn trống không tự điền bằng LLM.
Node discovery và ngữ nghĩa cạnh cần chấm source-grounded, gồm cả nội dung bị mọi graph bỏ sót.
Đảo thứ tự reviewer qua repeat; chưa loại hết self-preference/verbosity/model biases.
Không sửa nguồn/prompt sau khi xem kết quả để ép debate thắng. Lỗi/partial vẫn báo cáo.
