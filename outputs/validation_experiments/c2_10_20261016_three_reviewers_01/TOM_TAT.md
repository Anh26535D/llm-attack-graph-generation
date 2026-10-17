# Kết quả ngắn gọn

Cùng 10 graph C2 đã sinh trước đó, tổng 58 cạnh. Gemini, DeepSeek qua CoreWeave và GPT-5.6 Luna dùng cùng graph, dữ liệu CVE và prompt review.

| Reviewer | Review qua kiểm tra | LLM: có điều kiện | LLM: chưa rõ | LLM: không được hỗ trợ |
|---|---:|---:|---:|---:|
| Gemini | 57/58 | 48 | 5 | 4 |
| DeepSeek / CoreWeave | 56/58 | 37 | 2 | 17 |
| GPT-5.6 Luna | 57/58 | 39 | 14 | 4 |

Đề xuất LLM chỉ tính những review qua kiểm tra định dạng, ID và trích dẫn. Review hợp lệ không đồng nghĩa cạnh đúng.

**Nhãn cuối của cả ba: 35 cạnh có điều kiện, 23 cạnh chưa đủ bằng chứng, 0 cạnh được xác nhận đầy đủ. Không model nào làm policy chấp nhận đổi nhãn so với offline.**

DeepSeek đề xuất nhiều cạnh không được hỗ trợ hơn (17 so với 4), nhưng policy hiện tại yêu cầu chứng cứ xác định trước khi chấp nhận nhãn âm. Không thể kết luận 17 cạnh đó thực sự sai hoặc DeepSeek chính xác hơn.

Lỗi còn lại: Gemini 1 review JSON bọc Markdown; GPT 1 review sai ID/trích dẫn; DeepSeek 1 review sai ID/trích dẫn và 1 review bị cắt rồi hết call budget của round 5. Các trường hợp này dùng fallback offline, không chấm là cạnh sai.

Cấu hình lần đầu: high, 9999 token cho cả ba. Chỉ review lỗi được thử lại một lần ở 16384 token. Gemini cho phép 20 call/round; hai lượt mới theo .env là 10. DeepSeek round 5 có 10 cạnh nên không còn lượt để retry. So sánh sau retry cần đọc kèm khác biệt này.

Chưa có nhãn độc lập để tính accuracy. Muốn đo độ đúng: chấm độc lập các cạnh trong annotation_blind.json, sau đó tính precision/recall/F1.

Provider hiện tại trong .env: `OPENROUTER_PROVIDER_CONFIG_V2='{"only":["coreweave/fp8"],"allow_fallbacks":false}'`; backend vẫn là `openrouter_v2`.

Xem COMPARISON.md cho số liệu lần đầu/sau retry; edge_comparison.csv cho từng cạnh; AUDIT.json kiểm tra tính nhất quán. Kết quả và chi phí Baidu bị dừng được giữ riêng, không trộn với lượt CoreWeave.
