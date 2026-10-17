# So sánh reviewer trên cùng graph C2

Cùng 10 graph C2, cùng edge instances, evidence, offline baseline, prompt review và layout. Không gọi lại generation.

| Model | First pass hợp lệ | Sau retry | LLM: supported / conditional / unsupported / contradicted / unknown | Nhãn cuối C/U | Đổi nhãn B→C | API calls |
|---|---:|---:|---|---|---:|---:|
| gemini-3.8-flash | 49/58 | 57/58 | 0 / 48 / 4 / 0 / 5 | 35/23 | 0 | 67 |
| deepseek/deepseek-v4.1-flash | 50/58 | 56/58 | 0 / 37 / 17 / 0 / 2 | 35/23 | 0 | 65 |
| openai/gpt-5.6-luna | 56/58 | 57/58 | 0 / 39 / 4 / 0 / 14 | 35/23 | 0 | 60 |

First pass hợp lệ / sau retry đo parse, identity và quote recheck, không đo độ đúng ngữ nghĩa. Phân bố đề xuất chỉ tính review qua recheck; tổng có thể thấp hơn 58. Nhãn cuối gồm fallback offline khi review lỗi.

Primary protocol giống nhau: True. Token cap/call budget từng model và usage thực tế nằm trong comparison.json. Tokenizers và lượng reasoning khác nhau nên cùng high không đồng nghĩa cùng compute.

Call budget mỗi round: gemini-3.8-flash: 20; deepseek/deepseek-v4.1-flash: 10; openai/gpt-5.6-luna: 10. Kết quả sau retry chịu giới hạn ngân sách từng round; đọc riêng kết quả lần đầu.

Chưa có gold độc lập: không kết luận model nào chính xác hơn. Xem edge_comparison.csv để đối chiếu từng cạnh.
