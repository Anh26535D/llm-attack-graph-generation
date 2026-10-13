# Kiểm tra bộ chín ảnh

Đủ chín trường hợp, ba model; prompt C2/T0 giống nhau trong từng nhóm, reasoning high/cap 16.384. Hash prompt/response khớp; graph đầy đủ giữ nguyên dữ liệu đã parse. Tất cả response kết thúc STOP, không repair JSON; không còn chồng nhãn theo kiểm tra renderer, khung nhãn nằm trong SVG.

| Figure | Kịch bản | Backend | Graph đầy đủ node/edge | Prompt | Ảnh hiển thị |
|---|---|---|---|---|---|
| 2 | T1 | gemini | 19/21 | presentation | full graph |
| 6 | C0 | gemini | 11/11 | presentation | full graph |
| 7 | C2 | gemini | 8/7 | paper | full graph |
| 8 | T2 | gemini | 26/30 | paper | full graph |
| 9 | C2 | openrouter | 8/3 | paper | full graph |
| 10 | C2 | openrouter_v2 | 8/4 | paper | full graph |
| 11 | T0 | gemini | 10/11 | paper | full graph |
| 12 | T0 | openrouter | 17/20 | paper | full graph |
| 13 | T0 | openrouter_v2 | 15/18 | paper | editorial overview 4/2; full graph retained |

Đã xem riêng cả chín ảnh và trang bài gốc. Node tròn, tên node/edge hiện trong ảnh; mức độ lớn và phân nhánh được giữ theo response. Cấu trúc khác hình lịch sử vì dùng mô hình thay thế. Figure 13 dùng bản gom nhóm biên tập 4/2, có ánh xạ source_nodes/source_edges; output DeepSeek vẫn là 15/18.

Figure 2/6 dùng prompt presentation có bổ sung yêu cầu tổng quan; các hình còn lại dùng paper. Bộ này được chọn sau khi xem ảnh để minh họa, không dùng như mẫu ngẫu nhiên để xếp hạng. Nhãn CVE và kỹ thuật có tên hiển thị ngắn, label nguyên bản giữ trong JSON/render.json.

Đã gửi tổng cộng 18 request generation để thử hai biến thể; các lần giãn nhãn/đổi bố cục sau đó chỉ render lại, không gọi API. Kiểm tra UI: chọn node/nhãn cạnh mở JSON, tìm kiếm và phóng to hoạt động. Chưa đánh giá đúng ngữ nghĩa mọi path; một repeat không đủ kết luận thống kê.

Bằng chứng kiểm tra: [quality_review.json](quality_review.json). Mỗi hình có prompt.txt, response.txt, metadata.json, graph.json/png/svg/html, render.json và comparison.html.
