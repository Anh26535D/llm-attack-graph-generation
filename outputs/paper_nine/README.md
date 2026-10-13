# Kết quả chín attack graph

Ba bộ dưới đây được lưu trong Git, gồm ảnh, graph JSON, prompt, raw response, metadata và trang HTML. Có thể mở `index.html` trực tiếp sau khi clone, không cần gọi API để xem kết quả.

| Bộ | Nội dung |
|---|---|
| [paper9_20261013_reviewed](paper9_20261013_reviewed/index.html) | Bộ tuyển chọn đã kiểm tra để demo/báo cáo/slide. Figure 2/6 dùng prompt presentation; các hình còn lại dùng paper. Figure 13 có overview biên tập 4 node/2 edge, graph DeepSeek đầy đủ 15/18 được giữ riêng. |
| [paper9_20261013_original](paper9_20261013_original/index.html) | Chín response đợt đầu từ prompt nguyên bản, reasoning high, ba model thay thế. |
| [20261013T142243458365Z](20261013T142243458365Z/index.html) | Lần chạy mới ngày 13/10/2026, đủ chín response với prompt paper. Không thay thế bộ reviewed. |

Trong mỗi run: `figures/figure_NN_r01/graph.png` dùng cho slide; SVG để phóng to; HTML để xem tương tác; `comparison.html` để so riêng với hình gốc. Giữ `prompt.txt`, `response.txt`, `graph.json`, `metadata.json`, `render.json` và `manifest.json` làm bằng chứng. `references/` chứa ảnh trích từ bài gốc, không phải output của mô hình thay thế.

C2 (Figure 7/9/10) và T0 (Figure 11/12/13) dùng cùng prompt trong từng nhóm ba model. Đây là minh họa một repeat, không đủ để xếp hạng thống kê. Reviewed được tuyển chọn sau khi xem ảnh, có điều chỉnh tên hiển thị/bố cục và ghi rõ bản gom nhóm; không phải tái tạo chính xác output của GPT-4/GPT-3.5/Bard lịch sử.

Các đường dẫn tuyệt đối trong metadata/quality review là ghi chép nguồn trên máy chạy. Toàn bộ prompt/response được chọn đã có bản sao trong chính từng run, nên xem HTML không phụ thuộc các đường dẫn đó. `source_locations.json` chỉ hỗ trợ tra nguồn archive trên máy gốc; archive không nằm trong Git.

`.gitignore` chỉ cho phép ba bộ đã hoàn thành này và README. Các lần chạy mới vẫn được ignore cho tới khi chủ động chọn lưu kết quả.
