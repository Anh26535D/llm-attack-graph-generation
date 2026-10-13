# Các output cần dùng

Dọn ngày 13/10/2026. Git lưu kết quả trong [paper_nine](paper_nine/README.md) và [demo_presentation](demo_presentation/README.md). Các bản trung gian/đường dẫn archive dưới đây là ghi chép trên máy chạy, không kèm trong bản clone.

## Giữ ở phần đang dùng

| Thư mục | Dùng khi nào |
|---|---|
| [paper_nine/paper9_20261013_reviewed](paper_nine/paper9_20261013_reviewed/index.html) | Bộ chín hình cuối đã chọn và kiểm tra để demo/báo cáo/slide. Figure 2/6 dùng prompt presentation; Figure 13 có overview biên tập và graph đầy đủ riêng. |
| [paper_nine/paper9_20261013_original](paper_nine/paper9_20261013_original/index.html) | Chín response đợt đầu từ prompt nguyên bản. Giữ làm bằng chứng và để so với bộ tuyển chọn. |
| [paper_nine/20261013T142243458365Z](paper_nine/20261013T142243458365Z/index.html) | Run mới bạn chạy ngày 13/10, đủ chín response; giữ để đối chiếu lần chạy mới. Chưa được tuyển chọn/kiểm tra ảnh như reviewed. |
| experiments/20260927_full_reproduction (artifact lịch sử trên máy chạy) | Bằng chứng 130 response và đánh giá của báo cáo lịch sử. Không kèm trong bản clone; không trộn số liệu với demo chín hình. |
| demo_presentation | Hai sơ đồ `luong_he_thong` và `luong_tao_anh`, PNG/SVG để dùng trong slide. |
| graphs, prompts (chế độ pipeline thủ công) | Thư mục đích cho chế độ chạy thủ công, không cần để xem bộ chín hình đã lưu. |

Chỉ mở `paper_nine/paper9_20261013_reviewed/index.html` nếu mục tiêu là trình bày bộ cuối.

## Trong mỗi bộ chín hình, giữ file nào?

Giữ nguyên toàn bộ thư mục của run để liên kết tương tác và bằng chứng không bị thiếu.

| File/thư mục | Vai trò |
|---|---|
| index.html | Trang mở đầu, danh sách tất cả hình. |
| figures/figure_NN_r01/graph.png | Ảnh để chèn vào báo cáo và slide. |
| graph.svg | Ảnh vector để phóng to/in, sửa cách trình bày khi cần. |
| graph.html | Demo tương tác: tìm kiếm, zoom, chọn node/cạnh để đọc JSON. |
| comparison.html | So từng ảnh với đúng Figure của bài gốc. |
| graph.json | Dữ liệu node/edge đã parse từ response; để vẽ lại. |
| prompt.txt, response.txt | Đầu vào và output LLM thật; cần giữ để giải thích/tái kiểm tra. |
| metadata.json | Model, reasoning, cap, trạng thái, usage, hash và nguồn. |
| render.json | Tên gốc/tên hiển thị, seed/bố cục và kiểm tra chồng nhãn. |
| references/ | Ảnh gốc tách từ PDF và manifest nguồn; trang so sánh sử dụng chúng. |
| overview/ ở Figure 13 | Ảnh tổng quan gom nhóm; `mapping.json` giải thích ánh xạ về graph đầy đủ. |
| manifest.json | Danh sách trường hợp, runner dùng để resume/render-only. |
| quality_review.md/json | Kiểm tra kỹ thuật và giới hạn của bộ reviewed. |
| source_locations.json | Đường dẫn nguồn hiện tại sau khi chuyển các bản thử vào archive; metadata lịch sử giữ nguyên. |

Nếu chỉ cần gửi ảnh cho người làm slide, sao chép chín PNG (Figure 13 chọn bản đầy đủ hoặc overview và ghi đúng chú thích). Bản master ở đây vẫn giữ đủ prompt/response/metadata.

## Đã đưa vào archive

- `paper_nine/paper9_20261013_presentation` và `presentation_f02`: thử prompt/bố cục trước khi chọn reviewed; dữ liệu nguồn vẫn lưu để tra lại.
- Các run chỉ `prepared`/`--check`: chưa gọi API hoặc chưa có response, không phải bộ ảnh hoàn thành.
- `demo_online`: demo chi tiết, replay và preflight cũ.
- `paper_demo`: hai gallery từ bộ hai model lịch sử.
- Ba run `experiments` trước `20260927_full_reproduction`.
- `study`: DB/embedding/artifact thực hành offline; các file mẫu cũ của `graphs`/`prompts`.

Trên máy gốc, bảng archive nằm tại `archive/20261013_cleanup/README.md`, ánh xạ tại `archive_locations.json` và manifest hash tại `archive/20261013_cleanup/archive_manifest.json`. Tất cả file chuyển đi trong đợt dọn được kiểm tra hash trước/sau, không xóa file. Để phục hồi một mục, di chuyển từ archive về đường dẫn gốc ghi trong manifest, chỉ khi đường dẫn gốc chưa tồn tại. Các artifact archive không được đưa vào Git.
