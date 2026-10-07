# E1 — độ nhạy của graph do LLM sinh với thay đổi môi trường

Thí nghiệm phụ, tách khỏi bộ tái hiện §5.1–5.4. Không gọi API; chỉ sinh prompt và chấm response bạn tự thu thập.

## Giả thuyết (H5)

Graph do LLM sinh cho một hệ thống gần như **không nhạy** với thay đổi môi trường: sau khi vá hoặc đổi cấu hình, nó vẫn giữ các CVE/cạnh đã bị vô hiệu hóa.

## Cách đo

1. `envs.py` dựng 3 môi trường nhỏ với trạng thái S đã biết đầy đủ (host, phiên bản, cờ cấu hình, kết nối mạng, vị trí kẻ tấn công) và 10 can thiệp có kiểm soát (vá, đổi mật khẩu, chặn link, ...).
2. `engine.py` là engine tham chiếu (forward chaining, cỡ MulVAL thu nhỏ): cho biết cặp (CVE, host) nào **được kích hoạt** trong S, dựa trên `conditions.py`.
3. `conditions.py` viết điều kiện của 8 CVE **từ mô tả CVE** (có trích nguồn). Chỗ nguồn mơ hồ thì để rộng và ghi `note`.
4. `prompts.py` dùng nguyên `CVE_CONTEXT_PROMPT` của CrystalBall, thêm mô tả hệ thống đích và cả 8 CVE (kèm ID). Hai biến thể:
   - `plain`: đúng prompt của CrystalBall (không yêu cầu lọc theo hệ thống);
   - `env_aware`: thêm một câu yêu cầu chỉ giữ lỗ hổng khai thác được trên hệ thống đã mô tả.
5. `scoring.py` ánh xạ node → CVE bằng ID xuất hiện trong node, rồi tính:
   - **retention_rate:** tỷ lệ CVE bị vô hiệu hóa sau can thiệp nhưng vẫn có trong graph (càng cao càng tệ);
   - **retention_rate_direct:** như trên nhưng chỉ tính CVE bị chặn trực tiếp bởi thay đổi (lỗi hiểu phiên bản/cấu hình), tách khỏi CVE chỉ mất đường vào (lỗi suy luận chuỗi);
   - **retention_rate_active:** bỏ các node có từ phủ định ("patched", "not exploitable", ...);
   - **collateral_rate:** CVE vẫn khai thác được nhưng biến mất khỏi graph;
   - **precision/recall** ở trạng thái gốc, và phân loại cạnh `supported / redundant / unsupported / unevaluable`.

## Ngưỡng đi/dừng (đặt trước khi có dữ liệu)

Áp dụng cho `mean_retention_rate` gộp theo (model, variant):

| Kết quả | Kết luận |
|---|---|
| ≥ 0,30 | **GO** — H5 có dấu hiệu đúng (chỉ là tín hiệu, xem giới hạn) |
| < 0,10 | **STOP** — H5 yếu, LLM đã nhạy với môi trường |
| giữa hai ngưỡng | Chưa kết luận |

Không đổi ngưỡng sau khi thấy kết quả. Nếu muốn đổi, ghi lại lý do và coi đó là phân tích khám phá.

## Chạy

```bash
uv sync --locked --extra dev
uv run --no-sync python -m experiments.env_consistency.run emit --run-id e1_pilot
# Bản nhỏ nhất (12 prompt/lần lặp): --envs vr signage --variants env_aware
```

Lệnh `emit` ghi `outputs/experiments/<run-id>/prompts/<case>.txt` và `cases.json` (trạng thái mong đợi cho từng case). Tạo response bằng cách bạn chọn (dán vào giao diện chat hoặc API) và lưu:

```
<responses>/<tên_model>/<case_id>.r01.txt      # r02, r03... cho các lần lặp
```

```bash
uv run --no-sync python -m experiments.env_consistency.run score --run-id e1_pilot --responses <responses>
```

Kết quả: `metrics.csv` (từng graph) và `summary.json` (gộp theo model/variant, kèm verdict). Dùng cùng model và cấu hình cho `base` và các can thiệp của một môi trường, và ghi lại model, ngày, tham số sinh.

## Giới hạn — đọc trước khi dùng số liệu

- **Đây là kiểm tra nhất quán, không phải đúng thật.** Engine chỉ mã hóa điều kiện đã nêu trong mô tả CVE. Backport, cấu hình ẩn, PoC chập chờn nằm ngoài. Gọi kết quả là "nhất quán với môi trường", không gọi là "chính xác".
- **Điều kiện do người viết, chưa có chuyên gia duyệt.** Mỗi điều kiện kèm đoạn nguồn và ghi chú; cần người thứ hai rà `conditions.py` trước khi trích số liệu. Một số lựa chọn có tính diễn giải (ví dụ "gain privileges" = admin; "potentially execute code" = user).
- **Engine không biết chuỗi leo thang quyền vô nghĩa.** Cạnh giữa hai CVE leo thang cục bộ có thể được xếp `supported` dù cạnh đó không có ý nghĩa thực tế.
- **Ánh xạ node → CVE dựa vào ID trong văn bản.** Node không nêu ID sẽ không được tính. Prompt có ghi ID để giảm tình huống này, nhưng đó là khác biệt so với prompt gốc của CrystalBall.
- **Bộ lọc phủ định bằng từ khóa chỉ là tín hiệu thô.** Đọc lại vài graph có `retention_rate_active` khác `retention_rate`.
- **Mẫu nhỏ.** 3 môi trường, 8 CVE, mỗi môi trường chỉ 3–4 can thiệp; kết quả chỉ là tín hiệu sơ bộ, không phải ước lượng thống kê tin cậy. Báo cáo kèm số lần lặp và khoảng biến thiên.
- **Môi trường tự dựng sạch hơn thực tế.**
- **Kết quả với model này không suy rộng sang model khác** và không so trực tiếp với run `20260927_full_reproduction`.
