# Demo và thí nghiệm CrystalBall với ba mô hình

Cập nhật ngày 13/10/2026. Phạm vi hiện tại là tái hiện phương pháp và các kịch bản của bài báo bằng **ba mô hình độc lập**: Gemini, GPT-5.6 Luna và DeepSeek. DeepSeek là mô hình bổ sung cho so sánh; không phải phiên bản mới của dự án.

## 1. Ba mô hình và cấu hình

| Mô hình | Backend CLI | Biến môi trường |
|---|---|---|
| Gemini `gemini-3.8-flash` | `gemini` | `GEMINI_API_KEY`, `GEMINI_MODEL` |
| GPT-5.6 Luna `openai/gpt-5.6-luna` | `openrouter` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |
| DeepSeek `deepseek/deepseek-v4.1-flash` | `openrouter_v2` | `OPENROUTER_API_KEY_V2`, `OPENROUTER_MODEL_V2`, `OPENROUTER_PROVIDER_CONFIG_V2` |

Tên `openrouter_v2` và hậu tố `_V2` được giữ để dùng cấu hình OpenRouter thứ hai đã có. Khi viết báo cáo và slide, dùng tên **DeepSeek** hoặc **mô hình thứ ba**. Đây là ba mô hình qua hai dịch vụ API: Gemini và OpenRouter. Model ID phải còn truy cập được bằng tài khoản tại thời điểm chạy.

Cấu hình DeepSeek chỉ cần ba biến đã thống nhất:

```dotenv
OPENROUTER_API_KEY_V2=YOUR_API_KEY
OPENROUTER_MODEL_V2=deepseek/deepseek-v4.1-flash
OPENROUTER_PROVIDER_CONFIG_V2='{"only":["baidu/fp8"],"allow_fallbacks":false}'
```

Muốn đổi nhà cung cấp, sửa slug trong `only`; muốn đổi mô hình, sửa `OPENROUTER_MODEL_V2`. JSON này được gửi vào trường `provider` của request OpenRouter. Với `allow_fallbacks=false`, request không chuyển sang nhà cung cấp khác khi nhà cung cấp đã chọn không đáp ứng được. Không cần thêm biến giá hoặc biến reasoning. DeepSeek dùng `high` cố định tại `OPENROUTER_V2_REASONING_LEVEL` trong `src/crystalball/config.py`.

## 2. Code và kết quả hiện có

| Thành phần | Tình trạng |
|---|---|
| Client, chọn backend, cấu hình provider | Đã hỗ trợ cả ba mô hình |
| Demo `scripts/demo_online.py` / `demo_online.bat` | Đã hỗ trợ chọn từng mô hình, lưu output riêng mỗi lần |
| Kiểm tra DeepSeek không gọi API | Đã tạo prompt và metadata thành công; chưa xác nhận inference/quota ở máy chủ |
| Run `20260927_full_reproduction` | 130 response của Gemini và Luna; chưa có kết quả DeepSeek |
| Batch `scripts/run_paired_experiment.py` | `MODEL_SPECS` và kiểm tra cấu hình còn giới hạn Gemini/Luna |
| Gallery `scripts/export_paper_demo.py` | Đang xuất kết quả của hai mô hình từ run lịch sử |

**Thêm biến môi trường đã đủ để chọn DeepSeek trong demo, nhưng chưa đủ để batch tự chạy ba mô hình.** Không đổi nhãn 130 response cũ thành kết quả ba mô hình.

## 3. Demo đơn giản: cùng Appendix B qua ba mô hình

Chạy từ thư mục repo đã cài dependency và có `.env`. Appendix B là T0, dùng nguyên prompt bài báo, không cần index Contriever để tạo prompt.

Kiểm tra cả ba cấu hình trước buổi demo, không gửi request LLM:

```powershell
foreach ($modelBackend in @('gemini', 'openrouter', 'openrouter_v2')) {
    uv run --no-sync python scripts/demo_online.py --backend $modelBackend --report --reasoning high --check --no-open
    if ($LASTEXITCODE -ne 0) { break }
}
```

Đã kiểm tra local ngày 13/10/2026: cả ba lệnh đều trả `CHECK OK`, cùng prompt SHA-256, reasoning `high` và cap 16.384 token. Các run chỉ có trạng thái `prepared`, chưa gửi request hoặc tạo response/graph.

Khi cần sinh ba graph mới, chạy vòng lặp này. Mỗi mô hình nhận một request; đây là **một repeat minh họa**, chưa phải bộ thí nghiệm năm repeat:

```powershell
foreach ($modelBackend in @('gemini', 'openrouter', 'openrouter_v2')) {
    uv run --no-sync python scripts/demo_online.py --backend $modelBackend --report --reasoning high --no-open
    if ($LASTEXITCODE -ne 0) { break }
}
```

Mỗi lần chạy in đường dẫn `outputs/demo_online/<timestamp>/`. Mở `graph.html` để trình bày; dùng `graph.svg`/`graph.png` cho slide và báo cáo. Giữ `prompt.txt`, `response.txt`, `metadata.json` để ghi đúng model, provider, reasoning, cap, cảnh báo và run. Ba lệnh này yêu cầu `high` cho cả ba mô hình và cùng cap mặc định 16.384 token; cùng tên reasoning không bảo đảm ba API dùng cùng lượng tính toán.

Để minh họa SolarWinds với prompt nguyên bản, thay `--report` bằng `--paper-prompt` (T1), hoặc `--evasion --paper-prompt` (T2). `--cve` là C1 truy hồi thực tế, không phải C2 giữ đủ tám description Appendix A. Demo hiện chưa có lựa chọn trực tiếp cho C0/C2.

## 4. Thiết kế thí nghiệm để đối chiếu bài gốc

Bài gốc so sánh GPT-4/GPT-3.5/Bard ở hai nhóm **C2** (Figure 7/9/10) và **T0** (Figure 11/12/13). Nghiên cứu của nhóm dùng ba mô hình thay thế ở trên, không ánh xạ Gemini/Luna/DeepSeek thành các model gốc. Chín attack graph gốc tương ứng năm kịch bản C0, C2, T0, T1, T2.

Mục tiêu đợt tiếp theo: **cùng năm kịch bản × ba mô hình × năm repeat = 75 response generation**. Năm repeat là thiết kế của repo; không gọi đó là số lần lặp do bài gốc quy định.

| Kịch bản | Nguồn prompt đã có | Số response với ba mô hình, năm repeat |
|---|---|---:|
| C0 — không CVE context | Prompt no-context ở `build_conditions()` và prompt đã freeze | 15 |
| C2 — đủ tám CVE | `data/reproduction/appendix_a_context.txt` | 15 |
| T0 — PostgreSQL/container | `data/reproduction/kubernetes_appendix_b.txt` | 15 |
| T1 — SolarWinds đầy đủ | `data/reproduction/solarwinds_full_appendix_c1.txt` | 15 |
| T2 — SolarWinds evasion | `data/reproduction/solarwinds_evasion_appendix_c2.txt` | 15 |
| **Tổng** | **Năm kịch bản trực tiếp liên quan chín hình** | **75** |

Nếu mở rộng cả C1 và X0, tổng điều kiện chính là **105 response**. Nếu chạy thêm toàn bộ workflow §5.4 của repo cho cả ba mô hình, thêm 90 response, tổng **195**. Các số này là kế hoạch, chưa phải kết quả đã chạy.

Run cũ đã có 50 response của hai mô hình trên năm kịch bản. Chạy bổ sung riêng DeepSeek cần 25 response; chỉ bổ sung hai nhóm so sánh C2/T0 cần 10. Tuy nhiên run cũ dùng reasoning `low`, DeepSeek hiện cố định `high`. Nếu dùng lại run cũ, phải ghi rõ khác biệt này và phân tích theo cấu hình; không coi đó là thí nghiệm chỉ thay mỗi model. Với đợt mới, chốt prompt/hash, cap và reasoning trước khi chạy; có thể yêu cầu `high` cho cả ba mô hình như demo ở trên.

## 5. Những phần code còn cần bổ sung cho batch

1. Mở rộng danh sách mô hình và kiểm tra cấu hình trong `run_paired_experiment.py`; dùng client DeepSeek đã có và giữ nguyên prompt bytes của mỗi kịch bản giữa ba mô hình.
2. Cập nhật kế hoạch request, ID kết quả, manifest và bảng tổng hợp để lưu ba mô hình riêng biệt; chọn rõ scope năm kịch bản hay toàn bộ repo.
3. Sửa bộ tạo báo cáo còn ghi cứng kết luận T0 cũ; xuất báo cáo theo run, bảo vệ bản tổng hợp đã biên tập khỏi bị ghi đè.
4. Mở rộng exporter/gallery để đọc run mới và hiển thị ba mô hình, cùng repeat và cảnh báo. Giữ báo cáo số liệu hai mô hình của run cũ.

Không cần thêm dữ liệu hoặc prompt mới để bao phủ năm kịch bản này. Phần còn thiếu là điều phối và tổng hợp thí nghiệm ba mô hình. Các bước trên chưa được triển khai trong lần cập nhật tài liệu này.

## 6. Cách viết báo cáo và slide

Khi chưa chạy đủ bộ mới, ghi: “Dự án đã bổ sung DeepSeek làm mô hình thứ ba; kết quả định lượng hiện có thuộc run hai mô hình. Bộ thí nghiệm ba mô hình được thiết kế trên cùng năm kịch bản và năm lần lặp.”

Sau khi chạy và đánh giá đủ, ghi ba model ID, provider, cấu hình, run và số repeat thực tế. Minh họa C2 và T0 bằng ba graph cùng repeat; bổ sung C0, T1, T2 để bao phủ năm kịch bản. Giữ hình gốc với chú thích nguồn [1], và ghi riêng hình do nhóm tạo. Số node/edge mô tả kích thước, schema mô tả cấu trúc; đánh giá quan hệ tấn công phải đọc bằng chứng nguồn.

Xem [quy trình demo và slide](HUONG_DAN_DEMO_VA_TRINH_BAY.md), [đối chiếu chín graph](DOI_CHIEU_9_DO_THI_VA_PHAM_VI_TAI_HIEN.md), [báo cáo số liệu lịch sử](../REPRODUCTION_REPORT.md).
