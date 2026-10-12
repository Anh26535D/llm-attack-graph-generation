"""Create two standalone process diagrams for a Vietnamese report or slide deck."""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parent
plt.rcParams.update({"font.family": "Arial", "svg.fonttype": "none"})
INK = "#173554"
MUTED = "#526980"
BLUE = "#e8f1fb"
TEAL = "#e5f4f0"
GOLD = "#fff2da"


def canvas(title, subtitle):
    fig, ax = plt.subplots(figsize=(16, 9), dpi=160)
    fig.patch.set_facecolor("white")
    ax.set(xlim=(0, 1), ylim=(0, 1))
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    ax.text(.045, .945, title, color=INK, fontsize=25, weight="bold", va="top")
    ax.text(.045, .893, subtitle, color=MUTED, fontsize=14, va="top")
    return fig, ax


def box(ax, x, y, w, h, title, body, fill=BLUE, title_size=15, body_size=12):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.006,rounding_size=0.014",
                               facecolor=fill, edgecolor="#b4c9db", linewidth=1.1))
    ax.text(x + w/2, y + h*.69, title, ha="center", va="center", fontsize=title_size,
            weight="bold", color=INK, linespacing=1.35)
    ax.text(x + w/2, y + h*.27, body, ha="center", va="center", fontsize=body_size,
            color=MUTED, linespacing=1.4)


def arrow(ax, points, color="#6486a6"):
    if len(points) > 2:
        ax.plot(*zip(*points[:-1]), color=color, linewidth=1.8, solid_capstyle="round")
    ax.add_patch(FancyArrowPatch(points[-2], points[-1], arrowstyle="-|>",
                                mutation_scale=16, color=color, linewidth=1.8,
                                shrinkA=0, shrinkB=2))


def save(fig, name):
    for suffix in ("png", "svg"):
        target = OUT / f"{name}.{suffix}"
        fig.savefig(target, dpi=160, facecolor="white")
        if suffix == "svg":
            target.write_text(
                "\n".join(line.rstrip() for line in target.read_text(encoding="utf-8").splitlines()) + "\n",
                encoding="utf-8",
            )
    plt.close(fig)


fig, ax = canvas("Luồng sinh attack graph của CrystalBall",
                 "CVE RAG và báo cáo mối đe dọa tạo context theo hai luồng khác nhau")
ax.text(.045, .84, "NHÁNH CVE RAG · CHUẨN BỊ INDEX", color="#326bb3", fontsize=12, weight="bold")
xs = [.045, .283, .521, .759]
box(ax, xs[0], .71, .196, .108, "CVE JSON", "Description chính thức")
box(ax, xs[1], .71, .196, .108, "Trích thuộc tính", "Product · Platform\nProblemType · Version")
box(ax, xs[2], .71, .196, .108, "Embedding", "Contriever → vector")
box(ax, xs[3], .71, .196, .108, "Lưu trữ", "SQLite + file .npy")
for left, right in zip(xs, xs[1:]):
    arrow(ax, [(left + .202, .764), (right - .008, .764)])
box(ax, .045, .545, .196, .108, "Tên sản phẩm", "Embedding query")
box(ax, .31, .545, .25, .108, "Truy hồi CVE", "Cosine Product / Platform\n> 0,68")
box(ax, .665, .545, .29, .108, "CVE context", "Gom các description\nGiới hạn < 3.750 token")
arrow(ax, [(.247, .599), (.302, .599)])
arrow(ax, [(.566, .599), (.657, .599)])
arrow(ax, [(.857, .704), (.857, .684), (.435, .684), (.435, .66)])
ax.text(.045, .495, "NHÁNH BÁO CÁO", color="#187f91", fontsize=12, weight="bold")
box(ax, .045, .365, .215, .105, "Threat report", "SolarWinds / Appendix B", TEAL)
box(ax, .335, .365, .25, .105, "Tạo prompt", "Instruction + context", TEAL)
box(ax, .66, .365, .295, .105, "LLM sinh cấu trúc", "JSON: nodes + edges", GOLD)
arrow(ax, [(.266, .4175), (.327, .4175)])
arrow(ax, [(.591, .4175), (.652, .4175)])
arrow(ax, [(.81, .539), (.81, .513), (.46, .513), (.46, .478)])
box(ax, .045, .155, .275, .12, "Parse + kiểm tra", "graph.json · schema · ID\nEndpoint và cảnh báo")
box(ax, .385, .155, .26, .12, "Bố trí và vẽ", "NetworkX + Matplotlib")
box(ax, .71, .155, .245, .12, "Xuất kết quả", "PNG · SVG · HTML", TEAL)
arrow(ax, [(.8075, .359), (.8075, .318), (.1825, .318), (.1825, .283)])
ax.text(.48, .331, "response.txt", fontsize=12, color=MUTED, ha="center")
arrow(ax, [(.326, .215), (.377, .215)])
arrow(ax, [(.651, .215), (.702, .215)])
ax.text(.045, .095, "Đối chiếu quan hệ với nguồn trước khi kết luận về đường tấn công.",
        color=INK, fontsize=15, weight="bold", va="center")
ax.text(.045, .052, "Schema và tham chiếu hợp lệ chỉ xác nhận cấu trúc; cần kiểm tra ngữ nghĩa từng quan hệ.",
        color=MUTED, fontsize=12, va="center")
save(fig, "luong_he_thong")

fig, ax = canvas("Luồng tạo ảnh trong một lần demo",
                 "LLM tạo nút và cạnh; Python tính bố cục và vẽ hình từ JSON")
xs = [.045, .37, .695]
w, h = .26, .175
box(ax, xs[0], .575, w, h, "1. Chọn dữ liệu", "CVE context hoặc báo cáo\nGiữ thông tin nguồn", TEAL, 17, 13)
box(ax, xs[1], .575, w, h, "2. Tạo prompt", "Instruction quy định JSON\nGhép nội dung context", BLUE, 17, 13)
box(ax, xs[2], .575, w, h, "3. Gọi LLM", "Sinh nodes / edges\nLưu response.txt", GOLD, 17, 13)
box(ax, xs[2], .265, w, h, "4. Parse + kiểm tra", "JSON, schema, ID, endpoint\nLưu graph.json + metadata", BLUE, 17, 13)
box(ax, xs[1], .265, w, h, "5. Bố trí và vẽ", "NetworkX spring_layout\nMatplotlib + dựng SVG", BLUE, 17, 13)
box(ax, xs[0], .265, w, h, "6. Xuất và trình bày", "PNG / SVG: báo cáo, slide\nHTML: demo tương tác", TEAL, 17, 13)
arrow(ax, [(.311, .6625), (.362, .6625)])
arrow(ax, [(.636, .6625), (.687, .6625)])
arrow(ax, [(.825, .569), (.825, .448)])
arrow(ax, [(.689, .3525), (.638, .3525)])
arrow(ax, [(.364, .3525), (.313, .3525)])
ax.text(.045, .165, "Replay: đọc response.txt đã lưu rồi thực hiện bước 4 → 5 → 6, không gọi API.",
        fontsize=15, color=INK, weight="bold")
ax.text(.045, .111, "Renderer kiểm tra ID và endpoint; không tự thêm quan hệ để nối các cụm graph.",
        fontsize=13, color=MUTED)
ax.text(.045, .065, "Khi trình bày kết quả: ghi run, mode, model và cảnh báo; đối chiếu cạnh với nguồn.",
        fontsize=13, color=MUTED)
save(fig, "luong_tao_anh")

print("Created 2 PNG and 2 SVG process diagrams.")
