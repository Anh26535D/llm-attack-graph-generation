"""Readable static and self-contained interactive views of the same model graph.

Rendering never adds nodes or relationships. Unsupported endpoints are rejected.
"""
from __future__ import annotations

from html import escape
import json
import math
from pathlib import Path
import textwrap

import networkx as nx
import numpy as np

COLORS = {
    "delivery": "#326bb3", "execution": "#6555aa", "c2": "#187f91",
    "post_compromise": "#b56923", "evasion": "#946045",
    "detection": "#24846a", "mitigation": "#637147", "other": "#506b8b",
}


def render_demo_graph(graph, output: Path, *, title: str, sources: dict | None = None,
                      subtitle: str | None = None) -> dict:
    nodes, edges = graph.nodes, graph.edges
    ids = [str(n["id"]) for n in nodes]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate node IDs; inspect graph.json before rendering.")
    index = {key: i for i, key in enumerate(ids)}
    pairs = [(str(e.get("from", e.get("source"))), str(e.get("to", e.get("target")))) for e in edges]
    if any(a not in index or b not in index for a, b in pairs):
        raise ValueError("An edge refers to a missing node; inspect graph.json.")
    net = nx.DiGraph()
    net.add_nodes_from(ids)
    net.add_edges_from(pairs)
    # Lay out disconnected components independently: never invent a bridge to
    # improve the picture, and avoid unbounded repulsion between components.
    undirected = net.to_undirected()
    points = {}
    offset = 0
    for component in sorted(nx.connected_components(undirected), key=len, reverse=True):
        part = undirected.subgraph(component)
        layout = nx.spring_layout(part, seed=42, k=.7, iterations=650)
        values = np.array(list(layout.values()))
        low, span = values.min(axis=0), np.maximum(np.ptp(values, axis=0), .001)
        region_width = max(400, math.sqrt(len(component)) * 490)
        region_height = max(300, region_width * .78)
        for key, pos in layout.items():
            points[key] = (pos-low)/span * [region_width, region_height] + [offset, 0]
        offset += region_width + 580
    labels = {key: textwrap.wrap(str(nodes[index[key]].get("label", key)), width=29,
                                break_long_words=True) or [key] for key in ids}
    sizes = {key: (300, max(70, len(labels[key]) * 23 + 26)) for key in ids}
    # Separate node rectangles while retaining the graph's spatial structure.
    for _ in range(150):
        moved = False
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                delta = points[b] - points[a]
                need = np.array([(sizes[a][0] + sizes[b][0]) / 2 + 45,
                                 (sizes[a][1] + sizes[b][1]) / 2 + 50]) - np.abs(delta)
                if min(need) > 0:
                    axis = int(np.argmin(need))
                    shift = (need[axis] / 2 + 1) * (1 if delta[axis] >= 0 else -1)
                    points[a][axis] -= shift
                    points[b][axis] += shift
                    moved = True
        if not moved:
            break
    low = np.min(list(points.values()), axis=0)
    for key in ids:
        points[key] += np.array([220, 260]) - low
    width = int(max(p[0] for p in points.values()) + 230)
    height = int(max(points[key][1] + sizes[key][1] / 2 for key in ids) + 100)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    from matplotlib.path import Path as MplPath
    fig, ax = plt.subplots(figsize=(width / 120, height / 120), dpi=120)
    ax.set(xlim=(0, width), ylim=(height, 0))
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    view_subtitle = subtitle or "LLM draft: verify relationships against source"
    summary_text = f"{len(nodes)} nodes / {len(edges)} edges | {view_subtitle}"
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">',
           '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#7392bb"/></marker></defs>',
           '<rect width="100%" height="100%" fill="white"/>',
           f'<text x="60" y="65" font-family="Arial" font-size="32" fill="#173554">{escape(title)}</text>',
           f'<text x="60" y="104" font-family="Arial" font-size="19" fill="#50617a">{escape(summary_text)}</text>']
    ax.text(60, 65, title, fontsize=19, color="#173554")
    ax.text(60, 104, summary_text, fontsize=11, color="#50617a")
    for k, (category, color) in enumerate(COLORS.items()):
        x = 60 + k * 200
        svg.append(f'<rect x="{x}" y="137" width="16" height="16" fill="{color}"/><text x="{x+24}" y="151" font-size="16" font-family="Arial">{category.replace("_", " ")}</text>')
        ax.plot(x + 8, 145, marker="s", color=color, markersize=8)
        ax.text(x + 24, 151, category.replace("_", " "), fontsize=9)

    occupied = []
    for key in ids:
        x, y = points[key]
        w, h = sizes[key]
        occupied.append((x-w/2-8, y-h/2-8, x+w/2+8, y+h/2+8))

    def endpoint(key, toward):
        direction = toward - points[key]
        w, h = sizes[key]
        scale = 1 / max(abs(direction[0]) / (w/2+7), abs(direction[1]) / (h/2+7), 1e-6)
        return points[key] + direction * scale

    for i, ((a, b), edge) in enumerate(zip(pairs, edges)):
        center_a, center_b = points[a], points[b]
        delta = center_b - center_a
        norm = max(float(np.linalg.norm(delta)), 1)
        normal = np.array([-delta[1], delta[0]]) / norm
        # Keep parallel relationships separate, including opposite directions.
        offset = 38 + 36 * sum(1 for x, y in pairs[:i] if {x, y} == {a, b})
        control = (center_a + center_b) / 2 + normal * offset
        start, end = endpoint(a, control), endpoint(b, control)
        if a == b:
            start = center_a + np.array([sizes[a][0]/2, 0])
            end = center_a + np.array([0, -sizes[a][1]/2])
            control = center_a + np.array([280, -190])
        path = f'M {start[0]:.1f} {start[1]:.1f} Q {control[0]:.1f} {control[1]:.1f} {end[0]:.1f} {end[1]:.1f}'
        svg.append(f'<g class="edge" data-i="{i}" tabindex="0"><path d="{path}" fill="none" stroke="#7392bb" stroke-width="1.9" marker-end="url(#arrow)"/><path d="{path}" fill="none" stroke="transparent" stroke-width="18"/>')
        ax.add_patch(FancyArrowPatch(path=MplPath([start, control, end], [1, 3, 3]), arrowstyle="-|>", mutation_scale=11, color="#7392bb", lw=.85))
        lines = textwrap.wrap(str(edge.get("label", edge.get("relation", "related to"))), width=27) or ["related to"]
        bw, bh = max(len(s) for s in lines) * 9.4 + 14, len(lines) * 20 + 8
        choices = []
        for t in (.5, .35, .65, .23, .77):
            mid = (1-t)**2 * start + 2*t*(1-t)*control + t*t*end
            for lift in (0, 28, -28, 55, -55, 85, -85, 120, -120):
                label_pos = mid + normal * lift
                x, y = label_pos
                box = (x-bw/2, y-bh/2, x+bw/2, y+bh/2)
                collisions = sum(max(0, min(box[2], r[2])-max(box[0], r[0])) * max(0, min(box[3], r[3])-max(box[1], r[1])) for r in occupied)
                choices.append((collisions + abs(lift), label_pos, box))
        _, pos, box = min(choices, key=lambda item: item[0])
        occupied.append(box)
        x, y = pos
        svg.append(f'<g class="edge-label"><rect x="{box[0]:.1f}" y="{box[1]:.1f}" width="{bw:.1f}" height="{bh}" fill="white" opacity=".94" rx="5"/>')
        for j, line in enumerate(lines):
            yy = y + (j-(len(lines)-1)/2)*20 + 6
            svg.append(f'<text x="{x:.1f}" y="{yy:.1f}" text-anchor="middle" font-family="Arial" font-size="17" fill="#bf3434">{escape(line)}</text>')
        svg.append('</g></g>')
        ax.text(x, y, "\n".join(lines), ha="center", va="center", fontsize=9.2, color="#bf3434", bbox=dict(facecolor="white", edgecolor="none", alpha=.94, pad=2))

    for i, key in enumerate(ids):
        x, y = points[key]
        w, h = sizes[key]
        color = COLORS.get(nodes[i].get("category"), COLORS["other"])
        svg.append(f'<g class="node" data-i="{i}" tabindex="0" role="button" aria-label="{escape(str(nodes[i].get("label",key)))}"><rect x="{x-w/2:.1f}" y="{y-h/2:.1f}" width="{w}" height="{h}" rx="18" fill="{color}" stroke="#254866" stroke-width="1.5"/>')
        ax.add_patch(FancyBboxPatch((x-w/2,y-h/2),w,h,boxstyle="round,pad=0,rounding_size=18",facecolor=color,edgecolor="#254866",lw=.8))
        for j, line in enumerate(labels[key]):
            yy = y + (j-(len(labels[key])-1)/2)*23 + 7
            svg.append(f'<text x="{x:.1f}" y="{yy:.1f}" text-anchor="middle" font-size="19" font-family="Arial" fill="white">{escape(line)}</text>')
        svg.append('</g>')
        ax.text(x,y,"\n".join(labels[key]),ha="center",va="center",fontsize=10.5,color="white")
    svg.append('</svg>')
    svg_text = "\n".join(svg)
    output.mkdir(parents=True, exist_ok=True)
    (output / "graph.svg").write_text(svg_text, encoding="utf-8")
    fig.savefig(output / "graph.png", dpi=120, facecolor="white")
    plt.close(fig)
    payload = json.dumps({"nodes": nodes, "edges": edges, "sources": sources or {}}, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    page = HTML.replace("__TITLE__", escape(title)).replace("__GRAPH__", svg_text).replace("__DATA__", payload)
    (output / "graph.html").write_text(page, encoding="utf-8")
    return {"png": "graph.png", "svg": "graph.svg", "html": "graph.html"}


HTML = '''<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title><style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#edf2f8;color:#19334b}header{padding:16px 24px;background:#173554;color:white}h1{font-size:21px;margin:0 0 7px}header p{margin:0;font-size:13px;color:#cbdaeb}nav{display:flex;gap:9px;padding:12px 20px;align-items:center;flex-wrap:wrap}button,input,a{padding:8px 12px;border:1px solid #bccbda;border-radius:6px;background:white;color:#173554;font-size:13px}button,a{cursor:pointer;text-decoration:none}input{width:260px}main{display:grid;grid-template-columns:minmax(0,1fr) 330px;height:calc(100vh - 144px);min-height:400px}#canvas{min-width:0;background:white;overflow:hidden;touch-action:none}svg{display:block;width:100%;height:100%;user-select:none}.node,.edge{cursor:pointer}.dim{opacity:.09}.selected rect{stroke:#f2bb3f;stroke-width:6}.no-labels .edge-label{display:none}aside{overflow:auto;padding:20px;border-left:1px solid #c8d5e2;background:#f8fbff}aside h2{font-size:18px;margin-top:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 Arial;margin:10px 0}.hint{font-size:13px;color:#536c86;line-height:1.55}#stats{margin-left:auto;font-size:13px}#sources{border-top:1px solid #ccd8e5;padding-top:12px}@media(max-width:850px){main{grid-template-columns:minmax(0,1fr);height:auto}#canvas{height:60vh}aside{max-height:300px;min-width:0}input{max-width:100%}#stats{margin:0}}
</style><header><h1>__TITLE__</h1><p>Đồ thị do LLM sinh từ nguồn bài báo · Nhấn nút hoặc cạnh để đọc chi tiết và đối chiếu nguồn.</p></header>
<nav><button id="fit">Toàn bộ</button><button id="plus">＋</button><button id="minus">−</button><button id="labels">Ẩn/hiện nhãn cạnh</button><input id="search" placeholder="Tìm nút: SUNBURST, credentials…" aria-label="Tìm nút"><a href="graph.svg" download>Tải SVG</a><a href="graph.png" download>Tải PNG</a><span id="stats"></span></nav>
<main><div id="canvas">__GRAPH__</div><aside><h2 id="heading">Khám phá đồ thị</h2><p class="hint">Cuộn để phóng to; kéo vùng trống để di chuyển. Nhấn một nút để làm nổi bật các cạnh nối trực tiếp. Nhãn cạnh màu đỏ biểu diễn loại quan hệ; quan hệ phát hiện hoặc giảm thiểu không phải bước khai thác.</p><pre id="detail"></pre><div id="sources"></div></aside></main>
<script type="application/json" id="data">__DATA__</script><script>
const data=JSON.parse(document.querySelector('#data').textContent),svg=document.querySelector('svg'),initial=svg.getAttribute('viewBox').split(' ').map(Number);let view=[...initial],drag=null;
const nodes=[...svg.querySelectorAll('.node')],edges=[...svg.querySelectorAll('.edge')];
document.querySelector('#stats').textContent=`${data.nodes.length} nút · ${data.edges.length} cạnh`;
function update(){svg.setAttribute('viewBox',view.join(' '))}
function clear(){nodes.concat(edges).forEach(el=>el.classList.remove('dim','selected'))}
function info(item,title){document.querySelector('#heading').textContent=title;document.querySelector('#detail').textContent=JSON.stringify(item,null,2);const box=document.querySelector('#sources');box.replaceChildren();const refs=item.source_refs||[];for(const ref of refs){const p=document.createElement('pre');p.textContent=`[${ref}] ${data.sources[ref]||'Không có đoạn nguồn tương ứng trong bản này.'}`;box.appendChild(p)}}
nodes.forEach((el,i)=>{const select=()=>{clear();const id=String(data.nodes[i].id),near=new Set([id]);edges.forEach((e,j)=>{const a=String(data.edges[j].from??data.edges[j].source),b=String(data.edges[j].to??data.edges[j].target),hit=a===id||b===id;e.classList.toggle('dim',!hit);if(hit){near.add(a);near.add(b)}});nodes.forEach((n,j)=>n.classList.toggle('dim',!near.has(String(data.nodes[j].id))));el.classList.add('selected');info(data.nodes[i],data.nodes[i].label)};el.addEventListener('click',select);el.addEventListener('keydown',e=>{if(e.key==='Enter')select()})});
edges.forEach((el,i)=>{const select=()=>{clear();edges.forEach(e=>e.classList.toggle('dim',e!==el));const edge=data.edges[i],a=String(edge.from??edge.source),b=String(edge.to??edge.target);nodes.forEach((n,j)=>n.classList.toggle('dim',![a,b].includes(String(data.nodes[j].id))));info(edge,edge.label||'Quan hệ')};el.addEventListener('click',select);el.addEventListener('keydown',e=>{if(e.key==='Enter')select()})});
function zoom(factor,cx=view[0]+view[2]/2,cy=view[1]+view[3]/2){const next=view[2]*factor;if(next<initial[2]/30||next>initial[2]*3)return;view=[cx+(view[0]-cx)*factor,cy+(view[1]-cy)*factor,view[2]*factor,view[3]*factor];update()}
svg.addEventListener('wheel',e=>{e.preventDefault();const p=new DOMPoint(e.clientX,e.clientY).matrixTransform(svg.getScreenCTM().inverse());zoom(e.deltaY<0?.85:1.18,p.x,p.y)},{passive:false});
svg.addEventListener('pointerdown',e=>{if(e.target.closest('.node,.edge'))return;drag={x:e.clientX,y:e.clientY,v:[...view],scale:svg.getScreenCTM().a};svg.setPointerCapture(e.pointerId)});
svg.addEventListener('pointermove',e=>{if(!drag)return;view=[drag.v[0]-(e.clientX-drag.x)/drag.scale,drag.v[1]-(e.clientY-drag.y)/drag.scale,drag.v[2],drag.v[3]];update()});svg.addEventListener('pointerup',()=>drag=null);svg.addEventListener('pointercancel',()=>drag=null);
document.querySelector('#fit').onclick=()=>{view=[...initial];update();clear();document.querySelector('#search').value=''};
document.querySelector('#plus').onclick=()=>zoom(.7);document.querySelector('#minus').onclick=()=>zoom(1.4);document.querySelector('#labels').onclick=()=>svg.classList.toggle('no-labels');
document.querySelector('#search').oninput=e=>{clear();const q=e.target.value.trim().toLowerCase();if(!q)return;const hits=new Set(data.nodes.filter(n=>JSON.stringify(n).toLowerCase().includes(q)).map(n=>String(n.id)));nodes.forEach((n,i)=>n.classList.toggle('dim',!hits.has(String(data.nodes[i].id))));edges.forEach((edge,i)=>edge.classList.toggle('dim',!hits.has(String(data.edges[i].from??data.edges[i].source))&&!hits.has(String(data.edges[i].to??data.edges[i].target))))};
</script></html>'''
