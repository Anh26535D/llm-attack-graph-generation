"""Paper-style circles and complete node/edge names, without changing graph data."""

from html import escape
import json
import math
import re
from pathlib import Path
import textwrap

import networkx as nx
import numpy as np

from .demo_graph import HTML
from .postprocess import AttackGraph

CVE_NAMES = {
    'CVE-2019-20354': 'piSignage path traversal',
    'CVE-2019-3562': 'Oculus Browser HTML injection',
    'CVE-2020-1885': 'OVRRedir.exe privileged file write',
    'CVE-2020-24572': 'RaspAP web console command execution',
    'CVE-2021-24038': 'OVRServiceLauncher.exe handle exposure',
    'CVE-2021-38545': 'Raspberry Pi Glowworm optical side channel',
    'CVE-2021-38759': 'Raspberry Pi default account credentials',
    'CVE-2022-21819': 'Jetson Linux IOMMU misconfiguration',
}


def cve_identity(node):
    ids = set(re.findall(r'CVE-\d{4}-\d{4,}', json.dumps(node), re.I))
    if len(ids) == 1 and next(iter(ids)).upper() in CVE_NAMES:
        return next(iter(ids)).upper()
    text = label(node, '').lower()
    tokens = {'CVE-2019-20354': 'pisignage', 'CVE-2019-3562': 'oculus browser',
              'CVE-2020-1885': 'ovrredir', 'CVE-2020-24572': 'raspap',
              'CVE-2021-24038': 'ovrservicelauncher', 'CVE-2021-38545': 'glowworm',
              'CVE-2022-21819': 'iommu'}
    matches = [key for key, token in tokens.items() if token in text]
    if 'raspberry' in text and 'default' in text and ('password' in text or 'credential' in text):
        matches.append('CVE-2021-38759')
    return matches[0] if len(matches) == 1 else None


CVE_RELATIONS = {
    ('CVE-2019-20354','CVE-2020-24572'): 'File disclosure may reveal RaspAP credentials',
    ('CVE-2019-20354','CVE-2021-38759'): 'File disclosure may expose default account credentials',
    ('CVE-2021-38759','CVE-2020-24572'): 'Administrator access may provide RaspAP authentication',
    ('CVE-2021-38759','CVE-2019-20354'): 'Administrator access may provide piSignage authentication',
    ('CVE-2020-24572','CVE-2019-20354'): 'Command execution may reveal piSignage credentials',
    ('CVE-2021-38759','CVE-2021-38545'): 'Audio playback may enable optical signal recovery',
    ('CVE-2020-24572','CVE-2021-38545'): 'Audio playback may enable optical signal recovery',
    ('CVE-2019-3562','CVE-2020-1885'): 'Unprivileged execution enables privileged file writes',
    ('CVE-2019-3562','CVE-2021-24038'): 'Unprivileged execution enables process handle access',
}

REPORT_NAMES = (
    (r'fake jpg', 'Fake JPG header / disguised payload'),
    (r'registry key.*microsoft.*ctf', 'Microsoft CTF registry check'),
    (r'rolling xor', 'Custom rolling XOR algorithm'),
    (r'pe-like.*format', 'Custom PE-like payload format'),
    (r'teardrop.*memory.only dropper', 'TEARDROP memory-only dropper'),
    (r'teardrop.*windows service', 'TEARDROP Windows service'),
    (r'teardrop.*worker thread', 'TEARDROP worker thread'),
    (r'customized cobalt strike beacon', 'Cobalt Strike BEACON execution'),
    (r'c2 hostnames.*match', 'C2 hostname matching'),
    (r'c2 vps ip.*geographically', 'Victim-country IP selection'),
    (r'compromised legitimate credentials.*remote', 'Legitimate remote-access credentials'),
    (r'distinct.*credentials.*lateral', 'Separate lateral-movement credentials'),
    (r'temporary file replacement', 'Temporary file replacement'),
    (r'temporary scheduled task modification', 'Temporary scheduled task modification'),
    (r'scheduled task.*restored', 'Restore original task configuration'),
    (r'reversion.*restoration.*legitimate utility', 'Restore legitimate utility'),
    (r'routine removal of backdoors', 'Routine backdoor removal'),
    (r'maintain light malware footprint', 'Light malware footprint'),
)


def display_node_name(text):
    matches = [name for pattern, name in REPORT_NAMES if re.search(pattern, text, re.I)]
    if len(matches) == 1:
        return matches[0]
    if ':' not in text:
        return text
    heading, detail = text.split(':', 1)
    generic = {'threat actor', 'initial compromise', 'execution', 'deployment', 'file access',
               'environment verification', 'payload decoding', 'memory loading', 'payload execution',
               'infrastructure', 'defense evasion', 'credential access', 'initial/persistent access',
               'lateral movement', 'defense evasion / execution', 'execution / defense evasion', 'strategic objective'}
    return detail.strip() if heading.strip().lower() in generic else heading.strip()


def label(item: dict, fallback: str) -> str:
    for key in ("label", "name", "title", "relation", "relationship", "action"):
        if item.get(key) is not None and str(item[key]).strip():
            return str(item[key])
    return fallback


def overlap(a, b) -> float:
    return max(0, min(a[2], b[2]) - max(a[0], b[0])) * max(0, min(a[3], b[3]) - max(a[1], b[1]))


def t0_overview(graph: AttackGraph):
    """Optional editorial abstraction, never a replacement for the model graph.

    Only emit it when every non-context node can be mapped to an explicit role.
    Edges are the quotient of real source edges; no extra relation is inferred.
    """
    groups = {key: [] for key in ('pg_conditions', 'pg_access', 'applications', 'execution')}
    mapping, omitted = {}, []
    for node in graph.nodes:
        key, text = str(node['id']), label(node, str(node['id'])).lower()
        if re.fullmatch(r'(external |initial |remote )?(attacker|start|initial access)', text.strip()):
            omitted.append(key)
            continue
        if any(word in text for word in ('postgres', 'trust authentication', 'ip address')):
            group = 'pg_access' if any(word in text for word in ('unauthorized', 'compromise', 'access granted', 'database access')) else 'pg_conditions'
        elif any(word in text for word in ('wordpress', 'liferay', 'phpunit', 'weblogic', 'container image', 'vulnerable application')):
            group = 'applications'
        elif any(word in text for word in ('remote code execution', 'rce', 'payload', 'server access', 'code execution')):
            group = 'execution'
        else:
            return None
        mapping[key] = group
        groups[group].append(key)
    if any(not members for members in groups.values()):
        return None
    edges = {}
    internal, context = [], []
    for index, edge in enumerate(graph.edges):
        source = str(edge.get('from', edge.get('source')))
        target = str(edge.get('to', edge.get('target')))
        a, b = mapping.get(source), mapping.get(target)
        if a is None or b is None:
            context.append(index)
        elif a == b:
            internal.append(index)
        else:
            edges.setdefault((a, b), []).append(index)
    if set(edges) != {('pg_conditions', 'pg_access'), ('applications', 'execution')}:
        return None
    texts = ' '.join(label(node, str(node['id'])).lower() for node in graph.nodes)
    products = [name for name in ('WordPress', 'Liferay', 'PHPUnit', 'Oracle WebLogic') if name.lower() in texts]
    conditions = [name for name, pattern in [('trust authentication', 'trust authentication'), ('broad IP access', 'ip address')] if pattern in texts]
    outcomes = [name for name, pattern in [('remote code execution', r'\brce\b|remote code execution'),
                                          ('payload delivery', r'payload'), ('server access', r'server access')] if re.search(pattern, texts)]
    names = {
        'pg_conditions': 'Misconfigured PostgreSQL server' + (' ('+' / '.join(conditions)+')' if conditions else ''),
        'pg_access': 'Unauthorized PostgreSQL server access',
        'applications': 'Container applications' + (' ('+' / '.join(products)+')' if products else ''),
        'execution': ' / '.join(outcomes).capitalize() if outcomes else 'Execution outcome',
    }
    nodes = [{'id': key, 'label': names[key], 'source_nodes': members} for key, members in groups.items()]
    projected_edges = [{'from': a, 'to': b, 'label': label(graph.edges[indexes[0]], '(unlabelled in response)'),
                        'source_edges': indexes, 'source_labels': [label(graph.edges[index], '') for index in indexes]}
                       for (a, b), indexes in edges.items()]
    record = {'kind': 'editorial_abstraction', 'model_graph_nodes': len(graph.nodes), 'model_graph_edges': len(graph.edges),
              'groups': groups, 'omitted_context_nodes': omitted, 'internal_edge_indexes': internal,
              'context_edge_indexes': context, 'new_relations_inferred': False}
    return AttackGraph(nodes, projected_edges), record


def _layout(ids, pairs, seed, aspect):
    net = nx.Graph()
    net.add_nodes_from(ids)
    net.add_edges_from(pairs)
    result = {}
    cursor_x = cursor_y = row_height = 0.
    # Disconnected components stay disconnected, as in Figures 7/9/10/13.
    components = sorted(nx.connected_components(net), key=lambda c: (-len(c), sorted(c)))
    widths = [max(280., math.sqrt(len(component))*220) for component in components]
    heights = [max(240., width/aspect) for width in widths]
    row_limit = max(max(widths), math.sqrt(sum((w+220)*(h+160) for w, h in zip(widths, heights))*aspect))
    if len(components) == 2 and max(map(len, components)) <= 4 and aspect >= 2:
        row_limit = sum(widths) + 250
    for component, width, height in zip(components, widths, heights):
        if cursor_x and cursor_x + width > row_limit:
            cursor_x = 0.
            cursor_y += row_height + 180
            row_height = 0.
        part = net.subgraph(sorted(component)).copy()
        pos = nx.spring_layout(part, seed=seed, iterations=350, k=1.7 / math.sqrt(len(part)))
        values = np.array([pos[key] for key in sorted(pos)])
        if len(part) > 3:
            centered = values-values.mean(axis=0)
            _, vectors = np.linalg.eigh(centered.T @ centered)
            basis = vectors[:, ::-1]
            rotated = centered @ basis
            pos = {key: value for key, value in zip(sorted(pos), rotated)}
            values = rotated
        low = values.min(axis=0)
        span = np.maximum(np.ptp(values, axis=0), .001)
        for key, value in pos.items():
            local = (value-low)/span * [width, height] if len(component)>1 else np.array([width/2, height/2])
            result[key] = local + [cursor_x, cursor_y]
        cursor_x += width + 240
        row_height = max(row_height, height)
    return result


def _crossings(points, pairs):
    def orientation(a, b, c):
        return (b[0]-a[0])*(c[1]-a[1]) - (b[1]-a[1])*(c[0]-a[0])
    count = 0
    for i, (a, b) in enumerate(pairs):
        for c, d in pairs[i+1:]:
            if len({a, b, c, d}) != 4:
                continue
            x, y, z, w = (points[key] for key in (a, b, c, d))
            if orientation(x, y, z)*orientation(x, y, w) < 0 and orientation(z, w, x)*orientation(z, w, y) < 0:
                count += 1
    return count


def render_paper_graph(graph, output: Path, *, title: str, subtitle: str = "", seed: int = 42, aspect: float = 1.78) -> dict:
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib import font_manager
    import matplotlib.pyplot as plt
    from matplotlib.patches import Circle, FancyArrowPatch
    from matplotlib.path import Path as MplPath
    from PIL import ImageFont

    if not graph.nodes:
        raise ValueError("Empty graph; inspect the saved response.")
    ids = [str(node["id"]) for node in graph.nodes]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate node IDs; no nodes were merged for presentation.")
    pairs = [(str(edge.get("from", edge.get("source"))), str(edge.get("to", edge.get("target")))) for edge in graph.edges]
    if any(a not in ids or b not in ids for a, b in pairs):
        raise ValueError("Missing edge endpoint; no edge was removed for presentation.")
    original_node_labels = [label(node, str(node["id"])) for node in graph.nodes]
    # A heading followed by explanatory detail is still the node's name. Keep
    # the complete response text in graph.json and the interactive detail panel.
    node_labels = [display_node_name(text) for text in original_node_labels]
    original_edge_labels = [label(edge, "(unlabelled in response)") for edge in graph.edges]
    edge_labels = list(original_edge_labels)
    identities = [cve_identity(node) for node in graph.nodes]
    aliases = len(identities) == 8 and set(identities) == set(CVE_NAMES)
    if aliases:
        node_labels = [CVE_NAMES[key] for key in identities]
        identity_by_id = dict(zip(ids, identities))
        for i, (a, b) in enumerate(pairs):
            # These are display aliases for the known case-study transitions;
            # full labels/conditions are preserved and not independently validated.
            if not re.search(r'\b(not|never|cannot|unsupported|unrelated)\b', original_edge_labels[i], re.I):
                edge_labels[i] = CVE_RELATIONS.get((identity_by_id[a], identity_by_id[b]), original_edge_labels[i])
    font_path = font_manager.findfont("Arial")
    font = ImageFont.truetype(font_path, 20)

    def text_box(text, wrap):
        lines = textwrap.wrap(text, width=wrap, break_long_words=True, break_on_hyphens=False) or [text]
        width = max(font.getlength(line) for line in lines) + 18
        return lines, width, len(lines) * 26 + 12

    candidates = [(trial, _layout(ids, pairs, trial, aspect)) for trial in dict.fromkeys([seed, 17, 7, 91])]
    selected_seed, base = min(candidates, key=lambda item: _crossings(item[1], pairs))

    best = None
    for scale in (1., 1.3, 1.7, 2.2, 3.):
        points = {key: value * scale + [220, 210] for key, value in base.items()}
        occupied = [(p[0]-30, p[1]-30, p[0]+30, p[1]+30) for p in points.values()]
        labels = []
        collisions = 0

        def place(text, options, wrap):
            nonlocal collisions
            lines, width, height = text_box(text, wrap)
            choices = []
            for priority, (x, y) in enumerate(options):
                box = (x-width/2, y-height/2, x+width/2, y+height/2)
                penalty = sum(overlap(box, other) for other in occupied)
                choices.append((penalty, priority, (x, y), box))
            penalty, _, center, box = min(choices, key=lambda item: (item[0], item[1]))
            if penalty > .01:
                collisions += 1
            occupied.append(box)
            labels.append((lines, center, box))
            return center

        for key, text in zip(ids, node_labels):
            x, y = points[key]
            _, width, height = text_box(text, 27)
            options = []
            for extra in (0, 25, 60, 110):
                dy, dx = 34 + height/2 + extra, 34 + width/2 + extra
                options.extend([(x, y+dy), (x, y-dy), (x+dx, y), (x-dx, y),
                                (x+dx*.8, y+dy), (x-dx*.8, y-dy)])
            place(text, options, 27)

        curves = []
        for i, ((a, b), text) in enumerate(zip(pairs, edge_labels)):
            start, end = points[a], points[b]
            direction = end-start
            length = max(float(np.linalg.norm(direction)), 1)
            normal = np.array([-direction[1], direction[0]]) / length
            parallel = sum(1 for x, y in pairs[:i] if {x, y} == {a, b})
            control = (start+end)/2 + normal*(20 + parallel*65)
            if a == b:
                start = start + [24, 0]
                end = end + [0, -24]
                control = points[a] + [190, -190]
            else:
                start = start + (control-start)/max(np.linalg.norm(control-start), 1)*25
                end = end + (control-end)/max(np.linalg.norm(control-end), 1)*27
            options = []
            for lift in (0, 25, -25, 55, -55, 90, -90, 140, -140, 210, -210):
                for t in (.5, .35, .65, .23, .77, .12, .88):
                    midpoint = (1-t)**2*start + 2*t*(1-t)*control + t*t*end
                    options.append(tuple(midpoint + normal*lift))
            center = place(text, options, 31)
            curves.append((start, control, end, center))
        best = points, labels, curves, occupied, collisions, scale
        if collisions == 0:
            break

    points, labels, curves, occupied, collisions, scale = best
    xmin = min(box[0] for box in occupied) - 40
    ymin = min(box[1] for box in occupied) - 40
    shift = np.array([35-xmin, 120-ymin])
    points = {key: value + shift for key, value in points.items()}
    labels = [(lines, np.array(center)+shift, tuple(np.array(box)+np.tile(shift, 2))) for lines, center, box in labels]
    curves = [(start+shift, control+shift, end+shift, np.array(center)+shift) for start, control, end, center in curves]
    width = int(max([box[2] for _, _, box in labels] + [value[0]+24 for value in points.values()] + [curve[1][0] for curve in curves]) + 90)
    height = int(max([box[3] for _, _, box in labels] + [value[1]+24 for value in points.values()] + [curve[1][1] for curve in curves]) + 90)
    width = max(width, 1100)
    fig, ax = plt.subplots(figsize=(width/150, height/150), dpi=150)
    ax.set(xlim=(0, width), ylim=(height, 0))
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">',
           '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#738aae"/></marker></defs>',
           '<rect width="100%" height="100%" fill="white"/>',
           f'<text x="55" y="50" font-family="Arial" font-size="25" fill="#19334b">{escape(title)}</text>',
           f'<text x="55" y="82" font-family="Arial" font-size="17" fill="#536c86">{escape(subtitle)} | {len(ids)} nodes / {len(pairs)} edges</text>']
    ax.text(55, 50, title, fontsize=12, fontfamily="Arial", color="#19334b")
    ax.text(55, 82, f"{subtitle} | {len(ids)} nodes / {len(pairs)} edges", fontsize=8.16, fontfamily="Arial", color="#536c86")

    for i, (start, control, end, center) in enumerate(curves):
        path = f'M {start[0]:.2f} {start[1]:.2f} Q {control[0]:.2f} {control[1]:.2f} {end[0]:.2f} {end[1]:.2f}'
        svg.append(f'<g class="edge" data-i="{i}" tabindex="0"><path d="{path}" fill="none" stroke="#96a9c8" stroke-width="1.5" marker-end="url(#arrow)"/><path d="{path}" fill="none" stroke="transparent" stroke-width="15"/></g>')
        ax.add_patch(FancyArrowPatch(path=MplPath([start, control, end], [1, 3, 3]), arrowstyle="-|>", mutation_scale=8, color="#96a9c8", lw=.7))
    for i, key in enumerate(ids):
        x, y = points[key]
        svg.append(f'<g class="node" data-i="{i}" tabindex="0" role="button" aria-label="{escape(node_labels[i], quote=True)}"><circle cx="{x:.2f}" cy="{y:.2f}" r="24" fill="#4776bd" stroke="#31558d"/></g>')
        ax.add_patch(Circle((x, y), radius=24, facecolor="#4776bd", edgecolor="#31558d", lw=.7))
    for i, (lines, center, box) in enumerate(labels):
        node_text = i < len(ids)
        color = "#222b38" if node_text else "#bf3434"
        x, y = center
        cls = "node-label" if node_text else "edge-label"
        svg.append(f'<g class="{cls}" data-i="{i if node_text else i-len(ids)}"><rect x="{box[0]:.2f}" y="{box[1]:.2f}" width="{box[2]-box[0]:.2f}" height="{box[3]-box[1]:.2f}" fill="white" opacity=".92"/>')
        for j, line in enumerate(lines):
            yy = y + (j-(len(lines)-1)/2)*26 + 7
            svg.append(f'<text x="{x:.2f}" y="{yy:.2f}" text-anchor="middle" font-family="Arial" font-size="20" fill="{color}">{escape(line)}</text>')
        svg.append('</g>')
        ax.text(x, y, "\n".join(lines), ha="center", va="center", fontfamily="Arial", fontsize=9.6,
                color=color, linespacing=1.28, bbox={"facecolor": "white", "edgecolor": "none", "alpha": .92, "pad": 3})
    svg.append('</svg>')
    svg_text = "\n".join(svg)
    output.mkdir(parents=True, exist_ok=True)
    (output / "graph.svg").write_text(svg_text, encoding="utf-8")
    fig.savefig(output / "graph.png", dpi=150, facecolor="white")
    plt.close(fig)
    payload = json.dumps({"nodes": graph.nodes, "edges": graph.edges, "sources": {}}, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    page = HTML.replace("__TITLE__", escape(title)).replace("__GRAPH__", svg_text).replace("__DATA__", payload)
    page = page.replace('.selected rect{', '.selected circle,.selected rect{')
    page = page.replace("e.target.closest('.node,.edge')", "e.target.closest('.node,.edge,.node-label,.edge-label')")
    page = page.replace('info(data.nodes[i],data.nodes[i].label)',
                        "info(data.nodes[i],data.nodes[i].label||data.nodes[i].name||data.nodes[i].title||String(data.nodes[i].id))")
    page = page.replace("info(edge,edge.label||'Quan hệ')", "info(edge,edge.label||edge.name||edge.relation||edge.relationship||'Quan hệ')")
    page = page.replace('</script></html>', '''document.querySelectorAll('.node-label,.edge-label').forEach(el=>{
el.style.cursor='pointer';el.addEventListener('click',()=>{
const cls=el.classList.contains('node-label')?'node':'edge';
document.querySelector(`.${cls}[data-i="${el.dataset.i}"]`).dispatchEvent(new MouseEvent('click'));
});});</script></html>''')
    (output / "graph.html").write_text(page, encoding="utf-8")
    record = {"style": "paper_circles", "seed": selected_seed, "scale": scale,
              "node_labels": node_labels, "original_node_labels": original_node_labels, "edge_labels": edge_labels,
              "original_edge_labels": original_edge_labels, "display_aliases": 'case_study_CVE_names' if aliases else 'report_techniques_and_headings',
              "label_collisions": collisions, "width": width, "height": height, "target_aspect": aspect,
              "nodes": len(ids), "edges": len(pairs), "graph_changed": False}
    (output / "render.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return record
