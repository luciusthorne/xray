"""A self-contained HTML page for the evidence graph (``xray inspect CMD --html``).

The program sits at the left; everything it reaches is laid out in
columns by the number of steps it takes to get there. A command or
library name and the file it resolves to are drawn as one edge to the
file, labelled with the name. Edge style shows the basis of the proof.
Clicking a node lists every link into and out of it with its evidence,
and highlights the strongest path from the program.
"""

from __future__ import annotations

import html
import json
from collections import defaultdict, deque
from pathlib import Path

from .evidence import BASES, weakest


def view_data(graph):
    """Nodes and drawn edges for the page, with command and soname names folded into their files."""

    owners = {}
    for link in graph.links.values():
        if link.kind == "owned_by":
            owners[link.source] = graph.nodes[link.target].label
    resolves = {}
    for link in graph.links.values():
        if link.kind == "resolves_to":
            resolves[link.source] = link

    edges = {}
    for link in graph.links.values():
        if link.kind in ("owned_by", "resolves_to"):
            continue
        target, via, basis = link.target, None, link.basis
        evidence = [item.to_dict() for item in link.evidence]
        onward = resolves.get(target)
        if onward is not None:
            via = graph.nodes[target].label
            evidence += [item.to_dict() for item in onward.evidence]
            basis = weakest([basis, onward.basis])
            target = onward.target
        key = (link.source, target)
        edge = edges.get(key)
        if edge is None:
            edges[key] = {"source": link.source, "target": target, "kinds": [link.kind], "via": via,
                          "basis": basis, "evidence": evidence}
        else:
            if link.kind not in edge["kinds"]:
                edge["kinds"].append(link.kind)
            edge["evidence"] += evidence
            edge["basis"] = min(edge["basis"], basis, key=BASES.index)

    used = {graph.root} | {edge["source"] for edge in edges.values()} | {edge["target"] for edge in edges.values()}
    nodes = []
    for node_id in used:
        node = graph.nodes.get(node_id)
        if node is None:
            continue
        attrs = node.attrs
        nodes.append({
            "id": node.id,
            "label": node.label if node.kind in ("command", "soname", "package") else Path(node.id).name or node.id,
            "path": node.id if node.id.startswith("/") else None,
            "kind": "file" if node.kind == "unknown" else node.kind,
            "package": owners.get(node.id),
            "missing": attrs.get("resolved") is False,
            "observed": bool(attrs.get("observed")),
            "unexpanded": bool(attrs.get("not_expanded")),
            "rpath": attrs.get("rpath"),
            "runpath": attrs.get("runpath"),
        })

    # columns: steps from the root
    depth = {graph.root: 0}
    outgoing = defaultdict(list)
    for edge in edges.values():
        outgoing[edge["source"]].append(edge["target"])
    queue = deque([graph.root])
    while queue:
        current = queue.popleft()
        for target in outgoing[current]:
            if target not in depth:
                depth[target] = depth[current] + 1
                queue.append(target)
    for node in nodes:
        node["depth"] = depth.get(node["id"], max(depth.values(), default=0) + 1)

    counts = dict.fromkeys(BASES, 0)
    for link in graph.links.values():
        counts[link.basis] += 1
    return {
        "root": graph.root,
        "nodes": nodes,
        "edges": list(edges.values()),
        "counts": counts,
        "blind_spots": graph.blind_spots,
        "risks": graph.risks,
        "truncated": graph.truncated,
        "trace": graph.trace,
    }


def render(graph):
    data = view_data(graph)
    payload = json.dumps(data).replace("</", "<\\/")
    title = html.escape(f"{Path(graph.root).name} — XRAY evidence graph")
    return _PAGE.replace("__TITLE__", title).replace("__DATA__", payload)


_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f7f8fa;--panel:#fff;--ink:#1d2330;--muted:#677084;--line:#d9dde5;--node:#fff;
--observed:#1f9d55;--declared:#2f6fd6;--inferred:#7b8494;--guessed:#d9822b;--risk:#c2410c;--hi:#7c3aed;
--k-shell:#0f766e;--k-python:#2563eb;--k-elf:#475569;--k-library:#94a3b8;--k-command:#b91c1c;--k-other:#a16207}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d1117;--panel:#151b23;--ink:#e6edf3;--muted:#8b949e;
--line:#2a313c;--node:#1b222c;--inferred:#8b949e;--k-elf:#94a3b8;--k-library:#64748b}}
:root[data-theme=dark]{--bg:#0d1117;--panel:#151b23;--ink:#e6edf3;--muted:#8b949e;--line:#2a313c;--node:#1b222c;
--inferred:#8b949e;--k-elf:#94a3b8;--k-library:#64748b}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);
font:14px/1.4 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;gap:12px 20px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{font-size:16px;margin:0;font-weight:650}header h1 code{font-weight:500;color:var(--muted)}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border:1px solid var(--line);
border-radius:999px;cursor:pointer;user-select:none;font-size:12.5px;background:var(--bg)}.chip.off{opacity:.4}
.sw{width:22px;height:0;border-top:3px solid}.sw.inferred{border-top-style:dashed}.sw.guessed{border-top-style:dotted}
input[type=search]{padding:5px 9px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--ink);min-width:200px}
button{padding:5px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--ink);cursor:pointer}
main{display:grid;grid-template-columns:1fr 380px;height:calc(100% - 56px)}
@media (max-width:860px){main{grid-template-columns:1fr;grid-template-rows:60% 40%}}
#stage{position:relative;overflow:hidden;cursor:grab}#stage.drag{cursor:grabbing}svg{display:block;width:100%;height:100%}
aside{border-left:1px solid var(--line);background:var(--panel);overflow:auto;padding:14px 16px}
aside h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:16px 0 6px}
aside h2:first-child{margin-top:0}.path{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.link{border:1px solid var(--line);border-radius:8px;padding:7px 9px;margin:6px 0;background:var(--bg)}
.link .top{display:flex;justify-content:space-between;gap:8px}.basis{font-size:11.5px;font-weight:650;text-transform:uppercase}
.ev{font-size:12.5px;color:var(--muted);margin-top:3px}.ev code{font-size:12px}
.risk{color:var(--risk)}.muted{color:var(--muted)}ul{padding-left:18px;margin:4px 0}li{margin:3px 0}
.n rect{fill:var(--node);stroke:var(--line);stroke-width:1.2;rx:6}.n text{fill:var(--ink);font-size:12.5px}
.n .bar{stroke:none}.n.sel rect{stroke:var(--hi);stroke-width:2.5}.n.dim{opacity:.18}.n.missing rect{stroke-dasharray:4 3}
.n.match rect{stroke:var(--hi);stroke-width:2}.e{fill:none;stroke-width:1.6}.e.dim{opacity:.08}.e.hi{stroke-width:3.2}
.e.observed{stroke:var(--observed)}.e.declared{stroke:var(--declared)}.e.inferred{stroke:var(--inferred);stroke-dasharray:6 4}
.e.guessed{stroke:var(--guessed);stroke-dasharray:2 4}.el{font-size:11px;fill:var(--muted)}.hidden{display:none}
.colhead{font-size:11.5px;fill:var(--muted);text-transform:uppercase;letter-spacing:.05em}
</style></head><body>
<header>
  <h1>XRAY evidence graph <code id="rootname"></code></h1>
  <div class="chips" id="bases"></div>
  <input type="search" id="q" placeholder="Find a file, command, library…">
  <button id="fit">Fit</button><button id="theme" title="Light / dark">◐</button>
</header>
<main><div id="stage"><svg id="svg"><g id="vp"></g></svg></div><aside id="side"></aside></main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const BASES = ['observed','declared','inferred','guessed'];
const RANK = Object.fromEntries(BASES.map((b,i)=>[b,i]));
const on = Object.fromEntries(BASES.map(b=>[b,true]));
const byId = Object.fromEntries(D.nodes.map(n=>[n.id,n]));
const W = 230, H = 28, GX = 110, GY = 10, PAD = 40;
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
document.getElementById('rootname').textContent = D.root;
try { const t = localStorage.getItem('xray-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
document.getElementById('theme').onclick = () => {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const cur = document.documentElement.dataset.theme || (dark ? 'dark' : 'light');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next; try { localStorage.setItem('xray-theme', next); } catch (e) {}
};

// basis chips
const chips = document.getElementById('bases');
for (const b of BASES) {
  const c = document.createElement('span'); c.className = 'chip'; c.dataset.b = b;
  c.innerHTML = `<span class="sw ${b}" style="border-top-color:var(--${b})"></span>${b} <b>${D.counts[b]}</b>`;
  c.onclick = () => { on[b] = !on[b]; c.classList.toggle('off', !on[b]); draw(); };
  chips.appendChild(c);
}

// layout: columns by depth, ordered by the mean position of parents
const cols = {};
for (const n of D.nodes) (cols[n.depth] ||= []).push(n);
const parents = {}; for (const e of D.edges) (parents[e.target] ||= []).push(e.source);
// hubs: files nearly everything links to (libc, the loader); their edges stay faint until selected
const hub = new Set(Object.entries(parents).filter(([, ps]) => ps.length >= Math.max(8, D.nodes.length / 8)).map(([id]) => id));
const pos = {};
const depths = Object.keys(cols).map(Number).sort((a,b)=>a-b);
const kindOrder = {shell:0, python:1, perl:1, ruby:1, javascript:1, typescript:1, lua:1, c:1, elf:2, library:3, command:4};
for (const d of depths) {
  const list = cols[d];
  list.forEach(n => {
    const ps = (parents[n.id] || []).filter(p => pos[p]);
    n._key = ps.length ? ps.reduce((s,p)=>s+pos[p].y,0)/ps.length : 0;
  });
  list.sort((a,b) => (kindOrder[a.kind] ?? 5) - (kindOrder[b.kind] ?? 5) || a._key - b._key || a.label.localeCompare(b.label));
  list.forEach((n,i) => pos[n.id] = {x: PAD + d*(W+GX), y: PAD + 26 + i*(H+GY)});
}
const totalW = PAD*2 + (depths.length)*(W+GX), totalH = PAD*2 + 26 + Math.max(...depths.map(d=>cols[d].length))*(H+GY);

const svg = document.getElementById('svg'), vp = document.getElementById('vp');
const NS = 'http://www.w3.org/2000/svg';
const el = (tag, attrs, parent) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); parent && parent.appendChild(e); return e; };
let selected = null, highlight = new Set(), hiEdges = new Set(), query = '';

function color(kind) { return `var(--k-${['shell','python','elf','library','command'].includes(kind) ? kind : (kind==='soname'?'command':'other')})`; }

function strongestPath(target) {
  // best path from the root: fewest weak links first, then fewest steps
  const inc = {}; for (const e of D.edges) if (on[e.basis]) (inc[e.target] ||= []).push(e);
  const best = {[D.root]: {w: -1, len: 0, prev: null}};
  const order = D.nodes.slice().sort((a,b)=>a.depth-b.depth);
  for (let pass=0; pass<3; pass++) for (const n of order) for (const e of inc[n.id] || []) {
    const p = best[e.source]; if (!p) continue;
    const cand = {w: Math.max(p.w, RANK[e.basis]), len: p.len+1, prev: e};
    const cur = best[n.id];
    if (!cur || cand.w < cur.w || (cand.w === cur.w && cand.len < cur.len)) best[n.id] = cand;
  }
  const nodes = new Set([target]), edges = new Set();
  let cur = best[target];
  while (cur && cur.prev) { edges.add(cur.prev); nodes.add(cur.prev.source); cur = best[cur.prev.source]; }
  return {nodes, edges, basis: best[target] ? BASES[Math.max(0,best[target].w)] : null, found: !!best[target]};
}

function draw() {
  vp.innerHTML = '';
  for (const d of depths) {
    const t = el('text', {x: PAD + d*(W+GX), y: PAD, class: 'colhead'}, vp);
    t.textContent = d === 0 ? 'program' : `${d} step${d>1?'s':''}`;
  }
  const visible = new Set([D.root]);
  for (const e of D.edges) if (on[e.basis]) { visible.add(e.source); visible.add(e.target); }
  const ge = el('g', {}, vp);
  for (const e of D.edges) {
    if (!on[e.basis]) continue;
    const a = pos[e.source], b = pos[e.target]; if (!a || !b) continue;
    const x1 = a.x + W, y1 = a.y + H/2, x2 = b.x, y2 = b.y + H/2;
    const back = x2 <= x1;
    const dpath = back ? `M${x1},${y1} C${x1+60},${y1} ${x2-60},${y2-40} ${x2},${y2}`
                       : `M${x1},${y1} C${(x1+x2)/2},${y1} ${(x1+x2)/2},${y2} ${x2},${y2}`;
    const dim = selected ? !hiEdges.has(e) : hub.has(e.target);
    const p = el('path', {d: dpath, class: `e ${e.basis}${hiEdges.has(e)?' hi':''}${dim?' dim':''}`}, ge);
    const t = el('title', {}, p); t.textContent = `${e.kinds.join(', ')} [${e.basis}]${e.via ? ' via '+e.via : ''}`;
  }
  const gn = el('g', {}, vp);
  for (const n of D.nodes) {
    if (!visible.has(n.id)) continue;
    const p = pos[n.id];
    const isMatch = query && (n.label.toLowerCase().includes(query) || (n.path||'').toLowerCase().includes(query));
    const cls = ['n', n.id===selected?'sel':'', selected && !highlight.has(n.id) ? 'dim' : '', n.missing?'missing':'', isMatch?'match':''].join(' ');
    const g = el('g', {class: cls, transform: `translate(${p.x},${p.y})`, 'data-id': n.id, style:'cursor:pointer'}, gn);
    el('rect', {width: W, height: H}, g);
    el('rect', {class:'bar', width: 5, height: H, fill: color(n.kind), rx: 2}, g);
    const room = n.missing ? 22 : 28;
    const label = n.label.length > room ? n.label.slice(0, room - 1) + '…' : n.label;
    const t = el('text', {x: 12, y: 18}, g); t.textContent = label;
    const k = el('text', {x: W - 8, y: 18, 'text-anchor':'end', class: n.missing ? 'el risk' : 'el'}, g);
    k.textContent = n.missing ? 'not found' : (n.observed ? '● ' + n.kind : n.kind);
    if (n.missing) k.setAttribute('style', 'fill:var(--risk)');
    const tt = el('title', {}, g); tt.textContent = (n.path || n.label) + (n.package ? `\npackage: ${n.package}` : '');
    g.onclick = ev => { ev.stopPropagation(); select(n.id); };
  }
}

function select(id) {
  selected = id;
  const sp = strongestPath(id);
  highlight = sp.nodes; hiEdges = sp.edges;
  draw(); side(id, sp);
}

function evidenceHtml(list) {
  return list.map(v => `<div class="ev"><span class="basis" style="color:var(--${v.basis})">${v.basis}</span> · ${esc(v.method)} — ${esc(v.detail)}${v.file ? ` <code>${esc(v.file.split('/').pop())}${v.line ? ':'+v.line : ''}</code>` : ''}</div>`).join('');
}

function side(id, sp) {
  const s = document.getElementById('side');
  if (!id) {
    const risks = D.risks.length ? '<ul>' + D.risks.map(r => `<li class="risk">${esc(r.file==='*'?'':r.file.split('/').pop()+': ')}${esc(r.message)}</li>`).join('') + '</ul>' : '<p class="muted">Nothing flagged — which is not proof of safety.</p>';
    const blind = '<ul>' + D.blind_spots.map(b => `<li>${b.file==='*'?'':'<code>'+esc(b.file.split('/').pop())+'</code>: '}${esc(b.message)}</li>`).join('') + '</ul>';
    const trace = D.trace ? `<h2>Traced run</h2><p>${D.trace.timed_out ? 'timed out' : 'exit status ' + D.trace.status}; ${D.trace.unpredicted.length} file(s) not predicted by static reading.</p>` : '<p class="muted">Nothing was run: links come from metadata and code. Run <code>xray inspect CMD --trace --html</code> to add an observed run.</p>';
    s.innerHTML = `<h2>${esc(D.nodes.length)} nodes · ${esc(D.edges.length)} links drawn</h2>
      <p>Click a node to see the proof for every link into and out of it, and the strongest path from the program.</p>
      <p class="muted">Edges: <b style="color:var(--observed)">observed</b> seen in a run · <b style="color:var(--declared)">declared</b> by metadata the system acts on · <b style="color:var(--inferred)">inferred</b> from code, resolved as this machine would · <b style="color:var(--guessed)">guessed</b>. A path is as strong as its weakest link.</p>
      ${trace}<h2>Worth a look</h2>${risks}<h2>Blind spots</h2>${blind}${D.truncated.length ? '<p class="muted">Truncated: ' + esc(D.truncated[0]) + '</p>' : ''}`;
    return;
  }
  const n = byId[id];
  const inc = D.edges.filter(e => e.target === id), out = D.edges.filter(e => e.source === id);
  const badge = e => `<span class="basis" style="color:var(--${e.basis})">${e.basis}</span>`;
  const via = (e, name) => e.via && e.via !== name ? ` <span class="muted">as ${esc(e.via)}</span>` : '';
  const inRow = e => `<div class="link"><div class="top"><span>${esc(byId[e.source]?.label || e.source)} <b>${esc(e.kinds.join(', '))}</b> it${via(e, n.label)}</span>${badge(e)}</div>${evidenceHtml(e.evidence)}</div>`;
  const outRow = e => `<div class="link"><div class="top"><span><b>${esc(e.kinds.join(', '))}</b> ${esc(byId[e.target]?.label || e.target)}${via(e, byId[e.target]?.label)}</span>${badge(e)}</div>${evidenceHtml(e.evidence)}</div>`;
  const chain = sp.found && id !== D.root ? [...sp.edges].sort((a,b) => (byId[a.source].depth - byId[b.source].depth)).map(e => esc(byId[e.target].label)).join(' → ') : '';
  s.innerHTML = `<button onclick="selected=null;highlight=new Set();hiEdges=new Set();draw();side(null)">← Overview</button>
    <h2>${esc(n.kind)}${n.observed ? ' · observed in a run' : ''}</h2><div class="path">${esc(n.path || n.label)}</div>
    ${n.package ? `<p>Package: <b>${esc(n.package)}</b></p>` : ''}${n.missing ? '<p class="risk">Named but not found on this machine.</p>' : ''}
    ${n.unexpanded ? '<p class="muted">Not read: at the depth limit.</p>' : ''}
    ${n.rpath ? `<p>RPATH: <code>${esc(n.rpath.join(':'))}</code></p>` : ''}${n.runpath ? `<p>RUNPATH: <code>${esc(n.runpath.join(':'))}</code></p>` : ''}
    ${chain ? `<h2>Strongest path from the program · ${sp.basis}</h2><p>${esc(byId[D.root].label)} → ${chain}</p>` : ''}
    <h2>Reached from (${inc.length})</h2>${inc.map(inRow).join('') || '<p class="muted">—</p>'}
    <h2>Reaches (${out.length})</h2>${out.map(outRow).join('') || '<p class="muted">nothing further</p>'}`;
}

// pan and zoom
let vb = {x: 0, y: 0, w: totalW, h: totalH};
const setVB = () => svg.setAttribute('viewBox', `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
function fit() {
  const r = svg.getBoundingClientRect(); const ratio = r.width / Math.max(r.height,1);
  const w = Math.max(totalW, Math.min(totalH, 2400) * ratio);
  vb = {x: 0, y: 0, w, h: w / ratio}; setVB();
}
document.getElementById('fit').onclick = fit;
svg.addEventListener('wheel', ev => {
  ev.preventDefault(); const r = svg.getBoundingClientRect(); const f = ev.deltaY > 0 ? 1.15 : 1/1.15;
  const mx = vb.x + (ev.clientX - r.left) / r.width * vb.w, my = vb.y + (ev.clientY - r.top) / r.height * vb.h;
  vb = {x: mx - (mx - vb.x)*f, y: my - (my - vb.y)*f, w: vb.w*f, h: vb.h*f}; setVB();
}, {passive: false});
let drag = null; const stage = document.getElementById('stage');
stage.addEventListener('pointerdown', ev => { drag = {x: ev.clientX, y: ev.clientY, vx: vb.x, vy: vb.y}; stage.classList.add('drag'); });
addEventListener('pointerup', () => { drag = null; stage.classList.remove('drag'); });
addEventListener('pointermove', ev => { if (!drag) return; const r = svg.getBoundingClientRect();
  vb.x = drag.vx - (ev.clientX - drag.x) / r.width * vb.w; vb.y = drag.vy - (ev.clientY - drag.y) / r.height * vb.h; setVB(); });
svg.addEventListener('click', () => { if (selected) { selected = null; highlight = new Set(); hiEdges = new Set(); draw(); side(null); } });
document.getElementById('q').addEventListener('input', ev => {
  query = ev.target.value.trim().toLowerCase(); draw();
  const hit = query && D.nodes.find(n => n.label.toLowerCase().includes(query) || (n.path||'').toLowerCase().includes(query));
  if (hit) { const p = pos[hit.id]; vb.x = p.x - vb.w/3; vb.y = p.y - vb.h/3; setVB(); }
});
draw(); side(null); fit(); addEventListener('resize', fit);
const deep = decodeURIComponent(location.hash.slice(1));
if (deep.startsWith('node=')) { const want = deep.slice(5); const hit = byId[want] || D.nodes.find(n => n.label === want); if (hit) select(hit.id); }
</script></body></html>
"""
