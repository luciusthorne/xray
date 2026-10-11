import json
from pathlib import Path

_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  html, body { margin: 0; height: 100%; font-family: system-ui, sans-serif; }
  body { display: flex; background: #12151c; color: #dde3ee; }
  #stage { flex: 1; position: relative; overflow: hidden; }
  svg { width: 100%; height: 100%; cursor: grab; }
  svg.panning { cursor: grabbing; }
  #panel { width: 320px; padding: 14px; overflow-y: auto; background: #1a1f2b;
           border-left: 1px solid #2c3446; font-size: 13px; }
  #panel h2 { font-size: 14px; margin: 0 0 8px; word-break: break-all; }
  #panel ul { padding-left: 16px; margin: 4px 0 12px; }
  #panel li { margin: 2px 0; word-break: break-all; }
  .muted { color: #8a94a8; }
  #notice { position: absolute; top: 8px; left: 8px; padding: 6px 10px;
            background: #5a4310; border-radius: 4px; font-size: 12px; }
  #legend { position: absolute; bottom: 8px; left: 8px; font-size: 12px; }
  #legend span { margin-right: 12px; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
         margin-right: 4px; }
  line { stroke: #5b6783; stroke-width: 1; }
  line.dim { opacity: 0.08; }
  line.hot { stroke: #f2c14e; stroke-width: 1.6; }
  line.open { stroke-dasharray: 3 3; }
  circle { stroke: #0c0e13; stroke-width: 1.5; cursor: pointer; }
  circle.hollow { fill: none !important; stroke-width: 2; }
  circle.sel { stroke: #fff; stroke-width: 3; }
  text { fill: #c3cbdb; font-size: 10px; pointer-events: none; }
  text.dim { opacity: 0.15; }
</style>
</head>
<body>
<div id="stage">
  <svg id="svg"><g id="view"><g id="edges"></g><g id="nodes"></g><g id="labels"></g></g></svg>
  <div id="notice" hidden>Graph truncated: some files were not followed.</div>
  <div id="legend"></div>
</div>
<div id="panel"><h2>__TITLE__</h2><p class="muted">Click a node to inspect it. Scroll to zoom, drag the background to pan.</p></div>
<script id="graph-data" type="application/json">__DATA__</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById("graph-data").textContent);
  var COLORS = { python: "#4b8bbe", shell: "#6cc070", elf: "#e07a5f",
                 library: "#a78bfa", unknown: "#8a94a8" };
  var NS = "http://www.w3.org/2000/svg";
  var svg = document.getElementById("svg");
  var view = document.getElementById("view");
  var panel = document.getElementById("panel");

  if (data.metadata.truncated) document.getElementById("notice").hidden = false;

  var legend = document.getElementById("legend");
  Object.keys(COLORS).slice(0, 4).forEach(function (kind) {
    var item = document.createElement("span");
    item.innerHTML = '<i class="dot" style="background:' + COLORS[kind] + '"></i>' + kind;
    legend.appendChild(item);
  });

  var nodes = [], byId = {}, links = [];

  function addNode(id, kind, extra) {
    var n = { id: id, kind: kind, hollow: false, x: 0, y: 0, vx: 0, vy: 0, info: extra };
    nodes.push(n);
    byId[id] = n;
    return n;
  }

  data.nodes.forEach(function (n) { addNode(n.id, n.kind, n); });

  data.edges.forEach(function (e, index) {
    var target;
    if (e.target === null) {
      var key = "?" + e.source + "|" + e.name;
      target = byId[key] || addNode(key, "unknown", { name: e.name });
      target.hollow = true;
      target.label = e.name;
    } else {
      target = byId[e.target];
    }
    if (byId[e.source] && target)
      links.push({ s: byId[e.source], t: target, e: e });
  });

  nodes.forEach(function (n, i) {
    var angle = (i / nodes.length) * Math.PI * 2;
    var radius = 60 + nodes.length * 4;
    n.x = Math.cos(angle) * radius;
    n.y = Math.sin(angle) * radius;
    var parts = (n.label || n.id).split("/");
    n.label = parts[parts.length - 1] || n.id;
  });

  function make(tag, attrs, parent) {
    var el = document.createElementNS(NS, tag);
    for (var k in attrs) el.setAttribute(k, attrs[k]);
    parent.appendChild(el);
    return el;
  }

  links.forEach(function (l) {
    l.el = make("line", {}, document.getElementById("edges"));
    if (l.e.status !== "resolved") l.el.setAttribute("class", "open");
  });
  nodes.forEach(function (n) {
    n.el = make("circle", { r: n.id === data.root ? 9 : 6 }, document.getElementById("nodes"));
    n.el.style.fill = COLORS[n.kind] || COLORS.unknown;
    if (n.hollow) n.el.setAttribute("class", "hollow");
    n.txt = make("text", { dx: 9, dy: 3 }, document.getElementById("labels"));
    n.txt.textContent = n.label;
    n.el.addEventListener("mousedown", function (ev) { startDrag(ev, n); });
  });

  var alpha = 1;

  function tick() {
    var i, j, a, b, dx, dy, d2, d, f;
    for (i = 0; i < nodes.length; i++) {
      for (j = i + 1; j < nodes.length; j++) {
        a = nodes[i]; b = nodes[j];
        dx = b.x - a.x; dy = b.y - a.y;
        d2 = dx * dx + dy * dy + 0.01;
        d = Math.sqrt(d2);
        f = 1400 / d2;
        a.vx -= (dx / d) * f; a.vy -= (dy / d) * f;
        b.vx += (dx / d) * f; b.vy += (dy / d) * f;
      }
    }
    links.forEach(function (l) {
      dx = l.t.x - l.s.x; dy = l.t.y - l.s.y;
      d = Math.sqrt(dx * dx + dy * dy) + 0.01;
      f = (d - 70) * 0.02;
      l.s.vx += (dx / d) * f; l.s.vy += (dy / d) * f;
      l.t.vx -= (dx / d) * f; l.t.vy -= (dy / d) * f;
    });
    nodes.forEach(function (n) {
      n.vx -= n.x * 0.004; n.vy -= n.y * 0.004;
      if (!n.fixed) { n.x += n.vx * alpha; n.y += n.vy * alpha; }
      n.vx *= 0.82; n.vy *= 0.82;
    });
    alpha = Math.max(alpha * 0.992, 0.03);
    draw();
  }

  function draw() {
    nodes.forEach(function (n) {
      n.el.setAttribute("cx", n.x); n.el.setAttribute("cy", n.y);
      n.txt.setAttribute("x", n.x); n.txt.setAttribute("y", n.y);
    });
    links.forEach(function (l) {
      l.el.setAttribute("x1", l.s.x); l.el.setAttribute("y1", l.s.y);
      l.el.setAttribute("x2", l.t.x); l.el.setAttribute("y2", l.t.y);
    });
  }

  var scale = 1, panX = 0, panY = 0;

  function applyView() {
    view.setAttribute("transform", "translate(" + panX + "," + panY + ") scale(" + scale + ")");
  }
  function centre() {
    panX = svg.clientWidth / 2; panY = svg.clientHeight / 2; applyView();
  }
  centre();
  window.addEventListener("resize", centre);

  svg.addEventListener("wheel", function (ev) {
    ev.preventDefault();
    var rect = svg.getBoundingClientRect();
    var mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
    var factor = ev.deltaY < 0 ? 1.15 : 1 / 1.15;
    var next = Math.min(6, Math.max(0.15, scale * factor));
    panX = mx - (mx - panX) * (next / scale);
    panY = my - (my - panY) * (next / scale);
    scale = next;
    applyView();
  }, { passive: false });

  var drag = null;

  svg.addEventListener("mousedown", function (ev) {
    if (ev.target !== svg) return;
    drag = { pan: true, x: ev.clientX, y: ev.clientY };
    svg.classList.add("panning");
  });

  function startDrag(ev, n) {
    ev.stopPropagation();
    drag = { node: n, moved: false };
    n.fixed = true;
  }

  window.addEventListener("mousemove", function (ev) {
    if (!drag) return;
    if (drag.pan) {
      panX += ev.clientX - drag.x; panY += ev.clientY - drag.y;
      drag.x = ev.clientX; drag.y = ev.clientY;
      applyView();
    } else {
      var rect = svg.getBoundingClientRect();
      drag.node.x = (ev.clientX - rect.left - panX) / scale;
      drag.node.y = (ev.clientY - rect.top - panY) / scale;
      drag.moved = true;
      alpha = Math.max(alpha, 0.3);
      draw();
    }
  });

  window.addEventListener("mouseup", function () {
    if (drag && drag.node) {
      if (!drag.moved) select(drag.node);
      drag.node.fixed = false;
    }
    drag = null;
    svg.classList.remove("panning");
  });

  var selected = null;

  function esc(text) {
    return String(text).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function listEdges(items, other) {
    if (!items.length) return '<p class="muted">none</p>';
    return "<ul>" + items.map(function (l) {
      var o = other(l);
      return "<li>" + esc(l.e.kind) + " " + esc(o.label) +
        (l.e.status === "resolved" ? "" : ' <span class="muted">(' + esc(l.e.status) + ")</span>") + "</li>";
    }).join("") + "</ul>";
  }

  function select(n) {
    selected = n;
    nodes.forEach(function (m) { m.el.classList.toggle("sel", m === n); });
    var near = {};
    near[n.id] = true;
    links.forEach(function (l) {
      var hot = l.s === n || l.t === n;
      l.el.classList.toggle("hot", hot);
      l.el.classList.toggle("dim", !hot);
      if (hot) { near[l.s.id] = true; near[l.t.id] = true; }
    });
    nodes.forEach(function (m) { m.txt.classList.toggle("dim", !near[m.id]); });
    var info = n.info || {};
    var out = links.filter(function (l) { return l.s === n; });
    var inc = links.filter(function (l) { return l.t === n; });
    panel.innerHTML =
      "<h2>" + esc(n.hollow ? n.label : n.id) + "</h2>" +
      "<p>kind: " + esc(n.hollow ? "not found" : n.kind) + "<br>" +
      "package: " + esc(info.package || "none") + "<br>" +
      "symbols: " + esc(info.symbol_count == null ? 0 : info.symbol_count) + "</p>" +
      "<b>Outgoing (" + out.length + ")</b>" + listEdges(out, function (l) { return l.t; }) +
      "<b>Incoming (" + inc.length + ")</b>" + listEdges(inc, function (l) { return l.s; });
  }

  svg.addEventListener("click", function (ev) {
    if (ev.target !== svg || !selected) return;
    selected = null;
    nodes.forEach(function (m) { m.el.classList.remove("sel"); m.txt.classList.remove("dim"); });
    links.forEach(function (l) { l.el.classList.remove("hot", "dim"); });
  });

  (function loop() { tick(); requestAnimationFrame(loop); })();
})();
</script>
</body>
</html>
"""


def _title(data):
    return "XRAY: " + Path(data["root"]).name


def _escape(text):
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def render_html(data):
    """Return one self-contained HTML page that draws a graph.

    data is the result of graphjson.graph_data. It is embedded as JSON
    with "<" escaped, so no path can close the script tag. The page
    loads nothing from the network.
    """

    payload = (
        json.dumps(data, sort_keys=True)
        .replace("<", "\\u003c")
        .replace("&", "\\u0026")
    )

    return _TEMPLATE.replace("__TITLE__", _escape(_title(data))).replace(
        "__DATA__", payload
    )
