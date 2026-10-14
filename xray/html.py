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
  line.cyc { stroke: #e5484d; stroke-width: 2; }
  circle.cyc { stroke: #e5484d; stroke-width: 3.5; }
  line.path { stroke: #4dd0e1; stroke-width: 2.6; opacity: 1; }
  circle.imp1 { stroke: #ff8c42; stroke-width: 4; }
  circle.imp2 { stroke: #ffc999; stroke-width: 3.5; }
  line.imp { stroke: #ff8c42; stroke-width: 1.8; opacity: 1; }
  circle.path { stroke: #4dd0e1; stroke-width: 3.5; }
  #controls button { margin-top: 6px; background: #12151c; color: #dde3ee;
              border: 1px solid #2c3446; padding: 3px 8px; border-radius: 3px;
              cursor: pointer; }
  #hint { margin-top: 6px; max-width: 230px; color: #8a94a8; }
  line.open { stroke-dasharray: 3 3; }
  circle { stroke: #0c0e13; stroke-width: 1.5; cursor: pointer; }
  circle.hollow { fill: none !important; stroke: #c3cbdb; stroke-width: 2; }
  circle.gone, text.gone, line.gone { display: none; }
  circle.nomatch { opacity: 0.15; }
  text.nomatch { opacity: 0.1; }
  #controls { position: absolute; top: 8px; right: 8px; padding: 8px;
              background: #1a1f2bcc; border-radius: 4px; font-size: 12px; }
  #controls input[type=text] { width: 170px; margin-bottom: 6px;
              background: #12151c; color: #dde3ee; border: 1px solid #2c3446;
              padding: 4px; border-radius: 3px; }
  #controls label { margin-right: 8px; white-space: nowrap; }
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
  <div id="controls">
    <input id="search" type="text" placeholder="Search names" autocomplete="off"><br>
    <label><input type="checkbox" data-kind="python" checked> python</label>
    <label><input type="checkbox" data-kind="shell" checked> shell</label>
    <label><input type="checkbox" data-kind="elf" checked> elf</label>
    <label><input type="checkbox" data-kind="library" checked> library</label>
    <label><input type="checkbox" data-kind="function" checked> function</label>
    <label><input type="checkbox" data-kind="import" checked> import</label><br>
    <button id="cycles" type="button">Highlight cycles</button>
    <button id="impact" type="button">Show impact</button>
    <div id="hint">Shift-click a node to trace the shortest path from the selected one.</div>
  </div>
</div>
<div id="panel"><h2>__TITLE__</h2><p class="muted">Click a node to inspect it. Scroll to zoom, drag the background to pan.</p></div>
<script id="graph-data" type="application/json">__DATA__</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById("graph-data").textContent);
  var COLORS = { python: "#4b8bbe", shell: "#6cc070", elf: "#e07a5f",
                 library: "#a78bfa", function: "#f4b942", import: "#7ad1c2",
                 unknown: "#8a94a8" };
  var NS = "http://www.w3.org/2000/svg";
  var svg = document.getElementById("svg");
  var view = document.getElementById("view");
  var panel = document.getElementById("panel");

  if (data.metadata.truncated) document.getElementById("notice").hidden = false;

  var legend = document.getElementById("legend");
  Object.keys(COLORS).slice(0, 6).forEach(function (kind) {
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

  window.addEventListener("mouseup", function (ev) {
    if (drag && drag.node) {
      if (!drag.moved) {
        if (ev.shiftKey && selected && selected !== drag.node) showPath(selected, drag.node);
        else select(drag.node);
      }
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

  function reach(n, forward) {
    var seen = {};
    seen[n.id] = 0;
    var queue = [n];
    while (queue.length) {
      var v = queue.shift();
      links.forEach(function (l) {
        var w = forward ? (l.s === v ? l.t : null) : (l.t === v ? l.s : null);
        if (w && seen[w.id] === undefined) { seen[w.id] = seen[v.id] + 1; queue.push(w); }
      });
    }
    var direct = 0, total = 0;
    Object.keys(seen).forEach(function (k) {
      if (k === n.id) return;
      total++;
      if (seen[k] === 1) direct++;
    });
    return { direct: direct, total: total };
  }

  function cycleOf(n) {
    var groups = components();
    for (var i = 0; i < groups.length; i++) {
      if (groups[i].indexOf(n) !== -1) return groups[i];
    }
    return null;
  }

  function summary(n) {
    var fwd = reach(n, true), back = reach(n, false), cyc = cycleOf(n);
    var cycleText = cyc
      ? "in a cycle with " + cyc.filter(function (m) { return m !== n; })
          .map(function (m) { return esc(m.label); }).join(", ")
      : "none";
    return "<p>Reaches: " + fwd.total + " file(s) (" + fwd.direct + " direct)<br>" +
      "Affected if changed: " + back.total + " file(s) (" + back.direct + " direct)<br>" +
      "Cycles: " + cycleText + "</p>";
  }

  function select(n) {
    selected = n;
    clearPath();
    if (typeof clearImpact === "function") clearImpact();
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
      summary(n) +
      "<b>Outgoing (" + out.length + ")</b>" + listEdges(out, function (l) { return l.t; }) +
      "<b>Incoming (" + inc.length + ")</b>" + listEdges(inc, function (l) { return l.s; });
  }

  svg.addEventListener("click", function (ev) {
    if (ev.target !== svg || !selected) return;
    selected = null;
    nodes.forEach(function (m) { m.el.classList.remove("sel"); m.txt.classList.remove("dim"); });
    links.forEach(function (l) { l.el.classList.remove("hot", "dim"); });
  });

__SERVE__
  var searchBox = document.getElementById("search");
  var kindBoxes = document.querySelectorAll("#controls input[data-kind]");

  function visibleKinds() {
    var on = {};
    Array.prototype.forEach.call(kindBoxes, function (box) {
      if (box.checked) on[box.getAttribute("data-kind")] = true;
    });
    return on;
  }

  function shown(n, on) { return n.hollow || on[n.kind] === true; }

  function matches(n, term) {
    return !term || (n.label + " " + n.id).toLowerCase().indexOf(term) !== -1;
  }

  function applyControls() {
    var on = visibleKinds();
    var term = searchBox.value.trim().toLowerCase();
    nodes.forEach(function (n) {
      var show = shown(n, on);
      var hit = matches(n, term);
      n.el.classList.toggle("gone", !show);
      n.txt.classList.toggle("gone", !show);
      n.el.classList.toggle("nomatch", show && !hit);
      n.txt.classList.toggle("nomatch", show && !hit);
    });
    links.forEach(function (l) {
      l.el.classList.toggle("gone", !(shown(l.s, on) && shown(l.t, on)));
    });
  }

  searchBox.addEventListener("input", applyControls);
  searchBox.addEventListener("keydown", function (ev) {
    if (ev.key !== "Enter") return;
    var on = visibleKinds();
    var term = searchBox.value.trim().toLowerCase();
    var first = nodes.filter(function (n) { return shown(n, on) && matches(n, term); })[0];
    if (term && first) select(first);
  });
  Array.prototype.forEach.call(kindBoxes, function (box) {
    box.addEventListener("change", applyControls);
  });

  var cycleBtn = document.getElementById("cycles");
  var cycleOn = false;

  function clearPath() {
    nodes.forEach(function (n) { n.el.classList.remove("path"); });
    links.forEach(function (l) { l.el.classList.remove("path"); });
  }

  function components() {
    var index = 0, stack = [], out = [];
    nodes.forEach(function (n) { n.idx = -1; n.low = 0; n.onst = false; });
    function visit(v) {
      v.idx = index; v.low = index; index++;
      stack.push(v); v.onst = true;
      links.forEach(function (l) {
        if (l.s !== v) return;
        var w = l.t;
        if (w.idx === -1) { visit(w); v.low = Math.min(v.low, w.low); }
        else if (w.onst) v.low = Math.min(v.low, w.idx);
      });
      if (v.low === v.idx) {
        var comp = [], w;
        do { w = stack.pop(); w.onst = false; comp.push(w); } while (w !== v);
        out.push(comp);
      }
    }
    nodes.forEach(function (n) { if (n.idx === -1) visit(n); });
    return out.filter(function (comp) {
      return comp.length > 1 || links.some(function (l) { return l.s === comp[0] && l.t === comp[0]; });
    });
  }

  function setCycles(on) {
    cycleOn = on;
    nodes.forEach(function (n) { n.el.classList.remove("cyc"); });
    links.forEach(function (l) { l.el.classList.remove("cyc"); });
    cycleBtn.textContent = on ? "Clear cycles" : "Highlight cycles";
    if (!on) return [];
    var groups = components();
    var member = {};
    groups.forEach(function (g, i) {
      g.forEach(function (n) { member[n.id] = i; n.el.classList.add("cyc"); });
    });
    links.forEach(function (l) {
      l.el.classList.remove("dim");
      if (member[l.s.id] !== undefined && member[l.s.id] === member[l.t.id]) l.el.classList.add("cyc");
    });
    return groups;
  }

  cycleBtn.addEventListener("click", function () {
    var groups = setCycles(!cycleOn);
    if (!cycleOn) return;
    if (!groups.length) {
      panel.innerHTML = "<h2>Cycles</h2><p>No cycles found in this graph.</p>";
      return;
    }
    panel.innerHTML = "<h2>Cycles</h2><p>" + groups.length + " cycle group(s) found:</p>" +
      groups.map(function (g) {
        return "<p>" + g.map(function (n) { return esc(n.label); }).join(" &harr; ") + "</p>";
      }).join("");
  });

  function findPath(a, b, directed) {
    var prev = {}, seen = {}, queue = [a];
    seen[a.id] = true;
    while (queue.length) {
      var v = queue.shift();
      if (v === b) break;
      links.forEach(function (l) {
        var w = null;
        if (l.s === v) w = l.t;
        else if (!directed && l.t === v) w = l.s;
        if (w && !seen[w.id]) { seen[w.id] = true; prev[w.id] = { from: v, link: l }; queue.push(w); }
      });
    }
    if (!seen[b.id]) return null;
    var steps = [], cur = b;
    while (cur !== a) { var p = prev[cur.id]; steps.unshift(p.link); cur = p.from; }
    return steps;
  }

  function showPath(a, b) {
    clearPath();
    var directed = true;
    var steps = findPath(a, b, true);
    if (!steps) { directed = false; steps = findPath(a, b, false); }
    if (!steps) {
      panel.innerHTML = "<h2>No path</h2><p>No path between " + esc(a.label) + " and " + esc(b.label) + ".</p>";
      return;
    }
    links.forEach(function (l) { l.el.classList.remove("hot", "dim"); });
    nodes.forEach(function (m) { m.txt.classList.remove("dim"); });
    a.el.classList.add("path"); b.el.classList.add("path");
    steps.forEach(function (l) {
      l.el.classList.add("path"); l.s.el.classList.add("path"); l.t.el.classList.add("path");
    });
    panel.innerHTML = "<h2>Path: " + esc(a.label) + " to " + esc(b.label) + "</h2><p>" +
      steps.length + " step(s)" + (directed ? "" : ", ignoring edge direction") + "</p><ul>" +
      steps.map(function (l) {
        return "<li>" + esc(l.s.label) + " " + esc(l.e.kind) + " " + esc(l.t.label) + "</li>";
      }).join("") + "</ul>";
  }

  var impactBtn = document.getElementById("impact");
  var impactOn = false;

  function clearImpact() {
    impactOn = false;
    impactBtn.textContent = "Show impact";
    nodes.forEach(function (n) { n.el.classList.remove("imp1", "imp2"); });
    links.forEach(function (l) { l.el.classList.remove("imp"); });
  }

  impactBtn.addEventListener("click", function () {
    if (impactOn) { clearImpact(); return; }
    if (!selected) {
      panel.innerHTML = "<h2>Impact</h2><p>Select a node first, then press Show impact.</p>";
      return;
    }
    var depth = {};
    depth[selected.id] = 0;
    var queue = [selected];
    while (queue.length) {
      var v = queue.shift();
      links.forEach(function (l) {
        if (l.t === v && depth[l.s.id] === undefined) {
          depth[l.s.id] = depth[v.id] + 1;
          queue.push(l.s);
        }
      });
    }
    var direct = [], indirect = [];
    nodes.forEach(function (n) {
      if (n === selected || depth[n.id] === undefined) return;
      if (depth[n.id] === 1) { direct.push(n); n.el.classList.add("imp1"); }
      else { indirect.push(n); n.el.classList.add("imp2"); }
    });
    links.forEach(function (l) {
      l.el.classList.remove("dim");
      if (depth[l.s.id] !== undefined && depth[l.t.id] !== undefined &&
          depth[l.s.id] === depth[l.t.id] + 1) l.el.classList.add("imp");
    });
    impactOn = true;
    impactBtn.textContent = "Clear impact";
    function names(list) {
      return list.length ? "<ul>" + list.map(function (n) { return "<li>" + esc(n.label) + "</li>"; }).join("") + "</ul>" : '<p class="muted">none</p>';
    }
    panel.innerHTML = "<h2>Impact of " + esc(selected.label) + "</h2><p>" +
      (direct.length + indirect.length) + " file(s) would be affected.</p>" +
      "<b>Directly (" + direct.length + ")</b>" + names(direct) +
      "<b>Indirectly (" + indirect.length + ")</b>" + names(indirect);
  });

  (function loop() { tick(); requestAnimationFrame(loop); })();
})();
</script>
</body>
</html>
"""


_SERVE_JS = r'''
  var base_select = select;
  select = function (n) {
    base_select(n);
    if (n.id === data.root) {
      var rbox = document.createElement("div");
      rbox.innerHTML = '<p><button id="b-files" type="button">Show source files</button></p>' +
        '<div id="b-list"></div><pre id="b-out" style="white-space:pre-wrap;font-size:11px"></pre>';
      panel.appendChild(rbox);
      document.getElementById("b-files").addEventListener("click", function () {
        var list = document.getElementById("b-list");
        list.textContent = "Loading...";
        fetch("/api/files").then(function (r) { return r.json(); }).then(function (d) {
          list.textContent = "";
          if (d.error) { list.textContent = d.error; return; }
          Object.keys(d.files).forEach(function (f) {
            var b = document.createElement("button");
            b.type = "button"; b.style.display = "block";
            b.textContent = f + " (" + d.files[f] + ")";
            b.addEventListener("click", function () {
              var out = document.getElementById("b-out");
              out.textContent = "Loading...";
              fetch("/api/file?path=" + encodeURIComponent(f))
                .then(function (r) { return r.text(); })
                .then(function (t) { out.textContent = t; });
            });
            list.appendChild(b);
          });
        }).catch(function () { list.textContent = "Request failed"; });
      });
      return;
    }
    if (n.kind !== "function") return;
    var name = n.id.slice(n.id.lastIndexOf(":") + 1);
    var box = document.createElement("div");
    box.innerHTML = '<p><button id="b-src" type="button">Show source</button> ' +
      '<button id="b-asm" type="button">Show disassembly</button></p>' +
      '<pre id="b-out" style="white-space:pre-wrap;font-size:11px"></pre>';
    panel.appendChild(box);
    function load(kind) {
      var out = document.getElementById("b-out");
      out.textContent = "Loading...";
      fetch("/api/" + kind + "?name=" + encodeURIComponent(name))
        .then(function (r) { return r.text(); })
        .then(function (t) { out.textContent = t; })
        .catch(function () { out.textContent = "Request failed"; });
    }
    document.getElementById("b-src").addEventListener("click", function () { load("source"); });
    document.getElementById("b-asm").addEventListener("click", function () { load("disasm"); });
  };
'''


def _title(data):
    return "XRAY: " + Path(data["root"]).name


def _escape(text):
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def render_html(data, serve=False):
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

    template = _TEMPLATE.replace("__SERVE__", _SERVE_JS if serve else "")

    return template.replace("__TITLE__", _escape(_title(data))).replace(
        "__DATA__", payload
    )
