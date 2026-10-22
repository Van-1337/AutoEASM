/* Interactive scan flowchart, styled after the AutoEASM drawio diagram.
   Hover a block to light every node and arrow on a path that reaches it and
   dim the rest. Zoom controls and fit-to-view are in the toolbar. */
(function () {
    'use strict';

    var NS = 'http://www.w3.org/2000/svg';
    var DATA_LABELS = ['Found sites', 'Hosts with WAF', 'Hosts without WAF', 'Crawled links',
        'JS links', 'Links on hosts with WAF', 'Links on hosts without WAF', 'Dependency check'];

    var STYLE = {
        process: { fill: '#ffffff', stroke: '#475569', text: '#1e293b' },
        data: { fill: '#f9feff', stroke: '#22a6b8', text: '#164e63' },
        data_waf: { fill: '#1599e8', stroke: '#0878bd', text: '#ffffff' },
        data_green: { fill: '#31a95b', stroke: '#168044', text: '#ffffff' },
        decision: { fill: '#a3a3a3', stroke: '#616161', text: '#111827' },
        report: { fill: '#31a95b', stroke: '#168044', text: '#ffffff' },
        bigreport: { fill: '#249449', stroke: '#147437', text: '#ffffff' },
        start: { fill: '#16b8a6', stroke: '#0d8276', text: '#042f2e' },
        sink: { fill: '#f4a30a', stroke: '#b66d00', text: '#3a2300' }
    };

    function el(name, attrs) {
        var node = document.createElementNS(NS, name);
        Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
        return node;
    }

    function norm(label) {
        return (label || '')
            .replace(/\u00a0/g, ' ')
            .replace('ROOTDOMAINS', 'ROOT DOMAINS')
            .replace('Subdomainstakeover', 'Subdomain takeover')
            .replace('Hidden hostssearch', 'Hidden hosts search')
            .replace('hostswith', 'hosts with')
            .replace('hostswithout', 'hosts without')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function displayLabel(label) {
        var text = norm(label);
        return text
            .replace('ROOT DOMAINS', 'ROOT\nDOMAINS')
            .replace('Subdomain takeover scan', 'Subdomain\ntakeover scan')
            .replace('Hidden hosts search', 'Hidden hosts\nsearch')
            .replace('Links on hosts with WAF', 'Links on hosts\nwith WAF')
            .replace('Links on hosts without WAF', 'Links on hosts\nwithout WAF')
            .replace('Hosts without WAF', 'Hosts without\nWAF')
            .replace('Hosts with WAF', 'Hosts with\nWAF')
            .replace('Nuclei default scan', 'Nuclei default\nscan')
            .replace('Nuclei config scan', 'Nuclei config\nscan')
            .replace('Nuclei tokens scan', 'Nuclei tokens\nscan')
            .replace('Nuclei DAST scan', 'Nuclei DAST\nscan')
            .replace('Dependency check', 'Dependency\ncheck')
            .replace('Social links check', 'Social links\ncheck');
    }

    function kindOf(node) {
        var label = norm(node.label);
        if (label === 'Start') { return 'start'; }
        if (label === 'Burp Suite') { return 'sink'; }
        if (label === 'Full report') { return 'bigreport'; }
        if (label === 'Report') { return 'report'; }
        if (node.kind === 'decision') { return 'decision'; }
        if (label === 'Hosts with WAF') { return 'data_waf'; }
        if (label === 'Hosts without WAF') { return 'data_green'; }
        if (DATA_LABELS.indexOf(label) >= 0) { return 'data'; }
        return 'process';
    }

    function center(node) { return [node.x + node.w / 2, node.y + node.h / 2]; }

    function sideAnchor(node, toward) {
        var c = center(node), t = center(toward);
        if (Math.abs(t[0] - c[0]) >= Math.abs(t[1] - c[1])) {
            return t[0] >= c[0] ? [node.x + node.w, c[1]] : [node.x, c[1]];
        }
        return t[1] >= c[1] ? [c[0], node.y + node.h] : [c[0], node.y];
    }

    function fracAnchor(node, frac, toward) {
        if (frac && frac[0] != null && frac[1] != null) {
            return [node.x + node.w * frac[0], node.y + node.h * frac[1]];
        }
        return sideAnchor(node, toward);
    }

    function sideFromFraction(fraction) {
        if (!fraction || fraction[0] == null || fraction[1] == null) { return ''; }
        if (fraction[0] <= 0.02) { return 'left'; }
        if (fraction[0] >= 0.98) { return 'right'; }
        if (fraction[1] <= 0.02) { return 'top'; }
        if (fraction[1] >= 0.98) { return 'bottom'; }
        return '';
    }

    function addOrthogonalLeg(points, point, side, isEnd) {
        var previous = points[points.length - 1];
        if (previous[0] === point[0] || previous[1] === point[1]) {
            points.push(point);
            return;
        }
        var bridge;
        if (side === 'left' || side === 'right') {
            bridge = isEnd ? [previous[0], point[1]] : [point[0], previous[1]];
        } else {
            bridge = isEnd ? [point[0], previous[1]] : [previous[0], point[1]];
        }
        points.push(bridge, point);
    }

    function routePoints(edge, byId) {
        var source = byId[edge.source];
        var target = byId[edge.target];
        var start = fracAnchor(source, edge.exit, target);
        var end = fracAnchor(target, edge.entry, source);
        var sourceSide = sideFromFraction(edge.exit);
        var targetSide = sideFromFraction(edge.entry);
        var waypoints = edge.points || [];

        if (waypoints.length) {
            var routed = [start];
            addOrthogonalLeg(routed, waypoints[0], sourceSide, false);
            for (var i = 1; i < waypoints.length; i += 1) {
                addOrthogonalLeg(routed, waypoints[i], '', false);
            }
            addOrthogonalLeg(routed, end, targetSide, true);
            return routed;
        }

        if (start[0] === end[0] || start[1] === end[1]) { return [start, end]; }

        var horizontal = sourceSide === 'left' || sourceSide === 'right';
        var targetHorizontal = targetSide === 'left' || targetSide === 'right';
        if (horizontal && targetHorizontal) {
            var midX = (start[0] + end[0]) / 2;
            return [start, [midX, start[1]], [midX, end[1]], end];
        }
        if (!horizontal && !targetHorizontal) {
            var midY = (start[1] + end[1]) / 2;
            return [start, [start[0], midY], [end[0], midY], end];
        }
        if (horizontal) { return [start, [end[0], start[1]], end]; }
        return [start, [start[0], end[1]], end];
    }

    function gearGlyph(node) {
        var group = el('g', { class: 'flow-gear' });
        var cx = node.x + 17;
        var cy = node.y + node.h / 2;
        group.appendChild(el('circle', { cx: cx, cy: cy, r: 11, fill: '#f6c84c', stroke: '#d79b00', 'stroke-width': 1 }));
        var glyph = el('text', {
            x: cx, y: cy + 0.5,
            'text-anchor': 'middle', 'dominant-baseline': 'central',
            'font-size': 13, fill: '#8a5a12'
        });
        glyph.textContent = '\u2699';
        group.appendChild(glyph);
        return group;
    }

    function shape(node, kind) {
        if (kind === 'decision') {
            var c = center(node);
            return el('polygon', {
                points: [c[0], node.y, node.x + node.w, c[1], c[0], node.y + node.h, node.x, c[1]].join(' ')
            });
        }
        if (kind === 'start') {
            return el('ellipse', { cx: node.x + node.w / 2, cy: node.y + node.h / 2, rx: node.w / 2, ry: node.h / 2 });
        }
        return el('rect', {
            x: node.x, y: node.y, width: node.w, height: node.h,
            rx: kind === 'report' ? node.h / 2 : 9, ry: kind === 'report' ? node.h / 2 : 9
        });
    }

    function labelText(node, kind, color) {
        var hasGear = kind === 'process';
        var cx = node.x + node.w / 2 + (hasGear ? 8 : 0);
        var text = el('text', { x: cx, y: node.y + node.h / 2, 'text-anchor': 'middle', 'dominant-baseline': 'central', fill: color });
        var lines = displayLabel(node.label).split('\n');
        var size = node.w < 110 || lines.length > 2 ? 12 : (kind === 'bigreport' ? 18 : 14);
        text.setAttribute('font-size', size);
        text.setAttribute('font-weight', kind === 'data' || kind === 'data_waf' || kind === 'data_green' ? 700 : 600);
        var top = -((lines.length - 1) * size) / 2;
        lines.forEach(function (line, index) {
            var span = el('tspan', { x: cx, dy: index === 0 ? top : size });
            span.textContent = line;
            text.appendChild(span);
        });
        return text;
    }

    function ancestors(id, incoming) {
        var seen = {};
        var stack = [id];
        while (stack.length) {
            var current = stack.pop();
            if (seen[current]) { continue; }
            seen[current] = true;
            (incoming[current] || []).forEach(function (parent) { stack.push(parent); });
        }
        return seen;
    }

    var api = {
        fit: function () {},
        zoomIn: function () {},
        zoomOut: function () {}
    };

    function render(data, stage) {
        var nodes = data.nodes.map(function (n) { return Object.assign({}, n); });
        var edges = data.edges.map(function (edge) {
            return Object.assign({}, edge, { points: (edge.points || []).slice() });
        });
        var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        nodes.forEach(function (n) {
            minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
            maxX = Math.max(maxX, n.x + n.w); maxY = Math.max(maxY, n.y + n.h);
        });
        var pad = 40;
        var shift = function (p) { return [p[0] - minX + pad, p[1] - minY + pad]; };
        nodes.forEach(function (n) { n.x += pad - minX; n.y += pad - minY; });
        var baseW = maxX - minX + pad * 2;
        var baseH = maxY - minY + pad * 2;
        edges.forEach(function (edge) {
            edge.points = (edge.points || []).map(shift);
        });

        var byId = {};
        nodes.forEach(function (n) { byId[n.id] = n; });
        var fullReport = nodes.find(function (node) { return norm(node.label) === 'Full report'; });
        var reportNodes = nodes.filter(function (node) { return norm(node.label) === 'Report'; });
        var canvasH = baseH;
        var reportCollector = null;

        /* The original flowchart has multiple intermediate REPORT sinks. In the
           UI all of them feed one shared visual collector so Full report is the
           actual destination of every branch, including hover-path traversal. */
        if (fullReport && reportNodes.length) {
            /* Supersede any legacy direct report->Full report line. All report
               outputs are drawn consistently through the shared collector. */
            edges = edges.filter(function (edge) {
                return !(edge.target === fullReport.id && byId[edge.source] && norm(byId[edge.source].label) === 'Report');
            });
            reportCollector = {
                x: fullReport.x + fullReport.w / 2,
                y: baseH + 34,
                fullId: fullReport.id,
                reports: reportNodes
            };
            reportNodes.forEach(function (node) {
                edges.push({
                    id: 'report-collector-' + node.id,
                    source: node.id,
                    target: fullReport.id,
                    green: true,
                    aggregate: true,
                    exit: [0.5, 1],
                    entry: [0.5, 1],
                    points: []
                });
            });
            canvasH = reportCollector.y + 34;
        }

        var incoming = {};
        edges.forEach(function (e) { (incoming[e.target] = incoming[e.target] || []).push(e.source); });

        var svg = el('svg', {
            class: 'flow-svg',
            viewBox: '0 0 ' + baseW + ' ' + canvasH,
            preserveAspectRatio: 'xMidYMid meet',
            role: 'img',
            'aria-label': 'AutoEASM scan flowchart'
        });
        var defs = el('defs', {});
        defs.innerHTML =
            '<marker id="flow-arrow" markerWidth="9" markerHeight="9" refX="7.5" refY="3" orient="auto">' +
            '<path d="M0,0 L7,3 L0,6 Z" fill="#475569"/></marker>' +
            '<marker id="flow-arrow-lit" markerWidth="9" markerHeight="9" refX="7.5" refY="3" orient="auto">' +
            '<path d="M0,0 L7,3 L0,6 Z" fill="#0284c7"/></marker>' +
            '<marker id="flow-arrow-green" markerWidth="10" markerHeight="10" refX="8" refY="3.5" orient="auto">' +
            '<path d="M0,0 L8,3.5 L0,7 Z" fill="#22a34a"/></marker>';
        svg.appendChild(defs);
        var edgeLayer = el('g', {});
        var nodeLayer = el('g', {});
        svg.appendChild(edgeLayer);
        svg.appendChild(nodeLayer);

        edges.forEach(function (edge) {
            if (!byId[edge.source] || !byId[edge.target]) { return; }
            if (edge.aggregate) { return; }
            var pts = routePoints({
                source: edge.source, target: edge.target, exit: edge.exit, entry: edge.entry,
                points: edge.points || []
            }, byId);
            var line = el('polyline', {
                points: pts.map(function (p) { return p[0] + ',' + p[1]; }).join(' '),
                class: 'edge' + (edge.green ? ' edge-green' : ''),
                'data-source': edge.source,
                'data-target': edge.target,
                'data-aggregate': 'false'
            });
            if (!edge.green) {
                line.setAttribute('marker-end', 'url(#flow-arrow)');
            }
            edgeLayer.appendChild(line);
        });

        if (reportCollector) {
            reportCollector.reports.forEach(function (node) {
                var sourceX = node.x + node.w / 2;
                var sourceY = node.y + node.h;
                var contribution = el('polyline', {
                    points: [sourceX + ',' + sourceY, sourceX + ',' + reportCollector.y,
                        reportCollector.x + ',' + reportCollector.y].join(' '),
                    class: 'edge edge-green edge-aggregate',
                    'data-source': node.id,
                    'data-target': reportCollector.fullId,
                    'data-aggregate': 'true'
                });
                edgeLayer.appendChild(contribution);
            });
            var trunk = el('polyline', {
                points: [reportCollector.x + ',' + reportCollector.y,
                    reportCollector.x + ',' + (fullReport.y + fullReport.h)].join(' '),
                class: 'edge edge-green edge-aggregate edge-aggregate-trunk',
                'data-source': '__report_collector__',
                'data-target': reportCollector.fullId,
                'data-aggregate': 'true',
                'data-trunk': 'true',
                'marker-end': 'url(#flow-arrow-green)'
            });
            edgeLayer.appendChild(trunk);
        }

        nodes.forEach(function (node) {
            var kind = kindOf(node);
            var color = STYLE[kind] || STYLE.process;
            var group = el('g', { class: 'node node-' + kind, 'data-id': node.id, tabindex: '0' });
            var body = shape(node, kind);
            body.setAttribute('fill', color.fill);
            body.setAttribute('stroke', color.stroke);
            body.setAttribute('stroke-width', 2);
            group.appendChild(body);
            if (kind === 'process') { group.appendChild(gearGlyph(node)); }
            group.appendChild(labelText(node, kind, color.text));
            group.addEventListener('mouseenter', function () { focus(node.id); });
            group.addEventListener('focus', function () { focus(node.id); });
            group.addEventListener('mouseleave', clear);
            group.addEventListener('blur', clear);
            nodeLayer.appendChild(group);
        });

        function focus(id) {
            var keep = ancestors(id, incoming);
            svg.classList.add('is-dim');
            svg.querySelectorAll('.node').forEach(function (n) { n.classList.toggle('lit', !!keep[n.getAttribute('data-id')]); });
            svg.querySelectorAll('.edge').forEach(function (e) {
                var on = e.getAttribute('data-trunk') === 'true'
                    ? id === fullReport.id
                    : keep[e.getAttribute('data-source')] && keep[e.getAttribute('data-target')];
                e.classList.toggle('lit', !!on);
                if (e.getAttribute('data-aggregate') === 'true') {
                    e.setAttribute('marker-end', 'url(#flow-arrow-green)');
                } else if (!e.classList.contains('edge-green')) {
                    e.setAttribute('marker-end', on ? 'url(#flow-arrow-lit)' : 'url(#flow-arrow)');
                }
            });
        }
        function clear() {
            svg.classList.remove('is-dim');
            svg.querySelectorAll('.lit').forEach(function (n) { n.classList.remove('lit'); });
            svg.querySelectorAll('.edge:not(.edge-green)').forEach(function (e) { e.setAttribute('marker-end', 'url(#flow-arrow)'); });
        }

        stage.innerHTML = '';
        stage.appendChild(svg);

        var zoom = 1;
        var valEl = document.getElementById('flow-zoom-val');
        function applyZoom() {
            svg.style.width = Math.round(baseW * zoom) + 'px';
            svg.style.height = Math.round(canvasH * zoom) + 'px';
            if (valEl) { valEl.textContent = Math.round(zoom * 100) + '%'; }
        }
        function setZoom(z) { zoom = Math.max(0.2, Math.min(4, z)); applyZoom(); }
        api.fit = function () {
            var availW = Math.max(1, stage.clientWidth - 28);
            var availH = Math.max(1, stage.clientHeight - 28);
            setZoom(Math.min(1, availW / baseW, availH / canvasH));
            stage.scrollLeft = 0;
            stage.scrollTop = 0;
        };
        api.zoomIn = function () { setZoom(zoom * 1.25); };
        api.zoomOut = function () { setZoom(zoom / 1.25); };
        requestAnimationFrame(function () {
            if (stage.clientWidth > 0 && stage.clientHeight > 0) { api.fit(); }
        });

        stage.addEventListener('wheel', function (event) {
            event.preventDefault();
            setZoom(zoom * (event.deltaY < 0 ? 1.12 : 1 / 1.12));
        }, { passive: false });
    }

    document.addEventListener('DOMContentLoaded', function () {
        var stage = document.getElementById('flow-stage');
        if (!stage) { return; }
        var ready = false;
        fetch('/static/flow.json')
            .then(function (r) { return r.json(); })
            .then(function (data) { render(data, stage); ready = true; })
            .catch(function () { stage.textContent = 'Flowchart could not be loaded.'; });

        var inBtn = document.getElementById('flow-zoom-in');
        var outBtn = document.getElementById('flow-zoom-out');
        var fitBtn = document.getElementById('flow-zoom-fit');
        if (inBtn) { inBtn.addEventListener('click', function () { api.zoomIn(); }); }
        if (outBtn) { outBtn.addEventListener('click', function () { api.zoomOut(); }); }
        if (fitBtn) { fitBtn.addEventListener('click', function () { api.fit(); }); }

        document.addEventListener('autoeasm-flow-shown', function () {
            requestAnimationFrame(function () {
                if (ready) {
                    api.fit();
                } else {
                    setTimeout(function () { api.fit(); }, 300);
                }
            });
        });
    });
})();
