    fetch("/api/assetmap")
        .then((res) => res.json())
        .then(async (graph) => {
            const edgeColors = {
                dmz_exposed: "#ef4444",
                app_backend: "#3b82f6",
                db_backend: "#10b981",
                admin_on: "#f59e0b",
                local_admin_on: "#6366f1",
                member_of: "#8b5c00",
                interactive_logon: "#14b8a6",
                data_access: "#f43f5e",
            };

            const rawNodes = graph.nodes || [];
            const rawEdges = graph.edges || [];

            const visNodes = rawNodes.map((n) => {
                let color = "#bdbdbd";
                let shape = "dot";
                let size = 18;
                if (n.type === "user") {
                    color = "#9e9e9e";
                    shape = "diamond";
                    size = 16;
                } else if (n.type === "group") {
                    color = "#8b8b8b";
                    shape = "hexagon";
                    size = 20;
                }

                let label = n.name || n.id;
                if (n.type === "host" && n.ip) label += "\n" + n.ip;
                if (n.type === "user" && n.sam_account_name) label += "\n(" + n.sam_account_name + ")";

                return {
                    id: n.id,
                    label,
                    color: { background: color, border: "#111" },
                    shape,
                    size,
                    font: { color: "#111", size: 12, multi: true },
                    raw: n,
                };
            });

            const visEdges = rawEdges.map((e, idx) => ({
                id: "e-" + idx,
                from: e.source,
                to: e.target,
                arrows: "to",
                color: {
                    color: edgeColors[e.relation] || "#999",
                    highlight: edgeColors[e.relation] || "#999",
                    inherit: false,
                },
                width: 2,
                smooth: { type: "dynamic" },
            }));

            const container = document.getElementById("network");
            const data = {
                nodes: new vis.DataSet(visNodes),
                edges: new vis.DataSet(visEdges),
            };

            const options = {
                interaction: { hover: true, navigationButtons: true, keyboard: true },
                physics: { stabilization: true, barnesHut: { gravitationalConstant: -3000, springLength: 150 } },
            };

            const network = new vis.Network(container, data, options);

            // Create an overlay canvas for peripheral decorations (rings, shapes)
            const overlay = document.createElement('canvas');
            overlay.id = 'overlay-canvas';
            overlay.style.position = 'absolute';
            overlay.style.top = '0';
            overlay.style.left = '0';
            overlay.style.width = '100%';
            overlay.style.height = '100%';
            overlay.style.pointerEvents = 'none';
            overlay.style.zIndex = 5; // below legend (9999) but above vis canvas (1)
            container.appendChild(overlay);

            // initialize overlay size immediately
            resizeOverlay();

            function resizeOverlay() {
                const rect = container.getBoundingClientRect();
                overlay.width = rect.width * window.devicePixelRatio;
                overlay.height = rect.height * window.devicePixelRatio;
                overlay.style.width = rect.width + 'px';
                overlay.style.height = rect.height + 'px';
                const ctx = overlay.getContext('2d');
                ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
            }

            // peripheral node ids
            let peripheralNodeIds = new Set();

            function drawPeripherals() {
                const ctx = overlay.getContext('2d');
                if (!ctx) return;
                // clear
                ctx.clearRect(0, 0, overlay.width, overlay.height);
                // debug
                console.debug('Drawing peripherals, count=', peripheralNodeIds.size);
                    // Currently we do not draw a glow/halo for peripherals. The nodes
                    // themselves are colored purple via data node updates. Keep the
                    // overlay canvas present but clear it to avoid any visible glow.
                    peripheralNodeIds.forEach((nid) => {
                        // intentionally no drawing here
                    });
                // overlay kept clear intentionally (peripherals are shown via node color)
            }

            // re-draw on resize and network interactions
            window.addEventListener('resize', () => { resizeOverlay(); drawPeripherals(); });
            network.on('resize', () => { resizeOverlay(); drawPeripherals(); });
            network.on('zoom', () => { drawPeripherals(); });
            network.on('dragEnd', () => { drawPeripherals(); });
            // ensure we draw after layout stabilizes
            network.on('stabilizationIterationsDone', () => { resizeOverlay(); drawPeripherals(); });


            const infoBox = document.getElementById("node-info");

            // Small helper to escape HTML
            function escapeHtml(str) {
                if (str === null || str === undefined) return '';
                return String(str)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            }

            function renderValue(value, indent = 0) {
                const spacing = '&nbsp;'.repeat(indent * 4);
                
                if (value === null || value === undefined) {
                    return `${spacing}<span style="color:#999">N/A</span>`;
                }
                
                if (typeof value === 'object' && !Array.isArray(value)) {
                    // Object - render nested key-value pairs
                    let html = '';
                    for (const [key, val] of Object.entries(value)) {
                        const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                        html += `${spacing}<strong>${label}:</strong><br>`;
                        html += renderValue(val, indent + 1);
                    }
                    return html;
                } else if (Array.isArray(value)) {
                    // Array - render as list
                    if (value.length === 0) return `${spacing}<span style="color:#999">None</span><br>`;
                    
                    let html = '';
                    value.forEach((item, idx) => {
                        if (typeof item === 'object' && item !== null) {
                            html += `${spacing}<div style="margin:4px 0;padding:6px;background:#f0f0f0;border-radius:4px">`;
                            html += renderValue(item, indent);
                            html += `${spacing}</div>`;
                        } else {
                            html += `${spacing}• ${escapeHtml(String(item))}<br>`;
                        }
                    });
                    return html;
                } else {
                    // Primitive value
                    return `${spacing}${escapeHtml(String(value))}<br>`;
                }
            }

            function renderInfo(node) {
                if (!node) {
                    infoBox.innerHTML = `<h3>Node Info</h3><p>Click a node in the graph to pin its details here.</p>`;
                    return;
                }

                const n = node.raw;
                let html = '<h3>Node Info</h3><div style="line-height:1.6">';
                
                // Skip keys handled separately
                const skipKeys = ['id', 'vuln', 'peripheral', 'peripheralData'];
                
                for (const [key, value] of Object.entries(n)) {
                    if (skipKeys.includes(key)) continue;
                    
                    const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                    html += `<div style="margin-bottom:12px">`;
                    html += `<strong style="color:#2563eb">${label}:</strong><br>`;
                    html += renderValue(value, 0);
                    html += `</div>`;
                }
                
                html += '</div>';
                
                // If vulnerability info exists, append it below
                if (n && n.vuln) {
                    const v = n.vuln;
                    let evidenceHtml = '';
                    if (v.evidence) {
                        // evidence can be a string or array
                        if (Array.isArray(v.evidence)) {
                            evidenceHtml = '<ul>' + v.evidence.map(e => `<li><pre style="white-space:pre-wrap;margin:0">${escapeHtml(JSON.stringify(e, null, 2))}</pre></li>`).join('') + '</ul>';
                        } else if (typeof v.evidence === 'string') {
                            evidenceHtml = `<pre style="white-space:pre-wrap;">${escapeHtml(v.evidence)}</pre>`;
                        } else {
                            evidenceHtml = `<pre style="white-space:pre-wrap;">${escapeHtml(JSON.stringify(v.evidence, null, 2))}</pre>`;
                        }
                    }

                    const vulnHtml = `
                    <hr/>
                    <h4>Vulnerability</h4>
                    <ul>
                        <li><strong>Risk:</strong> ${escapeHtml(v.risk_level || v.status || 'unknown')}</li>
                        <li><strong>Reason:</strong> ${escapeHtml(v.reason || v.summary || '')}</li>
                        <li><strong>Tags:</strong> ${escapeHtml((v.tags || []).join(', '))}</li>
                    </ul>
                    <div><strong>Evidence:</strong>${evidenceHtml}</div>
                `;

                    html += vulnHtml;
                }

                // If peripheral/perimeter info exists, append it below
                if (n && n.peripheralData) {
                    const p = n.peripheralData;
                    const periphHtml = `
                    <hr/>
                    <h4>Perimeter / Peripheral Details</h4>
                    <ul>
                        <li><strong>Risk Level:</strong> ${escapeHtml(p.risk_level || p.status || 'unknown')}</li>
                        <li><strong>Reason:</strong> ${escapeHtml(p.reason || '')}</li>
                        <li><strong>Tags:</strong> ${escapeHtml((p.tags || []).join(', '))}</li>
                        <li><strong>Affected Ports:</strong> ${escapeHtml((p.affected_ports || []).join(', '))}</li>
                        <li><strong>Vectors:</strong> ${escapeHtml((p.likely_vectors || []).join(', '))}</li>
                    </ul>
                    `;

                    html += periphHtml;
                }
                
                infoBox.innerHTML = html;
            }

            // After graph is constructed, request AI-filtered logs and highlight nodes
            async function applyVulnerabilities() {
                try {
                    const resp = await fetch('/api/logs');
                    if (!resp.ok) return; // silent fail
                    const logs = await resp.json();

                    // Expect logs.affected_hosts = [{ ip, hostname, status, risk_level, reason, evidence }, ...]
                    const affected = logs.affected_hosts || logs.affected || [];

                    // Build quick lookup from node raw.ip and raw.name -> node id
                    const ipToNode = {};
                    const nameToNode = {};
                    visNodes.forEach((n) => {
                        const r = n.raw || {};
                        if (r.ip) ipToNode[String(r.ip).trim()] = n.id;
                        if (r.name) nameToNode[String(r.name).toLowerCase().trim()] = n.id;
                    });

                    // Prepare updates
                    const updates = [];
                    affected.forEach((ah) => {
                        const ip = ah.ip && String(ah.ip).trim();
                        const host = ah.hostname && String(ah.hostname).toLowerCase().trim();
                        let nid = null;
                        if (ip && ipToNode[ip]) nid = ipToNode[ip];
                        else if (host && nameToNode[host]) nid = nameToNode[host];

                        if (!nid) return; // no matching node

                        // Determine color by status/risk
                        // Critical / Compromised = Red (#ef4444)
                        // High = Orange (#f59e0b)
                        // Medium / At Risk = Amber (#fbbf24)
                        // Others = Orange-Red (#f97316)
                        const risk = (ah.risk_level || ah.status || '').toString().toLowerCase();
                        let bg = '#f97316'; // default
                        if (risk.includes('critical') || risk.includes('compromised')) {
                            bg = '#ef4444'; // red
                        } else if (risk.includes('high')) {
                            bg = '#f59e0b'; // orange
                        } else if (risk.includes('medium') || risk.includes('at risk') || risk.includes('warning')) {
                            bg = '#fbbf24'; // amber
                        }

                        // Store evidence on the node raw for later display
                        const node = visNodes.find((x) => x.id === nid);
                        if (node) {
                            node.raw = node.raw || {};
                            node.raw.vuln = ah;
                        }

                        updates.push({ id: nid, color: { background: bg, border: '#111' } });
                    });

                    if (updates.length > 0) {
                        data.nodes.update(updates);
                    }
                } catch (e) {
                    console.warn('Failed to fetch /api/logs', e);
                }
            }

            // Ensure the legend stays above the vis-network canvas. vis-network may
            // insert canvases asynchronously, so use a MutationObserver to re-assert
            // styles whenever children change.
            (function keepLegendOnTop() {
                const legendEl = document.getElementById('legend');
                if (!legendEl) return;

                // Style the legend explicitly
                legendEl.style.zIndex = 9999;
                legendEl.style.position = legendEl.style.position || 'absolute';
                legendEl.style.pointerEvents = 'auto';

                function lowerCanvases(parent) {
                    try {
                        const canvases = parent.querySelectorAll('canvas, svg');
                        canvases.forEach((c) => {
                            // make sure canvases are behind the legend
                            c.style.zIndex = 1;
                            if (!c.style.position) c.style.position = 'relative';
                        });
                    } catch (e) {
                        console.warn('Failed to lower canvases', e);
                    }
                }

                // initial pass
                lowerCanvases(container);

                // observe for future canvas/svg insertions
                try {
                    const mo = new MutationObserver((mutations) => {
                        for (const m of mutations) {
                            if (m.addedNodes && m.addedNodes.length) {
                                lowerCanvases(container);
                            }
                        }
                    });
                    mo.observe(container, { childList: true, subtree: true });
                } catch (e) {
                    // MutationObserver might not be available in some older browsers;
                    // fallback to a short interval re-check
                    const iv = setInterval(() => lowerCanvases(container), 500);
                    // stop after 10 seconds
                    setTimeout(() => clearInterval(iv), 10000);
                }
            })();

            network.on("click", (params) => {
                if (params.nodes.length > 0) {
                    const nodeId = params.nodes[0];
                    const node = visNodes.find((n) => n.id === nodeId);
                    renderInfo(node);
                }
            });

            // Kick off vulnerability application (fire-and-forget)
            applyVulnerabilities();

            // Additionally fetch perimeter logs and mark peripherals
            async function applyPerimeterDecorations() {
                try {
                    const resp = await fetch('/api/peripherals');
                    if (!resp.ok) return;
                    const p = await resp.json();
                    const perips = new Set();
                    if (p.primary_compromised && Array.isArray(p.primary_compromised)) {
                        p.primary_compromised.forEach(ip => perips.add(String(ip).trim()));
                    }
                    if (p.affected_hosts && Array.isArray(p.affected_hosts)) {
                        p.affected_hosts.forEach(h => { if (h.ip) perips.add(String(h.ip).trim()); });
                    }

                    // match ips to node ids using ip on raw node and attach peripheral data
                    const updates = [];
                    const matched = [];
                    visNodes.forEach((n) => {
                        const r = n.raw || {};
                        const nodeIp = r.ip && String(r.ip).trim();
                        if (nodeIp && perips.has(nodeIp)) {
                            peripheralNodeIds.add(n.id);
                            n.raw = n.raw || {};
                            // find the matching affected_host entry
                            const match = (p.affected_hosts || []).find(h => String(h.ip).trim() === nodeIp) || null;
                            if (match) {
                                n.raw.peripheral = true;
                                n.raw.peripheralData = match;
                            } else {
                                n.raw.peripheral = true;
                            }
                            matched.push(n.id);
                            // Mark the node visually as peripheral by changing its background/border
                            // to purple and append an exclamation mark to its label (only once).
                            const currentLabel = n.label || (n.raw && (n.raw.name || n.id)) || n.id;
                            const hasMark = typeof currentLabel === 'string' && currentLabel.includes('!');
                            const newLabel = hasMark ? currentLabel : (currentLabel + ' !');
                            updates.push({ id: n.id, label: newLabel, color: { background: '#8b5cf6', border: '#4c1d95' } });
                        }
                    });
                    if (updates.length) data.nodes.update(updates);
                    console.debug('Perimeter perips=', Array.from(perips));
                    console.debug('Matched peripheral node ids=', matched);

                    // schedule a couple of redraws in case vis positions are not ready yet
                    setTimeout(() => { resizeOverlay(); drawPeripherals(); }, 250);
                    setTimeout(() => { resizeOverlay(); drawPeripherals(); }, 1000);

                    // ensure overlay sizing and draw
                    resizeOverlay();
                    drawPeripherals();
                } catch (e) {
                    console.warn('Failed to fetch /api/perimeter', e);
                }
            }

            applyPerimeterDecorations();

            // Fetch and display remediation playbook
            async function loadRemediationPlaybook() {
                // Create loading screen
                const loadingContainer = document.createElement('div');
                loadingContainer.id = 'remediation-loading';
                loadingContainer.style.marginTop = '2rem';
                loadingContainer.innerHTML = `
                    <div class="card">
                        <div class="card-body text-center py-5">
                            <div class="spinner-border text-primary mb-3" role="status" style="width: 3rem; height: 3rem;">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <h5>Generating Remediation Playbook...</h5>
                            <p class="text-muted">Analyzing incident data and creating response plan</p>
                        </div>
                    </div>
                `;
                
                // Append loading screen after the map container
                const mapContainer = document.getElementById('map-container');
                if (mapContainer && mapContainer.parentNode) {
                    mapContainer.parentNode.insertBefore(loadingContainer, mapContainer.nextSibling);
                }
                
                try {
                    const resp = await fetch('/api/remediation');
                    if (!resp.ok) {
                        console.warn('Failed to fetch remediation playbook');
                        loadingContainer.innerHTML = `
                            <div class="alert alert-warning">
                                <strong>Warning:</strong> Unable to load remediation playbook. Please try again later.
                            </div>
                        `;
                        return;
                    }
                    const data = await resp.json();
                    let html = data.remediation || '';
                    
                    if (!html) {
                        console.warn('No remediation content available');
                        loadingContainer.innerHTML = `
                            <div class="alert alert-info">
                                <strong>Info:</strong> No remediation content available at this time.
                            </div>
                        `;
                        return;
                    }
                    
                    // Strip all \n except when it's part of an HTML closing tag (</...>)
                    // Replace \n with empty string, but preserve closing tags
                    html = html.replace(/\\n(?!>)/g, '');
                    
                    // Replace loading screen with actual content
                    loadingContainer.id = 'remediation-playbook';
                    loadingContainer.innerHTML = html;
                    
                } catch (e) {
                    console.warn('Error loading remediation playbook:', e);
                    loadingContainer.innerHTML = `
                        <div class="alert alert-danger">
                            <strong>Error:</strong> Failed to load remediation playbook. ${e.message}
                        </div>
                    `;
                }
            }

            // Load remediation playbook after a short delay to allow other content to render
            setTimeout(loadRemediationPlaybook, 500);
        });