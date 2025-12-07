fetch("/api/assetmap")
    .then((res) => res.json())
    .then((graph) => {
        // ===== Edge color dictionary =====
        const edgeColors = {
            dmz_exposed: "#ef4444",
            app_backend: "#3b82f6",
            db_backend: "#10b981",
            admin_on: "#f59e0b",
            local_admin_on: "#6366f1",
            member_of: "#8b5cf6",
            interactive_logon: "#14b8a6",
            data_access: "#f43f5e",
        };

        const rawNodes = graph.nodes || [];
        const rawEdges = graph.edges || [];

        const visNodes = rawNodes.map((n) => {
            // Default monotone color
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

        const infoBox = document.getElementById("node-info");

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
                        html += `${spacing}• ${String(item)}<br>`;
                    }
                });
                return html;
            } else {
                // Primitive value
                return `${spacing}${String(value)}<br>`;
            }
        }

        function renderInfo(node) {
            if (!node) {
                infoBox.innerHTML = `<h3>Node Info</h3><p>Click a node in the graph to pin its details here.</p>`;
                return;
            }

            const n = node.raw;
            let html = '<h3>Node Info</h3><div style="line-height:1.6">';

            // Skip 'id' as it's usually redundant with 'name'
            const skipKeys = ['id'];

            for (const [key, value] of Object.entries(n)) {
                if (skipKeys.includes(key)) continue;

                const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                html += `<div style="margin-bottom:12px">`;
                html += `<strong style="color:#2563eb">${label}:</strong><br>`;
                html += renderValue(value, 0);
                html += `</div>`;
            }

            html += '</div>';
            infoBox.innerHTML = html;
        }

        network.on("click", (params) => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const node = visNodes.find((n) => n.id === nodeId);
                renderInfo(node);
            }
        });
    });