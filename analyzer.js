let rawData = [];
let filteredData = [];
let protoChart, portsChart, talkersChart;
let showOnlyErrors = false;

// 1. Initialización de Gráficos
function initCharts() {
    const chartStyles = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { 
            legend: { position: 'top', labels: { color: '#aaa', font: { size: 9 } } },
            title: { display: true, color: '#fff', font: { size: 12 } }
        }
    };

    if (protoChart) protoChart.destroy();
    if (portsChart) portsChart.destroy();
    if (talkersChart) talkersChart.destroy();

    protoChart = new Chart(document.getElementById('chart-protocols'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff', '#ff8c00'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { text: 'Protocols' } } }
    });

    portsChart = new Chart(document.getElementById('chart-ports'), {
        type: 'pie',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { text: 'Top Ports' } } }
    });

    talkersChart = new Chart(document.getElementById('chart-talkers'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: '#00ff41' }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { text: 'Top Talkers (Bandwidth)' } }, scales: { y: { ticks: { color: '#666' } }, x: { ticks: { color: '#666' } } } }
    });
}

// 2. Procesamiento de Archivo
const fileInput = document.getElementById('file-input');
document.getElementById('upload-zone').onclick = () => fileInput.click();

fileInput.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    document.getElementById('progress-container').classList.remove('hidden');
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            const json = JSON.parse(event.target.result);
            processData(json);
            setTimeout(() => {
                document.getElementById('landing-screen').classList.add('hidden');
                document.getElementById('main-dashboard').classList.remove('hidden');
                initCharts();
                applyFilters(); 
            }, 600);
        } catch (err) { alert("Invalid JSON"); }
    };
    reader.readAsText(file);
};

// 3. Extracción de Metadatos
function processData(json) {
    rawData = json.map(p => {
        const l = p._source.layers;
        const ip = l.ip || l.ipv6 || {};
        const tcp = l.tcp || {};
        const udp = l.udp || {};
        const tls = l.tls || {};
        
        let flags = [];
        let isReset = false;
        if (tcp["tcp.flags_tree"]) {
            const f = tcp["tcp.flags_tree"];
            if (f["tcp.flags.syn"] == "1") flags.push("SYN");
            if (f["tcp.flags.reset"] == "1") { flags.push("RST"); isReset = true; }
            if (f["tcp.flags.ack"] == "1") flags.push("ACK");
        }

        let domain = "---";
        if (l.http && l.http["http.host"]) domain = l.http["http.host"];
        else if (tls["tls.handshake"] && tls["tls.handshake"]["tls.handshake.extensions_server_name"]) domain = tls["tls.handshake"]["tls.handshake.extensions_server_name"];

        const isRetrans = !!tcp["tcp.analysis.retransmission"];
        let level = isReset ? "critical" : (isRetrans ? "warning" : "normal");

        return {
            delta: parseFloat(l.frame["frame.time_delta"] || 0).toFixed(4),
            src: ip["ip.src"] || ip["ipv6.src"] || "N/A",
            dst: ip["ip.dst"] || ip["ipv6.dst"] || "N/A",
            domain: domain,
            ttl: ip["ip.ttl"] || ip["ipv6.hlim"] || "---",
            win: tcp["tcp.window_size_value"] || "---",
            proto: l.frame["frame.protocols"].split(':').pop().toUpperCase(),
            port: tcp["tcp.dstport"] || udp["udp.dstport"] || "N/A",
            size: parseInt(l.frame["frame.len"]),
            flags: flags.join(',') || "---",
            isReset: isReset,
            isRetrans: isRetrans,
            level: level,
            original: l // Para el Modal
        };
    });

    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">All Protocols</option>';
    [...new Set(rawData.map(p => p.proto))].forEach(pr => select.innerHTML += `<option value="${pr}">${pr}</option>`);
}

// 4. Filtrado y UI
function applyFilters() {
    const src = document.getElementById('filter-src-ip').value.toLowerCase();
    const dst = document.getElementById('filter-dst-ip').value.toLowerCase();
    const pr = document.getElementById('filter-proto').value;
    const fl = document.getElementById('filter-flags').value.toUpperCase();

    filteredData = rawData.filter(p => {
        return (src === "" || p.src.toLowerCase().includes(src)) &&
               (dst === "" || p.dst.toLowerCase().includes(dst)) &&
               (pr === "all" || p.proto === pr) &&
               (fl === "" || p.flags.includes(fl)) &&
               (!showOnlyErrors || p.level !== "normal");
    });
    updateUI();
}

function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    
    filteredData.slice(0, 300).forEach((p, index) => {
        const tr = document.createElement('tr');
        tr.className = `row-${p.level}`;
        tr.innerHTML = `<td>${p.delta}s</td><td>${p.src}</td><td>${p.dst}</td><td style="color:var(--neon-blue)">${p.domain}</td><td>${p.ttl}</td><td>${p.win}</td><td>${p.flags}</td><td>${p.port}</td><td>${p.level.toUpperCase()}</td>`;
        tr.onclick = () => showPacketDetail(p.original);
        tbody.appendChild(tr);
    });
    
    document.getElementById('stat-packets').innerText = filteredData.length.toLocaleString();
    document.getElementById('stat-resets').innerText = filteredData.filter(p => p.isReset).length;
    document.getElementById('stat-retrans').innerText = filteredData.filter(p => p.isRetrans).length;
    document.getElementById('stat-ips').innerText = [...new Set(filteredData.map(p => p.src))].length;
    
    updateCharts();
}

// 5. Módulos Adicionales (Talkers & Modal)
function updateCharts() {
    if (!protoChart) return;
    
    // Protocols
    const pMap = {};
    filteredData.forEach(p => pMap[p.proto] = (pMap[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(pMap);
    protoChart.data.datasets[0].data = Object.values(pMap);
    protoChart.update();

    // Ports
    const ptMap = {};
    filteredData.filter(p => p.port !== "N/A").forEach(p => ptMap[p.port] = (ptMap[p.port] || 0) + 1);
    const topPorts = Object.entries(ptMap).sort((a,b) => b[1]-a[1]).slice(0, 5);
    portsChart.data.labels = topPorts.map(x => x[0]);
    portsChart.data.datasets[0].data = topPorts.map(x => x[1]);
    portsChart.update();

    // TOP TALKERS (MÓDULO NUEVO)
    const talkMap = {};
    filteredData.forEach(p => talkMap[p.src] = (talkMap[p.src] || 0) + p.size);
    const topTalkers = Object.entries(talkMap).sort((a,b) => b[1]-a[1]).slice(0, 5);
    talkersChart.data.labels = topTalkers.map(x => x[0]);
    talkersChart.data.datasets[0].data = topTalkers.map(x => x[1]);
    talkersChart.update();
}

function showPacketDetail(layers) {
    document.getElementById('json-display').innerText = JSON.stringify(layers, null, 4);
    document.getElementById('packet-modal').classList.remove('hidden');
}

// Close Modal
document.querySelector('.close-modal').onclick = () => document.getElementById('packet-modal').classList.add('hidden');
window.onclick = (event) => { if (event.target == document.getElementById('packet-modal')) document.getElementById('packet-modal').classList.add('hidden'); };

// Event Listeners
document.getElementById('filter-src-ip').oninput = applyFilters;
document.getElementById('filter-dst-ip').oninput = applyFilters;
document.getElementById('filter-proto').onchange = applyFilters;
document.getElementById('filter-flags').oninput = applyFilters;
document.getElementById('btn-only-errors').onclick = function() { this.classList.toggle('active'); showOnlyErrors = !showOnlyErrors; applyFilters(); };
document.getElementById('btn-clear').onclick = () => { location.reload(); };
document.getElementById('btn-reset').onclick = () => location.reload();
document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF('l', 'mm', 'a4');
    doc.text("Network Report - Selvin Mejia", 14, 15);
    doc.autoTable({ head: [['Delta', 'Source', 'Destination', 'TTL', 'Port', 'Status']], body: filteredData.slice(0, 50).map(p => [p.delta, p.src, p.dst, p.ttl, p.port, p.level]), startY: 25 });
    doc.save('Forensic_Report.pdf');
};
