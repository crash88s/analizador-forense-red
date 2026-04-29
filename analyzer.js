let rawData = [];
let filteredData = [];
let protoChart, portsChart, talkersChart;
let showOnlyErrors = false;

function initCharts() {
    const chartStyles = {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { color: '#777', font: { size: 10 } } }, title: { display: true, color: '#fff', font: { size: 13 } } }
    };
    if (protoChart) protoChart.destroy();
    if (portsChart) portsChart.destroy();
    if (talkersChart) talkersChart.destroy();

    protoChart = new Chart(document.getElementById('chart-protocols'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff', '#ff8c00'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { ...chartStyles.plugins.title, text: 'Protocols Distribution' } } }
    });

    portsChart = new Chart(document.getElementById('chart-ports'), {
        type: 'pie',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff', '#ff1493'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { ...chartStyles.plugins.title, text: 'Top Destination Ports' } } }
    });

    talkersChart = new Chart(document.getElementById('chart-talkers'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Total Bytes', data: [], backgroundColor: '#00ff41' }] },
        options: { 
            ...chartStyles, 
            plugins: { ...chartStyles.plugins, title: { ...chartStyles.plugins.title, text: 'Top Talkers (Bandwidth)' } },
            scales: { y: { grid: { color: '#111' }, ticks: { color: '#444' } }, x: { grid: { display: false }, ticks: { color: '#444' } } }
        }
    });
}

const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
uploadZone.onclick = () => fileInput.click();
fileInput.onchange = (e) => handleFile(e.target.files[0]);

function handleFile(file) {
    if (!file || !file.name.endsWith('.json')) { alert("Please upload a valid JSON file."); return; }
    document.getElementById('progress-container').classList.remove('hidden');
    const reader = new FileReader();
    reader.onprogress = (e) => { if (e.lengthComputable) document.getElementById('progress-fill').style.width = (e.loaded / e.total * 100) + '%'; };
    reader.onload = (e) => {
        try {
            const json = JSON.parse(e.target.result);
            processData(json);
            setTimeout(() => {
                document.getElementById('landing-screen').classList.add('hidden');
                document.getElementById('main-dashboard').classList.remove('hidden');
                initCharts(); applyFilters(); 
            }, 600);
        } catch (err) { alert("Error parsing JSON."); document.getElementById('progress-container').classList.add('hidden'); }
    };
    reader.readAsText(file);
}

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

        return {
            delta: parseFloat(l.frame["frame.time_delta"] || 0).toFixed(4),
            src: ip["ip.src"] || ip["ipv6.src"] || "N/A",
            dst: ip["ip.dst"] || ip["ipv6.dst"] || "N/A",
            domain: domain,
            ttl: ip["ip.ttl"] || ip["ipv6.hlim"] || "---",
            win: tcp["tcp.window_size_value"] || "---",
            proto: l.frame["frame.protocols"].split(':').pop().toUpperCase(),
            port: tcp["tcp.dstport"] || udp["udp.dstport"] || "N/A",
            size: parseInt(l.frame["frame.len"] || 0),
            flags: flags.join(',') || "---",
            isReset: isReset,
            isRetrans: !!tcp["tcp.analysis.retransmission"],
            level: isReset ? "critical" : (!!tcp["tcp.analysis.retransmission"] ? "warning" : "normal"),
            original: l
        };
    });
    const protos = [...new Set(rawData.map(p => p.proto))];
    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">All Protocols</option>';
    protos.forEach(pr => select.innerHTML += `<option value="${pr}">${pr}</option>`);
}

function applyFilters() {
    const srcInput = document.getElementById('filter-src-ip').value.toLowerCase();
    const dstInput = document.getElementById('filter-dst-ip').value.toLowerCase();
    const protoSelect = document.getElementById('filter-proto').value;
    const flagInput = document.getElementById('filter-flags').value.toUpperCase();
    filteredData = rawData.filter(p => {
        const matchSrc = (srcInput === "" || p.src.toLowerCase().includes(srcInput));
        const matchDst = (dstInput === "" || p.dst.toLowerCase().includes(dstInput));
        const matchProto = (protoSelect === "all" || p.proto === protoSelect);
        const matchFlags = (flagInput === "" || p.flags.includes(flagInput));
        const matchError = (!showOnlyErrors || p.level !== "normal");
        return matchSrc && matchDst && matchProto && matchFlags && matchError;
    });
    updateUI();
}

document.getElementById('btn-clear').onclick = () => {
    document.getElementById('filter-src-ip').value = ""; document.getElementById('filter-dst-ip').value = "";
    document.getElementById('filter-proto').value = "all"; document.getElementById('filter-flags').value = "";
    showOnlyErrors = false; document.getElementById('btn-only-errors').classList.remove('active');
    applyFilters();
};

function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    filteredData.slice(0, 300).forEach(p => {
        const tr = document.createElement('tr');
        tr.className = `row-${p.level}`;
        tr.innerHTML = `<td class="col-delta">${p.delta} s</td><td class="col-ip">${p.src}</td><td class="col-ip">${p.dst}</td><td class="col-domain" style="color:var(--neon-blue)">${p.domain}</td><td class="col-ttl">${p.ttl}</td><td class="col-win">${p.win}</td><td class="col-flags">${p.flags}</td><td class="col-port">${p.port}</td><td class="col-status">${p.level.toUpperCase()}</td>`;
        tr.onclick = () => { document.getElementById('json-display').innerText = JSON.stringify(p.original, null, 4); document.getElementById('packet-modal').classList.remove('hidden'); };
        tbody.appendChild(tr);
    });
    document.getElementById('stat-packets').innerText = filteredData.length.toLocaleString();
    document.getElementById('stat-resets').innerText = rawData.filter(p => p.isReset).length;
    document.getElementById('stat-retrans').innerText = rawData.filter(p => p.isRetrans).length;
    document.getElementById('stat-ips').innerText = [...new Set(filteredData.map(p => p.src))].length;
    updateCharts();
}

function updateCharts() {
    if (!protoChart) return;
    const pMap = {}; filteredData.forEach(p => pMap[p.proto] = (pMap[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(pMap); protoChart.data.datasets[0].data = Object.values(pMap); protoChart.update();
    const ptMap = {}; filteredData.filter(p => p.port !== "N/A").forEach(p => ptMap[p.port] = (ptMap[p.port] || 0) + 1);
    const topPorts = Object.entries(ptMap).sort((a,b) => b[1]-a[1]).slice(0, 8);
    portsChart.data.labels = topPorts.map(x => x[0]); portsChart.data.datasets[0].data = topPorts.map(x => x[1]); portsChart.update();
    const talkMap = {}; filteredData.forEach(p => talkMap[p.src] = (talkMap[p.src] || 0) + p.size);
    const topTalkers = Object.entries(talkMap).sort((a,b) => b[1]-a[1]).slice(0, 5);
    talkersChart.data.labels = topTalkers.map(x => x[0]); talkersChart.data.datasets[0].data = topTalkers.map(x => x[1]); talkersChart.update();
}

document.querySelector('.close-modal').onclick = () => document.getElementById('packet-modal').classList.add('hidden');
window.onclick = (e) => { if (e.target == document.getElementById('packet-modal')) document.getElementById('packet-modal').classList.add('hidden'); };
document.getElementById('filter-src-ip').oninput = applyFilters;
document.getElementById('filter-dst-ip').oninput = applyFilters;
document.getElementById('filter-proto').onchange = applyFilters;
document.getElementById('filter-flags').oninput = applyFilters;
document.getElementById('btn-only-errors').onclick = function() { showOnlyErrors = !showOnlyErrors; this.classList.toggle('active'); applyFilters(); };
document.getElementById('btn-reset').onclick = () => location.reload();
document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf; const doc = new jsPDF('l', 'mm', 'a4');
    doc.text("Network Forensic Report - Selvin Mejia", 14, 15);
    doc.autoTable({ head: [['Delta', 'Source', 'Destination', 'Domain', 'TTL', 'Win', 'Flags', 'Port', 'Status']], body: filteredData.slice(0, 50).map(p => [p.delta, p.src, p.dst, p.domain, p.ttl, p.win, p.flags, p.port, p.level]), startY: 25 });
    doc.save('Forensic_Report.pdf');
};
