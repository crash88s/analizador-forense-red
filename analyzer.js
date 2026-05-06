let rawData = [];
let filteredData = [];
let protoChart, portsChart, talkersChart;
let showOnlyErrors = false;

// 1. Chart Initialization - UPDATED COLORS FOR CRYSTAL WHITE BACKGROUND
function initCharts() {
    const chartStyles = {
        responsive: true, maintainAspectRatio: false,
        events: ['mousemove', 'mouseout', 'touchstart', 'touchmove'],
        plugins: { 
            legend: { 
                position: 'top', 
                labels: { color: '#000', font: { size: 9, weight: 'bold' } }, // Black for white background
                onClick: (e) => e.stopPropagation()
            }, 
            title: { 
                display: true, 
                color: '#111', // Dark for white background
                font: { size: 11, weight: '900' } 
            } 
        }
    };
    if (protoChart) protoChart.destroy();
    if (portsChart) portsChart.destroy();
    if (talkersChart) talkersChart.destroy();

    const ctx1 = document.getElementById('chart-protocols').getContext('2d');
    const ctx2 = document.getElementById('chart-ports').getContext('2d');
    const ctx3 = document.getElementById('chart-talkers').getContext('2d');

    protoChart = new Chart(ctx1, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d2ff', '#3aeb34', '#ffcc00', '#ff3131', '#9d00ff', '#ff8c00'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { text: 'Protocols Distribution' } } }
    });

    portsChart = new Chart(ctx2, {
        type: 'pie',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d2ff', '#3aeb34', '#ffcc00', '#ff3131', '#9d00ff', '#ff8c00', '#ff1493'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { text: 'Top Destination Ports' } } }
    });

    talkersChart = new Chart(ctx3, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: '#00ff41' }] },
        options: { 
            ...chartStyles, 
            plugins: { ...chartStyles.plugins, title: { text: 'Top Talkers (Bandwidth)' } },
            scales: { 
                y: { grid: { color: 'rgba(0,0,0,0.1)' }, ticks: { color: '#333', font: { size: 8, weight: 'bold' } } }, 
                x: { grid: { display: false }, ticks: { color: '#333', font: { size: 8, weight: 'bold' } } } 
            }
        }
    });
}

// 2. File Handling
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
uploadZone.onclick = () => fileInput.click();
fileInput.onchange = (e) => handleFile(e.target.files[0]);

function handleFile(file) {
    if (!file || !file.name.endsWith('.json')) { alert("Please upload a valid JSON file."); return; }
    document.getElementById('upload-content').classList.add('hidden');
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
            }, 800);
        } catch (err) { alert("Error parsing JSON."); location.reload(); }
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
            level: (isReset || tcp["tcp.window_size_value"] === "0") ? "critical" : (!!tcp["tcp.analysis.retransmission"] ? "warning" : "normal"),
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
    const portInput = document.getElementById('filter-port').value;
    const flagInput = document.getElementById('filter-flags').value.toUpperCase();
    filteredData = rawData.filter(p => {
        const matchSrc = (srcInput === "" || p.src.toLowerCase().includes(srcInput));
        const matchDst = (dstInput === "" || p.dst.toLowerCase().includes(dstInput));
        const matchProto = (protoSelect === "all" || p.proto === protoSelect);
        const matchPort = (portInput === "" || p.port.toString() === portInput);
        const matchFlags = (flagInput === "" || p.flags.includes(flagInput));
        const matchError = (!showOnlyErrors || p.level !== "normal");
        return matchSrc && matchDst && matchProto && matchPort && matchFlags && matchError;
    });
    updateUI();
}

document.getElementById('btn-clear').onclick = () => {
    document.getElementById('filter-src-ip').value = ""; document.getElementById('filter-dst-ip').value = "";
    document.getElementById('filter-proto').value = "all"; document.getElementById('filter-flags').value = "";
    document.getElementById('filter-port').value = "";
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
        tr.onclick = () => { 
            document.getElementById('json-display').innerText = JSON.stringify(p.original, null, 4); 
            document.getElementById('packet-modal').classList.remove('hidden'); 
        };
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
