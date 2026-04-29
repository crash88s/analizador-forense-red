let rawData = [];
let filteredData = [];
let protoChart, portsChart;
let showOnlyErrors = false;

// 1. Chart Initialization
function initCharts() {
    const chartStyles = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { 
            legend: { 
                position: 'top',
                labels: { color: '#aaa', font: { size: 10, family: 'Segoe UI' } } 
            } 
        }
    };

    protoChart = new Chart(document.getElementById('chart-protocols'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff', '#ff8c00', '#00ced1'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { display: true, text: 'Protocols Distribution', color: '#fff' } } }
    });

    // Ports Chart changed to Pie
    portsChart = new Chart(document.getElementById('chart-ports'), {
        type: 'pie',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff', '#ff8c00', '#00ced1', '#ff1493'] }] },
        options: { ...chartStyles, plugins: { ...chartStyles.plugins, title: { display: true, text: 'Top Destination Ports', color: '#fff' } } }
    });
}

// 2. File Handling
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

dropZone.onclick = () => fileInput.click();

fileInput.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    document.getElementById('progress-container').classList.remove('hidden');
    const reader = new FileReader();

    reader.onprogress = (event) => {
        if (event.lengthComputable) {
            const percent = (event.loaded / event.total) * 100;
            document.getElementById('progress-fill').style.width = percent + '%';
        }
    };

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
        } catch (err) {
            alert("Error: File is not a valid Wireshark JSON.");
            document.getElementById('progress-container').classList.add('hidden');
        }
    };
    reader.readAsText(file);
};

// 3. Processing Layers
function processData(json) {
    rawData = json.map(p => {
        const l = p._source.layers;
        const ip = l.ip || l.ipv6 || {};
        const tcp = l.tcp || {};
        const udp = l.udp || {};
        const http = l.http || {};
        
        let flags = [];
        if (tcp["tcp.flags_tree"]) {
            const f = tcp["tcp.flags_tree"];
            if (f["tcp.flags.syn"] == "1") flags.push("SYN");
            if (f["tcp.flags.reset"] == "1") flags.push("RST");
            if (f["tcp.flags.ack"] == "1") flags.push("ACK");
            if (f["tcp.flags.fin"] == "1") flags.push("FIN");
        }

        let level = "normal";
        let status = "OK";
        if (tcp["tcp.analysis.retransmission"] || tcp["tcp.analysis.duplicate_ack"]) {
            level = "warning";
            status = "Retransmission / Latency";
        }
        if (flags.includes("RST") || (http["http.response.code"] >= 400)) {
            level = "critical";
            status = "Critical RST / HTTP Error";
        }

        return {
            delta: parseFloat(l.frame["frame.time_delta"] || 0).toFixed(4),
            src: ip["ip.src"] || "N/A",
            dst: ip["ip.dst"] || "N/A",
            proto: l.frame["frame.protocols"].split(':').pop().toUpperCase(),
            port: tcp["tcp.dstport"] || udp["udp.dstport"] || "N/A",
            flags: flags.join(','),
            level: level,
            status: status
        };
    });

    // Populate Protocol Select
    const protos = [...new Set(rawData.map(p => p.proto))];
    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">All Protocols</option>';
    protos.forEach(pr => select.innerHTML += `<option value="${pr}">${pr}</option>`);
}

// 4. Filtering Engine
function applyFilters() {
    const srcInput = document.getElementById('filter-src-ip').value.toLowerCase();
    const dstInput = document.getElementById('filter-dst-ip').value.toLowerCase();
    const protoSelect = document.getElementById('filter-proto').value;
    const flagInput = document.getElementById('filter-flags').value.toUpperCase();

    filteredData = rawData.filter(p => {
        const matchesSrc = p.src.toLowerCase().includes(srcInput);
        const matchesDst = p.dst.toLowerCase().includes(dstInput);
        const matchesProto = protoSelect === "all" || p.proto === protoSelect;
        const matchesFlags = flagInput === "" || p.flags.includes(flagInput);
        const matchesErrors = showOnlyErrors ? p.level !== "normal" : true;

        return matchesSrc && matchesDst && matchesProto && matchesFlags && matchesErrors;
    });

    updateUI();
}

// 5. Interface Rendering
function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    
    // Render first 300 for performance
    filteredData.slice(0, 300).forEach(p => {
        const tr = document.createElement('tr');
        tr.className = `row-${p.level}`;
        tr.innerHTML = `
            <td>${p.delta} s</td>
            <td>${p.src}</td>
            <td>${p.dst}</td>
            <td>${p.flags || '---'}</td>
            <td>${p.port}</td>
            <td>${p.status}</td>
        `;
        tbody.appendChild(tr);
    });

    // Update KPIs
    document.getElementById('stat-packets').innerText = filteredData.length.toLocaleString();
    document.getElementById('stat-alerts').innerText = filteredData.filter(p => p.level === 'critical').length;
    document.getElementById('stat-ips').innerText = [...new Set(filteredData.map(p => p.src))].length;

    updateCharts();
}

function updateCharts() {
    if (!protoChart || !portsChart) return;

    // Protocols
    const pMap = {};
    filteredData.forEach(p => pMap[p.proto] = (pMap[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(pMap);
    protoChart.data.datasets[0].data = Object.values(pMap);
    protoChart.update();

    // Ports (Pie)
    const ptMap = {};
    filteredData.filter(p => p.port !== "N/A").forEach(p => ptMap[p.port] = (ptMap[p.port] || 0) + 1);
    const topPorts = Object.entries(ptMap).sort((a,b) => b[1]-a[1]).slice(0, 8);
    portsChart.data.labels = topPorts.map(x => x[0]);
    portsChart.data.datasets[0].data = topPorts.map(x => x[1]);
    portsChart.update();
}

// 6. Event Listeners
document.getElementById('filter-src-ip').addEventListener('input', applyFilters);
document.getElementById('filter-dst-ip').addEventListener('input', applyFilters);
document.getElementById('filter-proto').addEventListener('change', applyFilters);
document.getElementById('filter-flags').addEventListener('input', applyFilters);

document.getElementById('btn-only-errors').onclick = function() {
    showOnlyErrors = !showOnlyErrors;
    this.classList.toggle('active');
    applyFilters();
};

document.getElementById('btn-reset').onclick = () => location.reload();

document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text("Network Tshoot Report", 14, 15);
    doc.setFontSize(10);
    doc.text(`Analyst: Selvin Mejia | Packets: ${filteredData.length}`, 14, 22);
    
    const rows = filteredData.slice(0, 50).map(p => [p.delta, p.src, p.dst, p.port, p.status]);
    doc.autoTable({
        head: [['Delta', 'Source', 'Destination', 'Port', 'Status']],
        body: rows,
        startY: 30,
        theme: 'grid'
    });
    doc.save('Tshoot_Report_SelvinMejia.pdf');
};
