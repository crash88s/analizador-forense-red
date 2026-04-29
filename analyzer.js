let rawData = [];
let filteredData = [];
let timelineChart, protoChart;
let showOnlyErrors = false;

function initCharts() {
    const ctxTime = document.getElementById('chart-timeline').getContext('2d');
    const ctxProto = document.getElementById('chart-protocols').getContext('2d');

    timelineChart = new Chart(ctxTime, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Paquetes por Seg', data: [], borderColor: '#00d4ff', tension: 0.3, fill: true, backgroundColor: 'rgba(0, 212, 255, 0.1)' }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
    });

    protoChart = new Chart(ctxProto, {
        type: 'pie',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#39ff14', '#00d4ff', '#f1c40f', '#e74c3c'] }] },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

document.getElementById('file-input').addEventListener('change', handleFile);
document.getElementById('drop-zone').onclick = () => document.getElementById('file-input').click();
document.getElementById('btn-only-errors').onclick = toggleErrors;

function handleFile(e) {
    const reader = new FileReader();
    reader.onload = (event) => {
        const json = JSON.parse(event.target.result);
        processPackets(json);
    };
    reader.readAsText(e.target.files[0]);
}

function processPackets(json) {
    rawData = json.map(p => {
        const l = p._source.layers;
        const tcp = l.tcp || {};
        const ip = l.ip || l.ipv6 || {};
        const http = l.http || {};
        
        // Extracción de Flags
        let flags = [];
        if (tcp["tcp.flags_tree"]) {
            const f = tcp["tcp.flags_tree"];
            if (f["tcp.flags.syn"] == "1") flags.push("SYN");
            if (f["tcp.flags.ack"] == "1") flags.push("ACK");
            if (f["tcp.flags.reset"] == "1") flags.push("RST");
            if (f["tcp.flags.fin"] == "1") flags.push("FIN");
            if (f["tcp.flags.push"] == "1") flags.push("PSH");
        }

        // Detección de errores y status
        let status = "TCP OK";
        let analysis = "Normal";
        let level = "success";

        if (tcp["tcp.analysis.retransmission"]) {
            analysis = "RETRANSMISSION";
            level = "warning";
        }
        if (tcp["tcp.analysis.duplicate_ack"]) {
            analysis = "DUP ACK";
            level = "warning";
        }
        if (flags.includes("RST")) {
            analysis = "CONNECTION RESET";
            level = "critical";
        }
        if (http["http.response.code"]) {
            status = `HTTP ${http["http.response.code"]}`;
            if (parseInt(http["http.response.code"]) >= 400) level = "critical";
        }

        return {
            delta: parseFloat(l.frame["frame.time_delta"] || 0).toFixed(4),
            src: ip["ip.src"] || "N/A",
            dst: ip["ip.dst"] || "N/A",
            flags: flags.join(','),
            size: parseInt(l.frame["frame.len"]),
            status: status,
            analysis: analysis,
            level: level,
            proto: l.frame["frame.protocols"].split(':').pop().toUpperCase(),
            epoch: parseFloat(l.frame["frame.time_epoch"])
        };
    });

    updateFilters();
    applyFilters();
}

function toggleErrors() {
    showOnlyErrors = !showOnlyErrors;
    document.getElementById('btn-only-errors').classList.toggle('active');
    applyFilters();
}

function applyFilters() {
    const ipVal = document.getElementById('filter-ip').value.toLowerCase();
    const flagVal = document.getElementById('filter-flags').value.toUpperCase();

    filteredData = rawData.filter(p => {
        const matchesIp = p.src.includes(ipVal) || p.dst.includes(ipVal);
        const matchesFlags = flagVal === "" || p.flags.includes(flagVal);
        const matchesError = showOnlyErrors ? (p.level !== "success") : true;
        return matchesIp && matchesFlags && matchesError;
    });

    renderUI();
}

function renderUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    
    let totalBytes = 0;
    let errors = 0;

    filteredData.slice(0, 200).forEach(p => {
        if (p.level !== 'success') errors++;
        totalBytes += p.size;
        
        const row = `<tr class="row-${p.level}">
            <td>${p.delta}</td>
            <td>${p.src}</td>
            <td>${p.dst}</td>
            <td>${p.flags}</td>
            <td>${p.size} B</td>
            <td>${p.status}</td>
            <td>${p.analysis}</td>
        </tr>`;
        tbody.innerHTML += row;
    });

    // Calcular Throughput
    const timeSpan = filteredData.length > 0 ? (filteredData[filteredData.length-1].epoch - filteredData[0].epoch) : 0;
    const mbps = timeSpan > 0 ? ((totalBytes * 8) / (timeSpan * 1000000)).toFixed(2) : 0;

    document.getElementById('stat-packets').innerText = filteredData.length;
    document.getElementById('stat-throughput').innerText = `${mbps} Mbps`;
    document.getElementById('stat-alerts').innerText = errors;

    updateCharts();
}

function updateCharts() {
    // Timeline Chart (PPS)
    const ppsMap = {};
    filteredData.forEach(p => {
        const sec = Math.floor(p.epoch);
        ppsMap[sec] = (ppsMap[sec] || 0) + 1;
    });
    
    timelineChart.data.labels = Object.keys(ppsMap).map(t => new Date(t * 1000).toLocaleTimeString());
    timelineChart.data.datasets[0].data = Object.values(ppsMap);
    timelineChart.update();

    // Protocol Chart
    const protoMap = {};
    filteredData.forEach(p => protoMap[p.proto] = (protoMap[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(protoMap);
    protoChart.data.datasets[0].data = Object.values(protoMap);
    protoChart.update();
}

function updateFilters() {
    const protos = [...new Set(rawData.map(p => p.proto))];
    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">Todos</option>' + protos.map(p => `<option value="${p}">${p}</option>`).join('');
}

// PDF Export (Simplified)
document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.text("Network Troubleshooting Report", 14, 15);
    doc.autoTable({
        head: [['Delta', 'Src', 'Dst', 'Flags', 'Status', 'Analysis']],
        body: filteredData.slice(0, 40).map(p => [p.delta, p.src, p.dst, p.flags, p.status, p.analysis])
    });
    doc.save('network-tshoot.pdf');
};

window.onload = initCharts;
document.getElementById('filter-ip').oninput = applyFilters;
document.getElementById('filter-flags').oninput = applyFilters;
document.getElementById('filter-proto').onchange = applyFilters;
