let rawData = [];
let filteredData = [];
let timelineChart, protoChart;
let showOnlyErrors = false;

// Inicializar Gráficas
function initCharts() {
    const ctxTime = document.getElementById('chart-timeline').getContext('2d');
    const ctxProto = document.getElementById('chart-protocols').getContext('2d');

    timelineChart = new Chart(ctxTime, {
        type: 'line',
        data: { labels: [], datasets: [{ 
            label: 'Paquetes por Segundo', 
            data: [], 
            borderColor: '#39ff14', 
            backgroundColor: 'rgba(57, 255, 20, 0.1)',
            fill: true,
            tension: 0.4 
        }]},
        options: { 
            responsive: true, 
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#fff' } } },
            scales: { 
                x: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
                y: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } }
            }
        }
    });

    protoChart = new Chart(ctxProto, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d4ff', '#39ff14', '#f1c40f', '#e74c3c', '#9b59b6'] }] },
        options: { 
            responsive: true, 
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: '#fff' } } }
        }
    });
}

// Carga de Archivo
document.getElementById('file-input').addEventListener('change', handleFile);
document.getElementById('drop-zone').onclick = () => document.getElementById('file-input').click();

function handleFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            const json = JSON.parse(event.target.result);
            processData(json);
        } catch (err) { alert("Error al leer JSON de Wireshark."); }
    };
    reader.readAsText(file);
}

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

        let level = "success";
        let analysis = "OK";
        if (tcp["tcp.analysis.retransmission"]) { level = "warning"; analysis = "Retransmission"; }
        if (flags.includes("RST")) { level = "critical"; analysis = "Connection Reset"; }
        
        let status = "TCP/UDP";
        if (http["http.response.code"]) {
            status = `HTTP ${http["http.response.code"]}`;
            if (parseInt(http["http.response.code"]) >= 400) level = "critical";
        }

        return {
            delta: parseFloat(l.frame["frame.time_delta"] || 0).toFixed(4),
            epoch: parseFloat(l.frame["frame.time_epoch"]),
            src: ip["ip.src"] || "N/A",
            dst: ip["ip.dst"] || "N/A",
            proto: l.frame["frame.protocols"].split(':').pop().toUpperCase(),
            size: parseInt(l.frame["frame.len"]),
            flags: flags.join(','),
            status: status,
            analysis: analysis,
            level: level
        };
    });

    populateProtos();
    applyFilters();
}

function populateProtos() {
    const protos = [...new Set(rawData.map(p => p.proto))];
    const sel = document.getElementById('filter-proto');
    sel.innerHTML = '<option value="all">Todos</option>';
    protos.forEach(pr => sel.innerHTML += `<option value="${pr}">${pr}</option>`);
}

function applyFilters() {
    const src = document.getElementById('filter-src-ip').value.toLowerCase();
    const dst = document.getElementById('filter-dst-ip').value.toLowerCase();
    const proto = document.getElementById('filter-proto').value;
    const flags = document.getElementById('filter-flags').value.toUpperCase();

    filteredData = rawData.filter(p => {
        const matchSrc = p.src.toLowerCase().includes(src);
        const matchDst = p.dst.toLowerCase().includes(dst);
        const matchProto = proto === "all" || p.proto === proto;
        const matchFlags = flags === "" || p.flags.includes(flags);
        const matchError = showOnlyErrors ? p.level !== "success" : true;
        return matchSrc && matchDst && matchProto && matchFlags && matchError;
    });

    updateUI();
}

function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    let totalBytes = 0;
    let alerts = 0;

    filteredData.slice(0, 300).forEach(p => {
        if (p.level !== 'success') alerts++;
        totalBytes += p.size;
        
        const tr = document.createElement('tr');
        tr.className = `row-${p.level}`;
        tr.innerHTML = `
            <td>${p.delta} s</td>
            <td>${p.src}</td>
            <td>${p.dst}</td>
            <td>${p.flags}</td>
            <td>${p.size} B</td>
            <td>${p.status}</td>
            <td>${p.analysis}</td>
        `;
        tbody.appendChild(tr);
    });

    // Cálculo de Throughput: (Suma Bytes * 8 bits) / (Tiempo Total en segundos)
    if (filteredData.length > 1) {
        const startTime = filteredData[0].epoch;
        const endTime = filteredData[filteredData.length - 1].epoch;
        const duration = endTime - startTime;
        if (duration > 0) {
            const mbps = ((totalBytes * 8) / (duration * 1000000)).toFixed(2);
            document.getElementById('stat-throughput').innerText = `${mbps} Mbps`;
        }
    }

    document.getElementById('stat-packets').innerText = filteredData.length;
    document.getElementById('stat-alerts').innerText = alerts;

    updateCharts();
}

function updateCharts() {
    // 1. Timeline Chart (PPS)
    const ppsData = {};
    filteredData.forEach(p => {
        const sec = Math.floor(p.epoch);
        ppsData[sec] = (ppsData[sec] || 0) + 1;
    });

    const labels = Object.keys(ppsData).sort();
    timelineChart.data.labels = labels.map(l => new Date(l * 1000).toLocaleTimeString());
    timelineChart.data.datasets[0].data = labels.map(l => ppsData[l]);
    timelineChart.update();

    // 2. Protocols Chart
    const protoData = {};
    filteredData.forEach(p => protoData[p.proto] = (protoData[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(protoData);
    protoChart.data.datasets[0].data = Object.values(protoData);
    protoChart.update();
}

// Eventos de Filtro
document.getElementById('filter-src-ip').oninput = applyFilters;
document.getElementById('filter-dst-ip').oninput = applyFilters;
document.getElementById('filter-proto').onchange = applyFilters;
document.getElementById('filter-flags').oninput = applyFilters;

document.getElementById('btn-only-errors').onclick = function() {
    showOnlyErrors = !showOnlyErrors;
    this.classList.toggle('active');
    applyFilters();
};

// Exportar PDF
document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text("Reporte de Análisis Forense de Red", 14, 20);
    doc.setFontSize(10);
    doc.text(`Generado por SOC Analyzer - Selvin Mejia`, 14, 30);
    
    const rows = filteredData.slice(0, 50).map(p => [p.delta, p.src, p.dst, p.proto, p.size, p.analysis]);
    doc.autoTable({
        head: [['Delta', 'Origen', 'Destino', 'Proto', 'Size', 'Análisis']],
        body: rows,
        startY: 40
    });
    doc.save('analisis-trafico.pdf');
};

window.onload = initCharts;
