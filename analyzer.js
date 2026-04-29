let rawData = [];
let filteredData = [];
let protoChart, portsChart;
let showOnlyErrors = false;

// Configuración Inicial de Gráficos
function initCharts() {
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#fff', font: { family: 'Courier' } } } }
    };

    protoChart = new Chart(document.getElementById('chart-protocols'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff'] }] },
        options: commonOptions
    });

    portsChart = new Chart(document.getElementById('chart-ports'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Top Puertos', data: [], backgroundColor: '#00f2ff' }] },
        options: commonOptions
    });
}

// Lógica de Carga de Archivo
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

dropZone.onclick = () => fileInput.click();

fileInput.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Mostrar barra de carga
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
            // Simular un pequeño delay para que se vea la barra llena
            setTimeout(() => {
                document.getElementById('landing-screen').classList.add('hidden');
                document.getElementById('main-dashboard').classList.remove('hidden');
                initCharts();
                updateUI();
            }, 800);
        } catch (err) {
            alert("Error: El archivo no es un JSON válido de Wireshark.");
            document.getElementById('progress-container').classList.add('hidden');
        }
    };
    reader.readAsText(file);
};

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
        }

        let level = "normal";
        let status = "OK";
        if (tcp["tcp.analysis.retransmission"] || tcp["tcp.analysis.duplicate_ack"]) {
            level = "warning";
            status = "Retransmisión/Dup ACK";
        }
        if (flags.includes("RST") || (http["http.response.code"] >= 400)) {
            level = "critical";
            status = "Critical Error/RST";
        }

        return {
            delta: parseFloat(l.frame["frame.time_delta"] || 0).toFixed(4),
            src: ip["ip.src"] || "N/A",
            dst: ip["ip.dst"] || "N/A",
            proto: l.frame["frame.protocols"].split(':').pop().toUpperCase(),
            port: tcp["tcp.dstport"] || udp["udp.dstport"] || "N/A",
            size: l.frame["frame.len"],
            flags: flags.join(','),
            level: level,
            status: status
        };
    });

    // Llenar select de protocolos
    const protos = [...new Set(rawData.map(p => p.proto))];
    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">Todos los Protocolos</option>';
    protos.forEach(pr => select.innerHTML += `<option value="${pr}">${pr}</option>`);
}

function applyFilters() {
    const src = document.getElementById('filter-src-ip').value;
    const dst = document.getElementById('filter-dst-ip').value;
    const proto = document.getElementById('filter-proto').value;
    const flags = document.getElementById('filter-flags').value.toUpperCase();

    filteredData = rawData.filter(p => {
        return (src === "" || p.src.includes(src)) &&
               (dst === "" || p.dst.includes(dst)) &&
               (proto === "all" || p.proto === proto) &&
               (flags === "" || p.flags.includes(flags)) &&
               (!showOnlyErrors || p.level !== "normal");
    });

    updateUI();
}

function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    
    filteredData.slice(0, 150).forEach(p => {
        const tr = document.createElement('tr');
        tr.className = `row-${p.level}`;
        tr.innerHTML = `
            <td>${p.delta}</td>
            <td>${p.src}</td>
            <td>${p.dst}</td>
            <td>${p.flags}</td>
            <td>${p.port}</td>
            <td>${p.status}</td>
        `;
        tbody.appendChild(tr);
    });

    document.getElementById('stat-packets').innerText = filteredData.length;
    document.getElementById('stat-alerts').innerText = filteredData.filter(p => p.level === 'critical').length;
    document.getElementById('stat-ips').innerText = [...new Set(filteredData.map(p => p.src))].length;

    updateCharts();
}

function updateCharts() {
    if (!protoChart) return;

    // Protocolos
    const protoMap = {};
    filteredData.forEach(p => protoMap[p.proto] = (protoMap[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(protoMap);
    protoChart.data.datasets[0].data = Object.values(protoMap);
    protoChart.update();

    // Top Ports
    const portMap = {};
    filteredData.filter(p => p.port !== "N/A").forEach(p => portMap[p.port] = (portMap[p.port] || 0) + 1);
    const sortedPorts = Object.entries(portMap).sort((a,b) => b[1]-a[1]).slice(0, 5);
    portsChart.data.labels = sortedPorts.map(x => x[0]);
    portsChart.data.datasets[0].data = sortedPorts.map(x => x[1]);
    portsChart.update();
}

// Eventos
document.getElementById('filter-src-ip').oninput = applyFilters;
document.getElementById('filter-dst-ip').oninput = applyFilters;
document.getElementById('filter-proto').onchange = applyFilters;
document.getElementById('filter-flags').oninput = applyFilters;

document.getElementById('btn-only-errors').onclick = function() {
    showOnlyErrors = !showOnlyErrors;
    this.classList.toggle('btn-neon-blue');
    applyFilters();
};

document.getElementById('btn-reset').onclick = () => location.reload();

document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.text("Tshoot Tool Report - Selvin Mejia", 14, 15);
    doc.autoTable({
        head: [['Delta', 'Origen', 'Destino', 'Port', 'Status']],
        body: filteredData.slice(0, 50).map(p => [p.delta, p.src, p.dst, p.port, p.status])
    });
    doc.save('tshoot-report.pdf');
};
