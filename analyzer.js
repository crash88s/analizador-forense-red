let rawData = [];
let filteredData = [];
let protoChart, portsChart;
let showOnlyErrors = false;

function initCharts() {
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { 
            legend: { 
                position: 'top',
                labels: { color: '#888', font: { size: 10 } } 
            } 
        },
        scales: {
            y: { grid: { color: '#222' }, ticks: { color: '#555' } },
            x: { grid: { display: false }, ticks: { color: '#555' } }
        }
    };

    protoChart = new Chart(document.getElementById('chart-protocols'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f2ff', '#00ff41', '#f3ea5f', '#ff003c', '#9d00ff', '#ff8c00', '#00ced1'] }] },
        options: commonOptions
    });

    portsChart = new Chart(document.getElementById('chart-ports'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Paquetes por Puerto', data: [], backgroundColor: '#00f2ff' }] },
        options: commonOptions
    });
}

const fileInput = document.getElementById('file-input');
const dropZone = document.getElementById('drop-zone');

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
                
                // IMPORTANTE: Inicializar gráficas y LUEGO aplicar filtros para mostrar datos
                initCharts();
                applyFilters(); 
            }, 500);
        } catch (err) {
            alert("Error: El archivo no es un JSON válido.");
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
            if (f["tcp.flags.fin"] == "1") flags.push("FIN");
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
            flags: flags.join(','),
            level: level,
            status: status
        };
    });

    const protos = [...new Set(rawData.map(p => p.proto))];
    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">Todos los Protocolos</option>';
    protos.forEach(pr => select.innerHTML += `<option value="${pr}">${pr}</option>`);
}

function applyFilters() {
    const src = document.getElementById('filter-src-ip').value.toLowerCase();
    const dst = document.getElementById('filter-dst-ip').value.toLowerCase();
    const proto = document.getElementById('filter-proto').value;
    const flags = document.getElementById('filter-flags').value.toUpperCase();

    filteredData = rawData.filter(p => {
        return (src === "" || p.src.toLowerCase().includes(src)) &&
               (dst === "" || p.dst.toLowerCase().includes(dst)) &&
               (proto === "all" || p.proto === proto) &&
               (flags === "" || p.flags.includes(flags)) &&
               (!showOnlyErrors || p.level !== "normal");
    });

    updateUI();
}

function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    
    // Mostramos los primeros 200 paquetes para fluidez
    filteredData.slice(0, 200).forEach(p => {
        const tr = document.createElement('tr');
        tr.className = `row-${p.level}`;
        tr.innerHTML = `
            <td>${p.delta}</td>
            <td>${p.src}</td>
            <td>${p.dst}</td>
            <td>${p.flags || '---'}</td>
            <td>${p.port}</td>
            <td>${p.status}</td>
        `;
        tbody.appendChild(tr);
    });

    // Actualizar KPIs del Header
    document.getElementById('stat-packets').innerText = filteredData.length.toLocaleString();
    document.getElementById('stat-alerts').innerText = filteredData.filter(p => p.level === 'critical').length;
    document.getElementById('stat-ips').innerText = [...new Set(filteredData.map(p => p.src))].length;

    updateCharts();
}

function updateCharts() {
    if (!protoChart || !portsChart) return;

    // Gráfico de Protocolos
    const protoMap = {};
    filteredData.forEach(p => protoMap[p.proto] = (protoMap[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(protoMap);
    protoChart.data.datasets[0].data = Object.values(protoMap);
    protoChart.update();

    // Gráfico de Puertos
    const portMap = {};
    filteredData.filter(p => p.port !== "N/A").forEach(p => portMap[p.port] = (portMap[p.port] || 0) + 1);
    const sortedPorts = Object.entries(portMap).sort((a,b) => b[1]-a[1]).slice(0, 8);
    portsChart.data.labels = sortedPorts.map(x => x[0]);
    portsChart.data.datasets[0].data = sortedPorts.map(x => x[1]);
    portsChart.update();
}

// Escuchadores de eventos para filtros reactivos
document.getElementById('filter-src-ip').addEventListener('input', applyFilters);
document.getElementById('filter-dst-ip').addEventListener('input', applyFilters);
document.getElementById('filter-proto').addEventListener('change', applyFilters);
document.getElementById('filter-flags').addEventListener('input', applyFilters);

document.getElementById('btn-only-errors').onclick = function() {
    showOnlyErrors = !showOnlyErrors;
    this.classList.toggle('btn-warn'); // Solo efecto visual de activo
    applyFilters();
};

document.getElementById('btn-reset').onclick = () => location.reload();

document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(14);
    doc.text("Tshoot Tool Forensic Report", 14, 15);
    doc.setFontSize(10);
    doc.text("Analista: Selvin Mejia", 14, 22);
    
    const rows = filteredData.slice(0, 50).map(p => [p.delta, p.src, p.dst, p.port, p.status]);
    doc.autoTable({
        head: [['Delta', 'Origen', 'Destino', 'Puerto', 'Estado']],
        body: rows,
        startY: 30
    });
    doc.save('tshoot_report_selvin_mejia.pdf');
};
