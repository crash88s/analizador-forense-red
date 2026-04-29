let rawData = [];
let filteredData = [];
let protoChart, ipChart;
const criticalPorts = [21, 22, 23, 445, 3389];
const geoCache = new Map();

// Inicialización de gráficos
function initCharts() {
    const ctxProto = document.getElementById('chart-protocols').getContext('2d');
    const ctxIP = document.getElementById('chart-ips').getContext('2d');

    protoChart = new Chart(ctxProto, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d4ff', '#39ff14', '#f1c40f', '#e74c3c', '#9b59b6'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Protocolos Detectados', color: '#fff' } } }
    });

    ipChart = new Chart(ctxIP, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Paquetes', data: [], backgroundColor: '#00d4ff' }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { title: { display: true, text: 'Top IPs Origen', color: '#fff' } } }
    });
}

// Procesar Archivo JSON
document.getElementById('file-input').addEventListener('change', handleFile);
const dropZone = document.getElementById('drop-zone');
dropZone.onclick = () => document.getElementById('file-input').click();

function handleFile(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            const json = JSON.parse(event.target.result);
            parseWiresharkData(json);
        } catch (err) {
            alert("Error al procesar JSON. Asegúrate de exportar desde Wireshark como JSON.");
        }
    };
    reader.readAsText(file);
}

function parseWiresharkData(json) {
    rawData = json.map(packet => {
        const layers = packet._source.layers;
        return {
            timestamp: layers.frame["frame.time"],
            src_ip: layers.ip ? layers.ip["ip.src"] : (layers.ipv6 ? layers.ipv6["ipv6.src"] : "N/A"),
            dst_ip: layers.ip ? layers.ip["ip.dst"] : (layers.ipv6 ? layers.ipv6["ipv6.dst"] : "N/A"),
            proto: layers.frame["frame.protocols"].split(':').pop().toUpperCase(),
            port: layers.tcp ? layers.tcp["tcp.dstport"] : (layers.udp ? layers.udp["udp.dstport"] : "N/A"),
            info: layers.frame["frame.number"]
        };
    });
    
    populateProtocolFilter();
    applyFilters();
}

function populateProtocolFilter() {
    const protos = [...new Set(rawData.map(p => p.proto))];
    const select = document.getElementById('filter-proto');
    select.innerHTML = '<option value="all">Todos</option>';
    protos.forEach(p => {
        select.innerHTML += `<option value="${p}">${p}</option>`;
    });
}

async function applyFilters() {
    const fSrc = document.getElementById('filter-src-ip').value;
    const fDst = document.getElementById('filter-dst-ip').value;
    const fProto = document.getElementById('filter-proto').value;
    const fPort = document.getElementById('filter-port').value;

    filteredData = rawData.filter(p => {
        return (fSrc === "" || p.src_ip.includes(fSrc)) &&
               (fDst === "" || p.dst_ip.includes(fDst)) &&
               (fProto === "all" || p.proto === fProto) &&
               (fPort === "" || p.port == fPort);
    });

    updateUI();
}

function updateUI() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';
    let alerts = 0;

    // Renderizar tabla (limitado a 100 para rendimiento, pero filtrado sobre todo el set)
    filteredData.slice(0, 100).forEach(p => {
        const isCritical = criticalPorts.includes(parseInt(p.port));
        if (isCritical) alerts++;

        const row = `
            <tr class="${isCritical ? 'critical-port' : ''}">
                <td>${p.timestamp.split(' ')[3]}</td>
                <td>${p.src_ip}</td>
                <td>${p.dst_ip}</td>
                <td>${p.proto}</td>
                <td>${p.port}</td>
                <td class="geo" data-ip="${p.src_ip}">Consultando...</td>
                <td>Frame: ${p.info}</td>
            </tr>
        `;
        tbody.innerHTML += row;
    });

    // Actualizar Stats
    document.getElementById('stat-packets').innerText = filteredData.length;
    document.getElementById('stat-alerts').innerText = alerts;
    document.getElementById('stat-ips').innerText = [...new Set(filteredData.map(p => p.src_ip))].length;

    updateCharts();
    resolveGeoIP();
}

function updateCharts() {
    // Protocolos
    const protoCounts = {};
    filteredData.forEach(p => protoCounts[p.proto] = (protoCounts[p.proto] || 0) + 1);
    protoChart.data.labels = Object.keys(protoCounts);
    protoChart.data.datasets[0].data = Object.values(protoCounts);
    protoChart.update();

    // Top IPs
    const ipCounts = {};
    filteredData.forEach(p => ipCounts[p.src_ip] = (ipCounts[p.src_ip] || 0) + 1);
    const sortedIPs = Object.entries(ipCounts).sort((a,b) => b[1] - a[1]).slice(0, 5);
    ipChart.data.labels = sortedIPs.map(x => x[0]);
    ipChart.data.datasets[0].data = sortedIPs.map(x => x[1]);
    ipChart.update();
}

async function resolveGeoIP() {
    const geoCells = document.querySelectorAll('.geo');
    for (let cell of geoCells) {
        const ip = cell.getAttribute('data-ip');
        if (ip === "N/A" || ip.startsWith('192.168.') || ip.startsWith('10.')) {
            cell.innerText = "Local/Private";
            continue;
        }
        
        if (geoCache.has(ip)) {
            cell.innerText = geoCache.get(ip);
            continue;
        }

        try {
            const res = await fetch(`http://ip-api.com/json/${ip}?fields=country`);
            const data = await res.json();
            const country = data.country || "Unknown";
            geoCache.set(ip, country);
            cell.innerText = country;
        } catch (e) {
            cell.innerText = "Limit reached";
        }
    }
}

// Exportar Reporte PDF
document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
    doc.setFontSize(18);
    doc.text("SOC Forensic Traffic Report", 14, 20);
    doc.setFontSize(10);
    doc.text(`Total Packets Analyzed: ${filteredData.length}`, 14, 30);

    const tableRows = filteredData.slice(0, 50).map(p => [p.timestamp, p.src_ip, p.dst_ip, p.proto, p.port]);
    doc.autoTable({
        head: [['Timestamp', 'Source', 'Destination', 'Proto', 'Port']],
        body: tableRows,
        startY: 40
    });

    doc.save('soc-analysis-report.pdf');
};

// Eventos de filtros
['filter-src-ip', 'filter-dst-ip', 'filter-proto', 'filter-port'].forEach(id => {
    document.getElementById(id).addEventListener('input', applyFilters);
});

window.onload = initCharts;