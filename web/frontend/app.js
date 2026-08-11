document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const statusBadge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const dropzone = document.getElementById('dropzone');
    const pcapInput = document.getElementById('pcapInput');
    const selectedFileInfo = document.getElementById('selectedFileInfo');
    
    const btnAnalyze = document.getElementById('btnAnalyze');
    const btnSample = document.getElementById('btnSample');
    
    const progressBanner = document.getElementById('progressBanner');
    const progressStep = document.getElementById('progressStep');
    const errorBanner = document.getElementById('errorBanner');
    const errorMessage = document.getElementById('errorMessage');
    const resultsContainer = document.getElementById('resultsContainer');
    
    // Metric Elements
    const valTotalPackets = document.getElementById('valTotalPackets');
    const valForwardedVsDropped = document.getElementById('valForwardedVsDropped');
    const valTotalBytes = document.getElementById('valTotalBytes');
    const valAnalysisPps = document.getElementById('valAnalysisPps');
    const valAnalysisBps = document.getElementById('valAnalysisBps');
    const valActiveFlows = document.getElementById('valActiveFlows');
    const valBlockedCount = document.getElementById('valBlockedCount');
    const valDropRate = document.getElementById('valDropRate');
    
    // Bars
    const barTcp = document.getElementById('barTcp');
    const barUdp = document.getElementById('barUdp');
    const barOther = document.getElementById('barOther');
    const lblTcpCount = document.getElementById('lblTcpCount');
    const lblUdpCount = document.getElementById('lblUdpCount');
    const lblOtherCount = document.getElementById('lblOtherCount');
    
    // Tables
    const tblApplications = document.getElementById('tblApplications');
    const tblDomains = document.getElementById('tblDomains');
    const tblFlows = document.getElementById('tblFlows');

    let selectedFile = null;

    // Check Backend Status
    async function checkStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            if (data.status === 'ready') {
                statusBadge.className = 'badge status-badge ready';
                statusText.textContent = 'C++ Engine Ready';
            } else {
                statusBadge.className = 'badge status-badge error';
                statusText.textContent = 'C++ Binary Missing';
            }
        } catch (e) {
            statusBadge.className = 'badge status-badge error';
            statusText.textContent = 'Server Offline';
        }
    }
    checkStatus();

    // File Drag and Drop Handlers
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    pcapInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });

    function handleFileSelect(file) {
        if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
            showError('Please select a valid .pcap or .pcapng file');
            return;
        }
        selectedFile = file;
        selectedFileInfo.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
        hideError();
    }

    // Format Helpers
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatNumber(num) {
        return num.toLocaleString();
    }

    function getSelectedRules() {
        const apps = [];
        if (document.getElementById('blockAppYouTube').checked) apps.push('YouTube');
        if (document.getElementById('blockAppFacebook').checked) apps.push('Facebook');
        if (document.getElementById('blockAppTikTok').checked) apps.push('TikTok');
        if (document.getElementById('blockAppNetflix').checked) apps.push('Netflix');

        const domains = [];
        const customDom = document.getElementById('customDomain').value.trim();
        if (customDom) domains.push(customDom);

        return { block_apps: apps, block_domains: domains };
    }

    // Execute Analysis
    btnAnalyze.addEventListener('click', async () => {
        if (!selectedFile) {
            showError('Please select a PCAP file first or click "Run Sample PCAP"');
            return;
        }

        const formData = new FormData();
        formData.append('pcap_file', selectedFile);
        const rules = getSelectedRules();
        if (rules.block_apps.length > 0) formData.append('block_apps', rules.block_apps.join(','));
        if (rules.block_domains.length > 0) formData.append('block_domains', rules.block_domains.join(','));

        await runAnalysisRequest('/api/analyze', formData, false);
    });

    btnSample.addEventListener('click', async () => {
        const rules = getSelectedRules();
        const payload = {
            sample_filename: 'test_dpi.pcap',
            block_apps: rules.block_apps,
            block_domains: rules.block_domains
        };
        await runAnalysisRequest('/api/analyze', JSON.stringify(payload), true);
    });

    async function runAnalysisRequest(url, bodyData, isJson) {
        hideError();
        showProgress('Launching C++ DPI Engine Subprocess...');
        resultsContainer.classList.add('hidden');

        try {
            const options = {
                method: 'POST',
                body: bodyData
            };
            if (isJson) {
                options.headers = { 'Content-Type': 'application/json' };
            }

            const res = await fetch(url, options);
            const data = await res.json();

            if (!res.ok || data.status === 'error') {
                showError(data.message || 'DPI analysis failed');
                return;
            }

            renderResults(data);
        } catch (err) {
            showError('Network error communicating with local dashboard server: ' + err.message);
        } finally {
            hideProgress();
        }
    }

    function renderResults(data) {
        const summary = data.summary || {};
        const protocols = data.protocols || {};
        const apps = data.applications || [];
        const domains = data.domains || [];
        const flows = data.flows || [];

        // 1. Metrics
        const totalPkts = summary.total_packets || 0;
        const totalBytes = summary.total_bytes || 0;
        const fwdPkts = summary.forwarded_packets || 0;
        const dropPkts = summary.dropped_packets || 0;
        const pps = summary.packets_per_second || 0;
        const mbps = summary.mb_per_second || 0;

        valTotalPackets.textContent = formatNumber(totalPkts);
        valForwardedVsDropped.textContent = `Forwarded: ${formatNumber(fwdPkts)} | Dropped: ${formatNumber(dropPkts)}`;
        valTotalBytes.textContent = formatBytes(totalBytes);
        valAnalysisPps.textContent = `${formatNumber(Math.round(pps))} pkts/s`;
        valAnalysisBps.textContent = `${mbps.toFixed(2)} MB/s`;
        valActiveFlows.textContent = formatNumber(flows.length);
        valBlockedCount.textContent = formatNumber(dropPkts);

        const dropRate = totalPkts > 0 ? ((dropPkts / totalPkts) * 100).toFixed(2) : '0.00';
        valDropRate.textContent = `${dropRate}% Drop Rate`;

        // 2. Protocol Bars
        const tcpCount = protocols.TCP || 0;
        const udpCount = protocols.UDP || 0;
        const otherCount = protocols.Other || 0;
        const protoTotal = totalPkts > 0 ? totalPkts : 1;

        barTcp.style.width = `${((tcpCount / protoTotal) * 100).toFixed(1)}%`;
        barUdp.style.width = `${((udpCount / protoTotal) * 100).toFixed(1)}%`;
        barOther.style.width = `${((otherCount / protoTotal) * 100).toFixed(1)}%`;

        lblTcpCount.textContent = `${formatNumber(tcpCount)} pkts (${((tcpCount / protoTotal) * 100).toFixed(1)}%)`;
        lblUdpCount.textContent = `${formatNumber(udpCount)} pkts (${((udpCount / protoTotal) * 100).toFixed(1)}%)`;
        lblOtherCount.textContent = `${formatNumber(otherCount)} pkts (${((otherCount / protoTotal) * 100).toFixed(1)}%)`;

        // 3. Applications Table
        if (apps.length === 0) {
            tblApplications.innerHTML = '<tr><td colspan="5" class="empty-cell">No applications detected</td></tr>';
        } else {
            tblApplications.innerHTML = apps.map(app => `
                <tr>
                    <td><strong>${app.name}</strong></td>
                    <td class="font-mono">${app.flows}</td>
                    <td class="font-mono">${formatNumber(app.packets)}</td>
                    <td class="font-mono">${formatBytes(app.bytes)}</td>
                    <td><span class="pill-status ${app.status}">${app.status}</span></td>
                </tr>
            `).join('');
        }

        // 4. Domains Table
        if (domains.length === 0) {
            tblDomains.innerHTML = '<tr><td colspan="4" class="empty-cell">No domain inspection metadata found</td></tr>';
        } else {
            tblDomains.innerHTML = domains.map(d => `
                <tr>
                    <td class="font-mono">${d.domain}</td>
                    <td>${d.application}</td>
                    <td class="font-mono">${formatNumber(d.packets)}</td>
                    <td><span class="pill-status ${d.status}">${d.status}</span></td>
                </tr>
            `).join('');
        }

        // 5. Flows Table (limit to first 50 rows for snappy performance)
        if (flows.length === 0) {
            tblFlows.innerHTML = '<tr><td colspan="8" class="empty-cell">No flow connections tracked</td></tr>';
        } else {
            const displayFlows = flows.slice(0, 50);
            tblFlows.innerHTML = displayFlows.map(f => `
                <tr>
                    <td class="font-mono">${f.flow}</td>
                    <td class="font-mono">${f.protocol}</td>
                    <td>${f.application}</td>
                    <td class="font-mono">${f.domain || '-'}</td>
                    <td><span class="pill-status ${f.state}">${f.state}</span></td>
                    <td class="font-mono">${formatNumber(f.packets)}</td>
                    <td class="font-mono">${formatBytes(f.bytes)}</td>
                    <td><span class="pill-status ${f.action}">${f.action}</span></td>
                </tr>
            `).join('');
        }

        resultsContainer.classList.remove('hidden');
    }

    function showProgress(stepMsg) {
        progressStep.textContent = stepMsg;
        progressBanner.classList.remove('hidden');
    }

    function hideProgress() {
        progressBanner.classList.add('hidden');
    }

    function showError(msg) {
        errorMessage.textContent = msg;
        errorBanner.classList.remove('hidden');
    }

    function hideError() {
        errorBanner.classList.add('hidden');
    }
});
