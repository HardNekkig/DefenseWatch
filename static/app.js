import { fetchJSON, formatTime, formatTimeShort, countryFlag, severityBadge, eventTypeBadge, truncate, formatNumber, escapeHtml, getAuthToken, setAuthToken, clearAuthToken, getAuthHeaders, postJSON, patchJSON } from './utils.js';
import { LiveSocket } from './ws.js';
import { initCharts, updateSSHTimeline, updateHTTPTimeline, updateCountries, updateAttackTypes, updateUsernames, updateEndpoints, updateASNs } from './charts.js';
import { initMap, loadArcs, invalidateMap, refreshMapOnEvent } from './map.js';

// ── Auth: patch global fetch to inject Bearer token for /api calls ──
const _origFetch = window.fetch;
window.fetch = function(url, opts = {}) {
    const token = getAuthToken();
    if (token && typeof url === 'string' && url.startsWith('/api')) {
        opts.headers = { ...(opts.headers || {}), 'Authorization': `Bearer ${token}` };
    }
    return _origFetch.call(this, url, opts);
};

// State
let currentSection = 'dashboard';
let authEnabled = false;
let sshPage = 1, httpPage = 1, intelPage = 1, incidentPage = 1, svcPage = 1;
let mapInitialized = false;
let currentEvtab = 'ssh';

// Navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const section = btn.dataset.section;
        if (section) showSection(section);
    });
});

// Navigation dropdown items
document.querySelectorAll('.nav-dropdown-item').forEach(item => {
    item.addEventListener('click', () => {
        const section = item.dataset.section;
        if (section) showSection(section);
    });
});

function showSection(name) {
    currentSection = name;
    document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
    document.getElementById(`section-${name}`)?.classList.remove('hidden');

    // Update active state for both nav buttons and dropdown items
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.section === name));
    document.querySelectorAll('.nav-dropdown-item').forEach(b => b.classList.toggle('active', b.dataset.section === name));

    if (name === 'map') {
        if (!mapInitialized) {
            initMap().then(() => { mapInitialized = true; loadArcs(); });
        } else {
            invalidateMap();
            loadArcs();
        }
    } else if (name === 'events') {
        loadEvtab(currentEvtab);
    } else if (name === 'intel') {
        loadIntel();
    } else if (name === 'incidents') {
        loadIncidents();
    } else if (name === 'scanner') {
        loadScannerView();
    } else if (name === 'firewall') {
        loadFirewallView();
    } else if (name === 'honeypot') {
        loadHoneypotView();
    } else if (name === 'audit') {
        loadAuditView();
    } else if (name === 'playbooks') {
        loadPlaybooksView();
    } else if (name === 'geo-policy') {
        loadGeoPolicyView();
    } else if (name === 'system') {
        loadSystemView();
    } else if (name === 'settings') {
        loadSettingsView();
    }
}

// WebSocket
const liveSocket = new LiveSocket(handleWSMessage, handleWSStatus);

function handleWSStatus(connected) {
    const dot = document.getElementById('ws-dot');
    const label = document.getElementById('ws-label');
    dot.className = `w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`;
    label.textContent = connected ? 'Connected' : 'Disconnected';
}

function handleWSMessage(msg) {
    if (msg.type === 'ssh_event' || msg.type === 'http_event' || msg.type === 'brute_force' || msg.type === 'service_event' || msg.type === 'port_scan') {
        addFeedItem(msg);
        if (currentSection === 'map' && (msg.type === 'ssh_event' || msg.type === 'http_event')) {
            refreshMapOnEvent();
        }
    }
    if (msg.type === 'service_event' && currentSection === 'events' && currentEvtab === 'services') {
        loadServiceEvents();
    }
    if (msg.type === 'port_scan' && currentSection === 'events' && currentEvtab === 'portscans') {
        loadPortScans();
    }
    if (msg.type === 'stats_update') {
        loadSummary();
    }
    if (msg.type === 'scan_status' || msg.type === 'scan_batch_start' || msg.type === 'scan_batch_complete') {
        if (currentSection === 'scanner') {
            updateScannerStatus(msg.data || msg);
        }
    }
    if (msg.type === 'nuclei_finding') {
        if (currentSection === 'scanner') {
            appendLiveFinding(msg.data || msg);
            updateLiveSeverityCounts(msg.data || msg);
        }
    }
    if (msg.type === 'firewall_block') {
        if (currentSection === 'firewall') {
            loadFirewallView();
        }
    }
}

// Live Feed
const feedEl = document.getElementById('live-feed');
let feedCount = 0;

function addFeedItem(msg) {
    const item = document.createElement('div');
    item.className = 'feed-item new';

    const time = formatTimeShort(msg.timestamp);
    const d = msg.data;

    if (msg.type === 'ssh_event') {
        item.innerHTML = `
            <span class="text-gray-500 w-20">${time}</span>
            ${eventTypeBadge(d.event_type)}
            <span class="text-red-400">${d.source_ip}</span>
            <span class="text-gray-500">user:</span>
            <span>${d.username || '-'}</span>
        `;
    } else if (msg.type === 'http_event') {
        item.innerHTML = `
            <span class="text-gray-500 w-20">${time}</span>
            ${severityBadge(d.severity)}
            <span class="text-orange-400">${d.source_ip}</span>
            <span class="text-gray-400">${d.method}</span>
            <span class="text-gray-300">${truncate(d.path, 30)}</span>
        `;
    } else if (msg.type === 'brute_force') {
        item.innerHTML = `
            <span class="text-gray-500 w-20">${time}</span>
            <span class="badge badge-critical">BRUTE FORCE</span>
            <span class="text-red-400">${d.source_ip}</span>
            <span>${d.attempt_count} attempts</span>
        `;
    } else if (msg.type === 'port_scan') {
        item.innerHTML = `
            <span class="text-gray-500 w-20">${time}</span>
            <span class="badge badge-investigating">PORT SCAN</span>
            <span class="text-purple-400">${d.source_ip}</span>
            <span>${d.port_count} ports: ${(d.ports_hit || []).join(', ')}</span>
        `;
    } else if (msg.type === 'service_event') {
        item.innerHTML = `
            <span class="text-gray-500 w-20">${time}</span>
            <span class="badge badge-info">${d.service_type}</span>
            ${severityBadge(d.severity)}
            <span class="text-orange-400">${d.source_ip || '-'}</span>
            <span class="text-gray-300">${truncate(d.detail || d.event_type, 30)}</span>
        `;
    }

    feedEl.insertBefore(item, feedEl.firstChild);
    feedCount++;
    if (feedCount > 200) {
        feedEl.removeChild(feedEl.lastChild);
        feedCount--;
    }
}

// Summary stats
async function loadSummary() {
    try {
        const data = await fetchJSON('/api/stats/summary');
        document.getElementById('stat-ssh').textContent = formatNumber(data.ssh_events);
        document.getElementById('stat-http').textContent = formatNumber(data.http_events);
        document.getElementById('stat-ips').textContent = formatNumber(data.unique_ips);
        document.getElementById('stat-brute').textContent = formatNumber(data.brute_forces);
        document.getElementById('stat-portscans').textContent = formatNumber(data.port_scans || 0);
        document.getElementById('stat-countries').textContent = formatNumber(data.countries);
    } catch (e) {
        console.error('Failed to load summary:', e);
    }
}

// Dashboard data
async function loadDashboardData() {
    const hours = document.getElementById('dashboard-range')?.value || 24;
    try {
        const [sshStats, httpStats, geoStats] = await Promise.all([
            fetchJSON(`/api/stats/ssh?hours=${hours}`),
            fetchJSON(`/api/stats/http?hours=${hours}`),
            fetchJSON('/api/stats/geo'),
        ]);

        updateSSHTimeline(sshStats);
        updateHTTPTimeline(httpStats);
        updateCountries(geoStats);
        updateAttackTypes(httpStats);
        updateUsernames(sshStats);
        updateEndpoints(httpStats);
        updateASNs(sshStats);
    } catch (e) {
        console.error('Failed to load dashboard data:', e);
    }
    loadTopIPs();
}

async function loadTopIPs() {
    const hours = document.getElementById('dashboard-range')?.value || 24;
    try {
        const data = await fetchJSON(`/api/stats/top-ips?hours=${hours}&limit=15`);
        const tbody = document.getElementById('dashboard-top-ips-body');
        if (!data.ips || data.ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-gray-500 text-center">No active IPs</td></tr>';
            return;
        }
        tbody.innerHTML = data.ips.map(ip => {
            const rowClass = ip.multi_attack ? 'style="background:rgba(239,68,68,0.08)"' : '';
            const tags = ip.attack_types.map(t => {
                const cls = ip.multi_attack ? 'badge-critical' : (t === 'ssh' ? 'badge-high' : t === 'http' ? 'badge-medium' : t === 'port_scan' ? 'badge-investigating' : 'badge-open');
                return `<span class="badge ${cls}">${t}</span>`;
            }).join(' ');
            return `<tr ${rowClass}>
                <td><a href="#" onclick="showIP('${escapeHtml(ip.ip)}');return false">${escapeHtml(ip.ip)}</a></td>
                <td>${ip.country_code ? countryFlag(ip.country_code) + ' ' + escapeHtml(ip.country_name || ip.country_code) : '-'}</td>
                <td>${escapeHtml(ip.org || '-')}</td>
                <td>${formatNumber(ip.ssh_count)}</td>
                <td>${formatNumber(ip.http_count)}</td>
                <td>${formatNumber(ip.brute_count)}</td>
                <td>${formatNumber(ip.portscan_count || 0)}</td>
                <td class="font-medium">${formatNumber(ip.total)}</td>
                <td>${tags}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('Failed to load top IPs:', e);
    }
}

// Recent events for live feed
async function loadRecentEvents() {
    try {
        const data = await fetchJSON('/api/events/recent?limit=30');
        for (const event of data.events.reverse()) {
            const msg = {
                type: event.source === 'ssh' ? 'ssh_event' : 'http_event',
                timestamp: event.timestamp,
                data: event,
            };
            addFeedItem(msg);
        }
    } catch (e) {
        console.error('Failed to load recent events:', e);
    }
}

// Sort state per table
let sortState = { ssh: { col: null, order: 'desc' }, http: { col: null, order: 'desc' } };

function toggleSort(table, col) {
    const st = sortState[table];
    if (st.col === col) {
        st.order = st.order === 'desc' ? 'asc' : 'desc';
    } else {
        st.col = col;
        st.order = 'desc';
    }
    // Update header indicators
    document.querySelectorAll(`.sortable-th[data-table="${table}"]`).forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sort === col) th.classList.add(st.order === 'asc' ? 'sort-asc' : 'sort-desc');
    });
    if (table === 'ssh') { sshPage = 1; loadSSHEvents(); }
    else if (table === 'http') { httpPage = 1; loadHTTPEvents(); }
}

document.querySelectorAll('.sortable-th').forEach(th => {
    th.addEventListener('click', () => toggleSort(th.dataset.table, th.dataset.sort));
});

// SSH Events table
async function loadSSHEvents() {
    const ip = document.getElementById('ssh-filter-ip')?.value || '';
    const country = document.getElementById('ssh-filter-country')?.value || '';
    const org = document.getElementById('ssh-filter-org')?.value || '';
    const username = document.getElementById('ssh-filter-username')?.value || '';
    const type = document.getElementById('ssh-filter-type')?.value || '';
    let url = `/api/events/ssh?page=${sshPage}&limit=50`;
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (country) url += `&country=${encodeURIComponent(country)}`;
    if (org) url += `&org=${encodeURIComponent(org)}`;
    if (username) url += `&username=${encodeURIComponent(username)}`;
    if (type) url += `&type=${encodeURIComponent(type)}`;
    if (sortState.ssh.col) url += `&sort=${sortState.ssh.col}&order=${sortState.ssh.order}`;

    try {
        const data = await fetchJSON(url);
        const tbody = document.getElementById('ssh-table-body');
        tbody.innerHTML = data.events.map(e => `
            <tr>
                <td>${formatTime(e.timestamp)}</td>
                <td><a href="#" onclick="showIP('${escapeHtml(e.source_ip)}');return false">${e.source_ip}</a></td>
                <td>${e.country_code ? countryFlag(e.country_code) + ' ' + (e.country_name || e.country_code) : '-'}</td>
                <td>${truncate(e.org || '-', 30)}</td>
                <td>${e.username || '-'}</td>
                <td>${eventTypeBadge(e.event_type)}</td>
                <td>${e.source_port || '-'}</td>
                <td class="font-mono">${e.service_port || '-'}</td>
            </tr>
        `).join('');

        const totalPages = Math.ceil(data.total / data.limit) || 1;
        document.getElementById('ssh-page-info').textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
        document.getElementById('ssh-prev').disabled = data.page <= 1;
        document.getElementById('ssh-next').disabled = data.page >= totalPages;
    } catch (e) {
        console.error('Failed to load SSH events:', e);
    }
}

// HTTP Events table
async function loadHTTPEvents() {
    const ip = document.getElementById('http-filter-ip')?.value || '';
    const country = document.getElementById('http-filter-country')?.value || '';
    const org = document.getElementById('http-filter-org')?.value || '';
    const severity = document.getElementById('http-filter-severity')?.value || '';
    const vhost = document.getElementById('http-filter-vhost')?.value || '';
    let url = `/api/events/http?page=${httpPage}&limit=50`;
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (country) url += `&country=${encodeURIComponent(country)}`;
    if (org) url += `&org=${encodeURIComponent(org)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    if (vhost) url += `&vhost=${encodeURIComponent(vhost)}`;
    if (sortState.http.col) url += `&sort=${sortState.http.col}&order=${sortState.http.order}`;

    try {
        const data = await fetchJSON(url);
        const tbody = document.getElementById('http-table-body');
        tbody.innerHTML = data.events.map(e => `
            <tr>
                <td>${formatTime(e.timestamp)}</td>
                <td><a href="#" onclick="showIP('${escapeHtml(e.source_ip)}');return false">${e.source_ip}</a></td>
                <td>${e.country_code ? countryFlag(e.country_code) + ' ' + (e.country_name || e.country_code) : '-'}</td>
                <td>${truncate(e.org || '-', 30)}</td>
                <td class="text-xs font-mono">${escapeHtml(e.vhost || '-')}</td>
                <td>${e.method || '-'}</td>
                <td class="max-w-xs truncate">${truncate(e.path, 35)}</td>
                <td>${e.status_code}</td>
                <td>${(e.attack_types || []).map(t => `<span class="badge badge-low mr-1">${t}</span>`).join('')}</td>
                <td>${severityBadge(e.severity)}</td>
                <td class="text-gray-500">${e.scanner_name || '-'}</td>
                <td>${uaClassBadge(e.ua_class)}</td>
            </tr>
        `).join('');

        const totalPages = Math.ceil(data.total / data.limit) || 1;
        document.getElementById('http-page-info').textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
        document.getElementById('http-prev').disabled = data.page <= 1;
        document.getElementById('http-next').disabled = data.page >= totalPages;
    } catch (e) {
        console.error('Failed to load HTTP events:', e);
    }
}

// Populate vhost filter dropdown
async function loadVhostFilter() {
    try {
        const data = await fetchJSON('/api/events/http/vhosts');
        const select = document.getElementById('http-filter-vhost');
        if (!select) return;
        // Keep the "All Vhosts" option, replace the rest
        select.innerHTML = '<option value="">All Vhosts</option>';
        for (const vh of (data.vhosts || [])) {
            const opt = document.createElement('option');
            opt.value = vh;
            opt.textContent = vh;
            select.appendChild(opt);
        }
    } catch (e) {
        console.error('Failed to load vhosts:', e);
    }
}

// Service Events table
async function loadServiceEvents() {
    const ip = document.getElementById('svc-filter-ip')?.value || '';
    const svcType = document.getElementById('svc-filter-type')?.value || '';
    let url = `/api/events/services?page=${svcPage}&limit=50`;
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (svcType) url += `&service_type=${encodeURIComponent(svcType)}`;

    try {
        const data = await fetchJSON(url);
        const tbody = document.getElementById('svc-table-body');
        tbody.innerHTML = data.events.map(e => `
            <tr>
                <td>${formatTime(e.timestamp)}</td>
                <td><span class="badge badge-info">${e.service_type}</span></td>
                <td>${eventTypeBadge(e.event_type)}</td>
                <td class="text-orange-400 cursor-pointer" onclick="window.showIP('${e.source_ip}')">${e.source_ip || '-'}</td>
                <td>${e.username || '-'}</td>
                <td class="max-w-xs truncate">${truncate(e.detail || '-', 40)}</td>
                <td>${severityBadge(e.severity)}</td>
                <td class="font-mono">${e.service_port || '-'}</td>
                <td>${countryFlag(e.country_code)} ${e.country_code || '-'}</td>
            </tr>
        `).join('');

        const totalPages = Math.ceil(data.total / data.limit) || 1;
        document.getElementById('svc-page-info').textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
        document.getElementById('svc-prev').disabled = data.page <= 1;
        document.getElementById('svc-next').disabled = data.page >= totalPages;
    } catch (e) {
        console.error('Failed to load service events:', e);
    }
}

async function loadServiceSummary() {
    try {
        const data = await fetchJSON('/api/events/services/summary');
        const container = document.getElementById('svc-summary-cards');
        if (!data.services || data.services.length === 0) {
            container.innerHTML = '<p class="text-gray-500 col-span-full">No service events recorded yet.</p>';
            return;
        }
        container.innerHTML = data.services.map(s => `
            <div class="stat-card">
                <div class="text-xs text-gray-400 uppercase">${escapeHtml(s.service_type)}</div>
                <div class="text-xl font-bold">${formatNumber(s.count)}</div>
                ${s.critical_high ? `<div class="text-xs text-red-400">${s.critical_high} high/critical</div>` : ''}
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to load service summary:', e);
    }
}

// ── Events sub-tab switching ─────────────────────────────
function loadEvtab(tab) {
    currentEvtab = tab;
    document.querySelectorAll('.events-subtab').forEach(b => b.classList.toggle('active', b.dataset.evtab === tab));
    document.querySelectorAll('.evtab-panel').forEach(p => p.classList.add('hidden'));
    document.getElementById(`evtab-${tab}`)?.classList.remove('hidden');

    if (tab === 'ssh') loadSSHEvents();
    else if (tab === 'http') { loadVhostFilter(); loadHTTPEvents(); }
    else if (tab === 'brute') loadBruteForce();
    else if (tab === 'services') { loadServiceSummary(); loadServiceEvents(); }
    else if (tab === 'portscans') loadPortScans();
    else if (tab === 'anomalies') loadAnomalies();
}

document.querySelectorAll('.events-subtab').forEach(btn => {
    btn.addEventListener('click', () => loadEvtab(btn.dataset.evtab));
});

// Brute Force table
async function loadBruteForce() {
    try {
        const data = await fetchJSON('/api/brute-force');
        const filterIp = document.getElementById('brute-filter-ip')?.value.toLowerCase() || '';
        const filterCountry = document.getElementById('brute-filter-country')?.value.toLowerCase() || '';
        const filterOrg = document.getElementById('brute-filter-org')?.value.toLowerCase() || '';
        let sessions = data.sessions || [];
        if (filterIp) {
            sessions = sessions.filter(s => s.source_ip?.toLowerCase().includes(filterIp));
        }
        if (filterCountry) {
            sessions = sessions.filter(s =>
                s.country_code?.toLowerCase().includes(filterCountry) ||
                s.country_name?.toLowerCase().includes(filterCountry)
            );
        }
        if (filterOrg) {
            sessions = sessions.filter(s => s.org?.toLowerCase().includes(filterOrg));
        }
        const tbody = document.getElementById('brute-table-body');
        tbody.innerHTML = sessions.map(s => `
            <tr>
                <td>${formatTime(s.session_start)}</td>
                <td>${formatTime(s.session_end)}</td>
                <td><a href="#" onclick="showIP('${escapeHtml(s.source_ip)}');return false">${s.source_ip}</a></td>
                <td>${s.country_code ? countryFlag(s.country_code) + ' ' + (s.country_name || s.country_code) : '-'}</td>
                <td>${truncate(s.org || '-', 30)}</td>
                <td>${s.attempt_count}</td>
                <td>${truncate((s.usernames_tried || []).join(', '), 35)}</td>
                <td class="font-mono">${s.service_port || '-'}</td>
                <td><span class="badge ${s.status === 'active' ? 'badge-critical' : 'badge-low'}">${s.status}</span></td>
            </tr>
        `).join('') || '<tr><td colspan="9" class="text-gray-500">No brute force sessions detected</td></tr>';
    } catch (e) {
        console.error('Failed to load brute force sessions:', e);
    }
}

document.getElementById('brute-filter-btn')?.addEventListener('click', () => loadBruteForce());
document.getElementById('brute-filter-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') loadBruteForce(); });

// Port Scans table
let psPage = 1;
let psSort = null;
let psOrder = 'desc';

async function loadPortScans(page) {
    if (page !== undefined) psPage = page;
    const filterIp = document.getElementById('ps-filter-ip')?.value || '';
    const filterCountry = document.getElementById('ps-filter-country')?.value || '';
    const filterOrg = document.getElementById('ps-filter-org')?.value || '';
    const filterStatus = document.getElementById('ps-filter-status')?.value || '';
    let url = `/api/events/portscans?page=${psPage}&limit=50`;
    if (filterIp) url += `&ip=${encodeURIComponent(filterIp)}`;
    if (filterCountry) url += `&country=${encodeURIComponent(filterCountry)}`;
    if (filterOrg) url += `&org=${encodeURIComponent(filterOrg)}`;
    if (filterStatus) url += `&status=${encodeURIComponent(filterStatus)}`;
    if (psSort) url += `&sort=${psSort}&order=${psOrder}`;
    try {
        const data = await fetchJSON(url);
        const tbody = document.getElementById('ps-table-body');
        tbody.innerHTML = (data.events || []).map(e => `
            <tr>
                <td>${formatTime(e.detected_at)}</td>
                <td><a href="#" onclick="showIP('${escapeHtml(e.source_ip)}');return false">${e.source_ip}</a></td>
                <td>${e.country_code ? countryFlag(e.country_code) + ' ' + (e.country_name || e.country_code) : '-'}</td>
                <td>${truncate(e.org || '-', 30)}</td>
                <td>${e.port_count}</td>
                <td class="font-mono text-xs">${(e.ports_hit || []).join(', ')}</td>
                <td>${e.window_seconds || '-'}s</td>
                <td><span class="badge ${e.status === 'active' ? 'badge-critical' : 'badge-low'}">${e.status}</span></td>
            </tr>
        `).join('') || '<tr><td colspan="8" class="text-gray-500">No port scan events detected</td></tr>';
        const total = data.total || 0;
        const pages = Math.ceil(total / 50) || 1;
        document.getElementById('ps-page-info').textContent = `Page ${psPage} of ${pages} (${total} total)`;
        document.getElementById('ps-prev').disabled = psPage <= 1;
        document.getElementById('ps-next').disabled = psPage >= pages;
    } catch (e) {
        console.error('Failed to load port scans:', e);
    }
}

document.getElementById('ps-filter-btn')?.addEventListener('click', () => { psPage = 1; loadPortScans(); });
document.getElementById('ps-filter-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') { psPage = 1; loadPortScans(); } });
document.getElementById('ps-prev')?.addEventListener('click', () => { if (psPage > 1) loadPortScans(psPage - 1); });
document.getElementById('ps-next')?.addEventListener('click', () => loadPortScans(psPage + 1));

document.querySelectorAll('.sortable-th[data-table="ps"]').forEach(th => {
    th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (psSort === col) {
            psOrder = psOrder === 'asc' ? 'desc' : 'asc';
        } else {
            psSort = col;
            psOrder = 'desc';
        }
        loadPortScans(1);
    });
});

// Anomalies table
async function loadAnomalies() {
    const hours = document.getElementById('anomaly-range')?.value || 24;
    try {
        const data = await fetchJSON(`/api/anomalies?hours=${hours}`);
        const tbody = document.getElementById('anomaly-table-body');
        tbody.innerHTML = (data.anomalies || []).map(a => `
            <tr>
                <td>${formatTime(a.detected_at)}</td>
                <td><span class="font-mono">${a.metric}</span></td>
                <td>${Math.round(a.current_value)}</td>
                <td>${Math.round(a.baseline_mean)}</td>
                <td><span class="badge ${a.z_score > 5 ? 'badge-critical' : a.z_score > 4 ? 'badge-high' : 'badge-medium'}">${a.z_score.toFixed(1)}</span></td>
                <td>${severityBadge(a.severity)}</td>
                <td class="text-sm">${a.message}</td>
            </tr>
        `).join('') || '<tr><td colspan="7" class="text-gray-500">No anomalies detected in this period</td></tr>';
    } catch (e) {
        console.error('Failed to load anomalies:', e);
    }
}

document.getElementById('anomaly-refresh-btn')?.addEventListener('click', () => loadAnomalies());
document.getElementById('anomaly-range')?.addEventListener('change', () => loadAnomalies());

// IP Intel
async function loadIntel() {
    const search = document.getElementById('intel-search')?.value || '';
    let url = `/api/ips?page=${intelPage}&limit=30`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const data = await fetchJSON(url);
        const grid = document.getElementById('intel-grid');
        grid.innerHTML = data.ips.map(ip => `
            <div class="intel-card" onclick="window.showIP('${ip.ip}')">
                <div class="flex items-center justify-between mb-2">
                    <span class="font-mono text-red-400">${ip.ip}</span>
                    <span class="text-lg">${countryFlag(ip.country_code)}</span>
                </div>
                <div class="text-sm space-y-1 text-gray-400">
                    <div><span class="text-gray-600">Country:</span> ${ip.country_name || '-'} ${ip.city ? '/ ' + ip.city : ''}</div>
                    <div><span class="text-gray-600">Org:</span> ${truncate(ip.org, 30)}</div>
                    <div><span class="text-gray-600">ISP:</span> ${truncate(ip.isp, 30)}</div>
                    <div><span class="text-gray-600">rDNS:</span> ${truncate(ip.rdns, 30)}</div>
                    <div class="flex gap-3 mt-2">
                        <span class="text-red-400">SSH: ${ip.ssh_count}</span>
                        <span class="text-orange-400">HTTP: ${ip.http_count}</span>
                    </div>
                </div>
            </div>
        `).join('');

        const totalPages = Math.ceil(data.total / data.limit) || 1;
        document.getElementById('intel-page-info').textContent = `Page ${data.page} of ${totalPages} (${data.total} IPs)`;
        document.getElementById('intel-prev').disabled = data.page <= 1;
        document.getElementById('intel-next').disabled = data.page >= totalPages;
    } catch (e) {
        console.error('Failed to load Intel:', e);
    }
}

// Show IP detail modal
let modalMap = null;
let modalMarker = null;
let currentModalIP = null;

window.showIP = async function (ip) {
    currentModalIP = ip;
    const modal = document.getElementById('ip-modal');
    modal.classList.remove('hidden');
    document.getElementById('modal-ip-title').textContent = `IP Detail: ${ip}`;

    // Reset tabs
    document.querySelectorAll('.modal-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'ssh'));
    document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.add('hidden'));
    document.getElementById('modal-tab-ssh').classList.remove('hidden');

    // Reset enrichment status
    document.getElementById('enrich-status').classList.add('hidden');
    document.getElementById('btn-enrich').classList.remove('loading');

    // Reset block button
    const blockBtn = document.getElementById('modal-block-btn');
    blockBtn.textContent = 'Block IP';
    blockBtn.disabled = false;

    try {
        const data = await fetchJSON(`/api/ips/${encodeURIComponent(ip)}`);
        renderModalSummary(data.summary, ip);
        renderModalIntel(data.intel);
        renderModalMap(data.intel);
        renderModalSSH(data.ssh_events);
        renderModalHTTP(data.http_events);
        renderModalBrute(data.brute_sessions);
        renderModalPortScans(data.port_scans);
        renderShodanData(data.shodan);
        renderVirusTotalData(data.virustotal);
        renderCensysData(data.censys);
        renderThreatIntelData(data.threat_intel);
    } catch (e) {
        console.error('Failed to load IP detail:', e);
    }
};

function renderModalSummary(summary, ip) {
    if (!summary) return;
    document.getElementById('modal-summary').innerHTML = `
        <div class="stat-card"><div class="stat-label">SSH Events</div><div class="stat-value">${formatNumber(summary.ssh_count)}</div></div>
        <div class="stat-card"><div class="stat-label">HTTP Events</div><div class="stat-value">${formatNumber(summary.http_count)}</div></div>
        <div class="stat-card"><div class="stat-label">Brute Force</div><div class="stat-value">${formatNumber(summary.brute_force_count)}</div></div>
        <div class="stat-card"><div class="stat-label">Port Scans</div><div class="stat-value">${formatNumber(summary.port_scan_count || 0)}</div></div>
        <div class="stat-card"><div class="stat-label">First Seen</div><div class="stat-value text-sm">${summary.first_seen ? formatTime(summary.first_seen) : '-'}</div></div>
        <div class="stat-card"><div class="stat-label">Last Seen</div><div class="stat-value text-sm">${summary.last_seen ? formatTime(summary.last_seen) : '-'}</div></div>
        <div class="stat-card"><div class="stat-label">IP Address</div><div class="stat-value text-sm font-mono">${ip}</div></div>
    `;
}

function renderModalIntel(intel) {
    const el = document.getElementById('modal-intel');
    if (!intel) { el.innerHTML = '<span class="text-gray-500">No intelligence data</span>'; return; }
    el.innerHTML = `
        <div><span class="text-gray-500">Country:</span> ${countryFlag(intel.country_code)} ${intel.country_name || '-'}</div>
        <div><span class="text-gray-500">City:</span> ${intel.city || '-'}</div>
        <div><span class="text-gray-500">Org:</span> ${intel.org || '-'}</div>
        <div><span class="text-gray-500">ISP:</span> ${intel.isp || '-'}</div>
        <div><span class="text-gray-500">ASN:</span> ${intel.asn || '-'}</div>
        <div><span class="text-gray-500">rDNS:</span> <span class="font-mono">${intel.rdns || '-'}</span></div>
        <div><span class="text-gray-500">Source:</span> ${intel.source || '-'}</div>
        <div><span class="text-gray-500">Enriched:</span> ${intel.enriched_at ? formatTime(intel.enriched_at) : '-'}</div>
    `;
}

function renderModalMap(intel) {
    const container = document.getElementById('modal-map');
    if (modalMap) { modalMap.remove(); modalMap = null; }

    const lat = intel?.latitude;
    const lon = intel?.longitude;
    if (!lat || !lon) {
        container.innerHTML = '<div class="flex items-center" style="height:100%;justify-content:center"><span class="text-gray-500">No geolocation data</span></div>';
        return;
    }
    container.innerHTML = '';

    modalMap = L.map(container, {
        center: [lat, lon], zoom: 5,
        zoomControl: true, attributionControl: false,
    });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd', maxZoom: 19,
    }).addTo(modalMap);

    modalMarker = L.circleMarker([lat, lon], {
        radius: 8, fillColor: '#ef4444', color: '#dc2626',
        weight: 2, opacity: 1, fillOpacity: 0.8,
    }).addTo(modalMap);
    modalMarker.bindPopup(`<b>${intel.ip}</b><br>${intel.city || ''} ${intel.country_name || ''}`).openPopup();

    setTimeout(() => modalMap.invalidateSize(), 150);
}

function renderModalSSH(events) {
    document.getElementById('modal-ssh-body').innerHTML = events.map(e => `
        <tr>
            <td>${formatTime(e.timestamp)}</td>
            <td>${eventTypeBadge(e.event_type)}</td>
            <td>${e.username || '-'}</td>
            <td>${e.source_port || '-'}</td>
        </tr>
    `).join('') || '<tr><td colspan="4" class="text-gray-500">No SSH events</td></tr>';
}

function renderModalHTTP(events) {
    document.getElementById('modal-http-body').innerHTML = events.map(e => `
        <tr>
            <td>${formatTime(e.timestamp)}</td>
            <td>${e.method}</td>
            <td class="max-w-xs truncate">${truncate(e.path, 40)}</td>
            <td>${e.status_code}</td>
            <td>${(e.attack_types || []).map(t => `<span class="badge badge-low mr-1">${t}</span>`).join('') || '-'}</td>
            <td>${severityBadge(e.severity)}</td>
        </tr>
    `).join('') || '<tr><td colspan="6" class="text-gray-500">No HTTP events</td></tr>';
}

function renderModalBrute(sessions) {
    document.getElementById('modal-brute-body').innerHTML = sessions.map(s => `
        <tr>
            <td>${formatTime(s.session_start)}</td>
            <td>${formatTime(s.session_end)}</td>
            <td>${s.attempt_count}</td>
            <td>${truncate((s.usernames_tried || []).join(', '), 40)}</td>
            <td><span class="badge ${s.status === 'active' ? 'badge-critical' : 'badge-low'}">${s.status}</span></td>
        </tr>
    `).join('') || '<tr><td colspan="5" class="text-gray-500">No brute force sessions</td></tr>';
}

function renderModalPortScans(scans) {
    const el = document.getElementById('modal-portscan-body');
    if (!el) return;
    el.innerHTML = (scans || []).map(s => `
        <tr>
            <td>${formatTime(s.detected_at)}</td>
            <td>${s.port_count}</td>
            <td class="font-mono text-xs">${(s.ports_hit || []).join(', ')}</td>
            <td><span class="badge ${s.status === 'active' ? 'badge-critical' : 'badge-low'}">${s.status}</span></td>
        </tr>
    `).join('') || '<tr><td colspan="4" class="text-gray-500">No port scans detected</td></tr>';
}

function renderShodanData(data) {
    const el = document.getElementById('modal-shodan');
    if (!data) { el.innerHTML = '<span class="text-gray-500">No data yet</span>'; return; }
    if (data.error) { el.innerHTML = `<span class="text-gray-500">${data.error}</span>`; return; }
    const ports = (data.ports || []).join(', ') || '-';
    const vulns = (data.vulns || []).slice(0, 10);
    const services = (data.services || []).slice(0, 8);
    el.innerHTML = `
        <div class="space-y-1">
            <div><span class="text-gray-500">Org:</span> ${data.org || '-'}</div>
            <div><span class="text-gray-500">ISP:</span> ${data.isp || '-'}</div>
            <div><span class="text-gray-500">OS:</span> ${data.os || '-'}</div>
            <div><span class="text-gray-500">Ports:</span> <span class="font-mono">${ports}</span></div>
            ${vulns.length ? `<div><span class="text-gray-500">Vulns:</span><div class="flex flex-wrap gap-1 mt-1">${vulns.map(v => `<span class="badge badge-critical">${v}</span>`).join('')}</div></div>` : ''}
            ${data.tags?.length ? `<div><span class="text-gray-500">Tags:</span><div class="flex flex-wrap gap-1 mt-1">${data.tags.map(t => `<span class="badge badge-low">${t}</span>`).join('')}</div></div>` : ''}
            ${services.length ? `<div class="mt-2"><span class="text-gray-500">Services:</span>
                ${services.map(s => `<div class="font-mono text-xs ml-2">${s.port}/${s.transport} ${s.product || ''} ${s.version || ''}</div>`).join('')}
            </div>` : ''}
            <div class="text-xs text-gray-500 mt-2">Updated: ${data.last_update || '-'}</div>
        </div>
    `;
}

function renderVirusTotalData(data) {
    const el = document.getElementById('modal-virustotal');
    if (!data) { el.innerHTML = '<span class="text-gray-500">No data yet</span>'; return; }
    if (data.error) { el.innerHTML = `<span class="text-gray-500">${data.error}</span>`; return; }
    const total = (data.malicious || 0) + (data.suspicious || 0) + (data.harmless || 0) + (data.undetected || 0);
    const malPct = total > 0 ? Math.round(((data.malicious || 0) / total) * 100) : 0;
    const badgeClass = (data.malicious || 0) > 0 ? 'badge-critical' : (data.suspicious || 0) > 0 ? 'badge-high' : 'badge-low';
    el.innerHTML = `
        <div class="space-y-1">
            <div><span class="text-gray-500">Reputation:</span> ${data.reputation ?? '-'}</div>
            <div><span class="text-gray-500">Analysis:</span>
                <div class="flex flex-wrap gap-1 mt-1">
                    <span class="badge ${badgeClass}">${data.malicious || 0} malicious</span>
                    <span class="badge badge-high">${data.suspicious || 0} suspicious</span>
                </div>
            </div>
            <div><span class="text-gray-500">Harmless:</span> ${data.harmless || 0} / ${total} engines (${malPct}% malicious)</div>
            <div><span class="text-gray-500">Owner:</span> ${data.as_owner || '-'}</div>
            <div><span class="text-gray-500">Network:</span> <span class="font-mono">${data.network || '-'}</span></div>
            ${data.tags?.length ? `<div><span class="text-gray-500">Tags:</span><div class="flex flex-wrap gap-1 mt-1">${data.tags.map(t => `<span class="badge badge-low">${t}</span>`).join('')}</div></div>` : ''}
            ${data.total_votes ? `<div><span class="text-gray-500">Votes:</span> harmless: ${data.total_votes.harmless || 0}, malicious: ${data.total_votes.malicious || 0}</div>` : ''}
        </div>
    `;
}

function renderCensysData(data) {
    const el = document.getElementById('modal-censys');
    if (!data) { el.innerHTML = '<span class="text-gray-500">No data yet</span>'; return; }
    if (data.error) { el.innerHTML = `<span class="text-gray-500">${data.error}</span>`; return; }
    const services = (data.services || []).slice(0, 8);
    const as = data.autonomous_system || {};
    el.innerHTML = `
        <div class="space-y-1">
            <div><span class="text-gray-500">ASN:</span> ${as.asn || '-'} (${as.name || '-'})</div>
            <div><span class="text-gray-500">Prefix:</span> <span class="font-mono">${as.bgp_prefix || '-'}</span></div>
            <div><span class="text-gray-500">OS:</span> ${data.operating_system || '-'}</div>
            ${data.labels?.length ? `<div><span class="text-gray-500">Labels:</span><div class="flex flex-wrap gap-1 mt-1">${data.labels.map(l => `<span class="badge badge-low">${l}</span>`).join('')}</div></div>` : ''}
            ${services.length ? `<div class="mt-2"><span class="text-gray-500">Services:</span>
                ${services.map(s => `<div class="font-mono text-xs ml-2">${s.port}/${s.transport_protocol} ${s.service_name || ''} ${(s.software || []).join(', ')}</div>`).join('')}
            </div>` : ''}
            <div class="text-xs text-gray-500 mt-2">Updated: ${data.last_updated_at || '-'}</div>
        </div>
    `;
}

function renderThreatIntelData(threatIntel) {
    const el = document.getElementById('modal-threat-intel');
    if (!threatIntel || !threatIntel.data) { el.innerHTML = '<span class="text-gray-500">No data yet</span>'; return; }
    const data = threatIntel.data;
    if (data.error) { el.innerHTML = `<span class="text-gray-500">${data.error}</span>`; return; }

    let html = '<div class="space-y-1">';

    if (data.abuseipdb) {
        const ab = data.abuseipdb;
        html += `
            <div class="mt-1 font-semibold text-gray-300">AbuseIPDB</div>
            <div><span class="text-gray-500">Confidence:</span> <span class="badge ${ab.abuse_confidence > 50 ? 'badge-critical' : ab.abuse_confidence > 0 ? 'badge-high' : 'badge-low'}">${ab.abuse_confidence}%</span></div>
            <div><span class="text-gray-500">Reports:</span> ${ab.total_reports || 0}</div>
            <div><span class="text-gray-500">Domain:</span> ${ab.domain || '-'}</div>
            ${ab.is_tor ? '<div><span class="badge badge-critical">TOR Node</span></div>' : ''}
        `;
    }

    if (data.otx) {
        const otx = data.otx;
        html += `
            <div class="mt-2 font-semibold text-gray-300">AlienVault OTX</div>
            <div><span class="text-gray-500">Pulses:</span> ${otx.pulse_count || 0}</div>
            ${otx.tags && otx.tags.length ? `<div><span class="text-gray-500">Tags:</span> <div class="mt-1 flex flex-wrap gap-1">${otx.tags.map(t => `<span class="badge badge-low">${t}</span>`).join('')}</div></div>` : ''}
        `;
    }

    html += `
        <div class="text-xs text-gray-500 mt-2">Updated: ${formatTime(threatIntel.checked_at)}</div>
    </div>`;

    el.innerHTML = html;
}

// Enrich button handler
document.getElementById('btn-enrich')?.addEventListener('click', async () => {
    if (!currentModalIP) return;
    const btn = document.getElementById('btn-enrich');
    const statusEl = document.getElementById('enrich-status');
    btn.classList.add('loading');
    statusEl.classList.remove('hidden');
    statusEl.textContent = 'Enriching data from external sources...';

    const ip = encodeURIComponent(currentModalIP);
    const sources = ['shodan', 'virustotal', 'censys', 'threat-intel'];
    const results = await Promise.allSettled(
        sources.map(s => fetch(`/api/ips/${ip}/enrich/${s}`, { method: 'POST' }).then(r => r.json()))
    );

    const errors = [];
    for (let i = 0; i < sources.length; i++) {
        const r = results[i];
        if (r.status === 'fulfilled' && r.value.status !== 'error') {
            if (sources[i] === 'shodan') renderShodanData(r.value.shodan);
            else if (sources[i] === 'virustotal') renderVirusTotalData(r.value.virustotal);
            else if (sources[i] === 'censys') renderCensysData(r.value.censys);
            else if (sources[i] === 'threat-intel') renderThreatIntelData(r.value.threat_intel);
        } else {
            const msg = r.status === 'fulfilled' ? r.value.error : 'Request failed';
            errors.push(`${sources[i]}: ${msg}`);
        }
    }

    btn.classList.remove('loading');
    if (errors.length === sources.length) {
        statusEl.textContent = 'All enrichment sources failed: ' + errors.join('; ');
    } else if (errors.length > 0) {
        statusEl.textContent = 'Partial success. Errors: ' + errors.join('; ');
    } else {
        statusEl.textContent = 'Enrichment complete.';
        setTimeout(() => statusEl.classList.add('hidden'), 3000);
    }
});

// Modal close
document.getElementById('modal-close')?.addEventListener('click', () => {
    document.getElementById('ip-modal').classList.add('hidden');
    if (modalMap) { modalMap.remove(); modalMap = null; }
    currentModalIP = null;
});

document.getElementById('ip-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
        document.getElementById('ip-modal').classList.add('hidden');
        if (modalMap) { modalMap.remove(); modalMap = null; }
        currentModalIP = null;
    }
});

// Modal tabs
document.querySelectorAll('.modal-tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById(`modal-tab-${btn.dataset.tab}`)?.classList.remove('hidden');
        if (btn.dataset.tab === 'timeline' && currentModalIP) {
            loadTimeline(currentModalIP);
        }
    });
});

// Pagination
document.getElementById('ssh-prev')?.addEventListener('click', () => { sshPage = Math.max(1, sshPage - 1); loadSSHEvents(); });
document.getElementById('ssh-next')?.addEventListener('click', () => { sshPage++; loadSSHEvents(); });
document.getElementById('http-prev')?.addEventListener('click', () => { httpPage = Math.max(1, httpPage - 1); loadHTTPEvents(); });
document.getElementById('http-next')?.addEventListener('click', () => { httpPage++; loadHTTPEvents(); });
document.getElementById('intel-prev')?.addEventListener('click', () => { intelPage = Math.max(1, intelPage - 1); loadIntel(); });
document.getElementById('intel-next')?.addEventListener('click', () => { intelPage++; loadIntel(); });
document.getElementById('incident-prev')?.addEventListener('click', () => { incidentPage = Math.max(1, incidentPage - 1); loadIncidents(); });
document.getElementById('incident-next')?.addEventListener('click', () => { incidentPage++; loadIncidents(); });
document.getElementById('svc-prev')?.addEventListener('click', () => { svcPage = Math.max(1, svcPage - 1); loadServiceEvents(); });
document.getElementById('svc-next')?.addEventListener('click', () => { svcPage++; loadServiceEvents(); });

// Filter buttons
document.getElementById('ssh-filter-btn')?.addEventListener('click', () => { sshPage = 1; loadSSHEvents(); });
document.getElementById('http-filter-btn')?.addEventListener('click', () => { httpPage = 1; loadHTTPEvents(); });
document.getElementById('intel-search-btn')?.addEventListener('click', () => { intelPage = 1; loadIntel(); });
document.getElementById('svc-filter-btn')?.addEventListener('click', () => { svcPage = 1; loadServiceSummary(); loadServiceEvents(); });

// Clear filter buttons
document.getElementById('ssh-clear-filter')?.addEventListener('click', () => {
    document.getElementById('ssh-filter-ip').value = '';
    document.getElementById('ssh-filter-country').value = '';
    document.getElementById('ssh-filter-org').value = '';
    document.getElementById('ssh-filter-username').value = '';
    document.getElementById('ssh-filter-type').value = '';
    sshPage = 1;
    loadSSHEvents();
});
document.getElementById('http-clear-filter')?.addEventListener('click', () => {
    document.getElementById('http-filter-ip').value = '';
    document.getElementById('http-filter-country').value = '';
    document.getElementById('http-filter-org').value = '';
    document.getElementById('http-filter-severity').value = '';
    document.getElementById('http-filter-vhost').value = '';
    httpPage = 1;
    loadHTTPEvents();
});
document.getElementById('brute-clear-filter')?.addEventListener('click', () => {
    document.getElementById('brute-filter-ip').value = '';
    document.getElementById('brute-filter-country').value = '';
    document.getElementById('brute-filter-org').value = '';
    loadBruteForce();
});
document.getElementById('ps-clear-filter')?.addEventListener('click', () => {
    document.getElementById('ps-filter-ip').value = '';
    document.getElementById('ps-filter-country').value = '';
    document.getElementById('ps-filter-org').value = '';
    document.getElementById('ps-filter-status').value = '';
    psPage = 1;
    loadPortScans();
});

// Enter key on search fields
document.getElementById('ssh-filter-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') { sshPage = 1; loadSSHEvents(); } });
document.getElementById('http-filter-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') { httpPage = 1; loadHTTPEvents(); } });
document.getElementById('intel-search')?.addEventListener('keydown', e => { if (e.key === 'Enter') { intelPage = 1; loadIntel(); } });
document.getElementById('svc-filter-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') { svcPage = 1; loadServiceSummary(); loadServiceEvents(); } });

// Dashboard time range
document.getElementById('dashboard-range')?.addEventListener('change', () => {
    loadDashboardData();
});

// Export buttons
document.getElementById('ssh-export-csv')?.addEventListener('click', () => {
    const ip = document.getElementById('ssh-filter-ip')?.value || '';
    const type = document.getElementById('ssh-filter-type')?.value || '';
    let url = '/api/events/ssh/export?format=csv';
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (type) url += `&type=${encodeURIComponent(type)}`;
    window.open(url, '_blank');
});
document.getElementById('ssh-export-json')?.addEventListener('click', () => {
    const ip = document.getElementById('ssh-filter-ip')?.value || '';
    const type = document.getElementById('ssh-filter-type')?.value || '';
    let url = '/api/events/ssh/export?format=json';
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (type) url += `&type=${encodeURIComponent(type)}`;
    window.open(url, '_blank');
});
document.getElementById('http-export-csv')?.addEventListener('click', () => {
    const ip = document.getElementById('http-filter-ip')?.value || '';
    const severity = document.getElementById('http-filter-severity')?.value || '';
    let url = '/api/events/http/export?format=csv';
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    window.open(url, '_blank');
});
document.getElementById('http-export-json')?.addEventListener('click', () => {
    const ip = document.getElementById('http-filter-ip')?.value || '';
    const severity = document.getElementById('http-filter-severity')?.value || '';
    let url = '/api/events/http/export?format=json';
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    window.open(url, '_blank');
});

// Timeline + threat score rendering
let timeline24hChart = null;
let timeline24hRO = null;

async function loadTimeline(ip) {
    try {
        const [timeline, score, timeline24h] = await Promise.all([
            fetchJSON(`/api/ips/${encodeURIComponent(ip)}/timeline?limit=200`),
            fetchJSON(`/api/ips/${encodeURIComponent(ip)}/score`),
            fetchJSON(`/api/ips/${encodeURIComponent(ip)}/timeline24h`),
        ]);

        // Threat score
        const scoreEl = document.getElementById('modal-threat-score');
        const badgeClass = score.recommendation === 'block' ? 'badge-critical' :
            score.recommendation === 'monitor' ? 'badge-high' : 'badge-low';
        scoreEl.innerHTML = `
            <div class="flex items-center gap-3">
                <span class="text-gray-500">Threat Score:</span>
                <span class="badge ${badgeClass}">${score.score}/100 — ${score.recommendation.toUpperCase()}</span>
                <span class="text-xs text-gray-500">${score.reasons.join(', ')}</span>
            </div>
        `;

        // 24h horizontal timeline chart
        render24hTimeline(timeline24h);

        // Timeline table
        document.getElementById('modal-timeline-body').innerHTML = timeline.events.map(e => `
            <tr>
                <td>${formatTime(e.timestamp)}</td>
                <td><span class="badge ${e.source === 'ssh' ? 'badge-high' : 'badge-low'}">${e.source}</span></td>
                <td>${truncate(e.detail, 50)}</td>
                <td>${e.severity ? severityBadge(e.severity) : (e.source === 'ssh' ? eventTypeBadge(e.detail) : '-')}</td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="text-gray-500">No events</td></tr>';
    } catch (e) {
        console.error('Failed to load timeline:', e);
    }
}

function render24hTimeline(data) {
    if (timeline24hChart) { timeline24hChart.dispose(); timeline24hChart = null; }
    if (timeline24hRO) { timeline24hRO.disconnect(); timeline24hRO = null; }

    const el = document.getElementById('timeline-24h-chart');
    if (!el) return;

    const labels = data.buckets.map(b => {
        const d = new Date(b.hour);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    const fullLabels = data.buckets.map(b => {
        const d = new Date(b.hour);
        return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    });
    const sshData = data.buckets.map(b => b.ssh);
    const httpData = data.buckets.map(b => b.http);
    const bruteData = data.buckets.map(b => b.brute_attempts);
    const portscanData = data.buckets.map(b => b.port_scans || 0);

    const labelColor = 'rgba(156, 163, 175, 0.8)';
    const gridColor = 'rgba(255, 255, 255, 0.06)';

    timeline24hChart = echarts.init(el, 'dark');
    el.style.background = 'transparent';
    timeline24hChart.getZr().dom.style.background = 'transparent';

    timeline24hRO = new ResizeObserver(() => timeline24hChart && timeline24hChart.resize());
    timeline24hRO.observe(el);

    timeline24hChart.setOption({
        backgroundColor: 'transparent',
        grid: { left: 45, right: 12, top: 36, bottom: 28 },
        legend: {
            top: 0,
            textStyle: { color: labelColor, fontSize: 11 },
            icon: 'roundRect',
            itemWidth: 12,
            itemHeight: 8,
            itemGap: 16,
        },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            backgroundColor: 'rgba(17, 24, 39, 0.95)',
            borderColor: 'rgba(255,255,255,0.08)',
            textStyle: { color: '#d1d5db', fontSize: 12 },
            formatter: (params) => {
                const idx = params[0]?.dataIndex;
                let html = `<div style="margin-bottom:4px;font-weight:500">${fullLabels[idx] || ''}</div>`;
                for (const p of params) {
                    if (p.value > 0) html += `<div>${p.marker} ${p.seriesName}: <b>${p.value}</b></div>`;
                }
                return html;
            },
        },
        xAxis: {
            type: 'category',
            data: labels,
            axisLabel: { color: labelColor, fontSize: 10, rotate: 0 },
            axisLine: { show: false },
            axisTick: { show: false },
            splitLine: { show: false },
        },
        yAxis: {
            type: 'value',
            name: 'Count',
            nameTextStyle: { color: labelColor, fontSize: 11 },
            axisLabel: { color: labelColor, fontSize: 10 },
            splitLine: { lineStyle: { color: gridColor } },
            minInterval: 1,
        },
        series: [
            {
                name: 'SSH Events',
                type: 'bar',
                data: sshData,
                itemStyle: { color: '#c9a66b', borderRadius: [2, 2, 0, 0] },
                barMaxWidth: 18,
            },
            {
                name: 'HTTP Attacks',
                type: 'bar',
                data: httpData,
                itemStyle: { color: '#7b9bc7', borderRadius: [2, 2, 0, 0] },
                barMaxWidth: 18,
            },
            {
                name: 'Brute Force',
                type: 'bar',
                data: bruteData,
                itemStyle: { color: '#c27c7c', borderRadius: [2, 2, 0, 0] },
                barMaxWidth: 18,
            },
            {
                name: 'Port Scans',
                type: 'bar',
                data: portscanData,
                itemStyle: { color: '#9b8ec4', borderRadius: [2, 2, 0, 0] },
                barMaxWidth: 18,
            },
        ],
    });

    // Summary
    const summaryEl = document.getElementById('timeline-24h-summary');
    if (summaryEl) {
        const t = data.totals;
        const peakBucket = data.buckets.reduce((max, b) => (b.ssh + b.http + b.brute_attempts + (b.port_scans||0)) > (max.ssh + max.http + max.brute_attempts + (max.port_scans||0)) ? b : max, data.buckets[0]);
        const peakTime = new Date(peakBucket.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const peakTotal = peakBucket.ssh + peakBucket.http + peakBucket.brute_attempts + (peakBucket.port_scans||0);
        summaryEl.innerHTML = `
            <span>SSH: <strong class="text-orange-400">${t.ssh}</strong></span>
            <span>HTTP: <strong class="text-blue-400">${t.http}</strong></span>
            <span>Brute Force: <strong class="text-red-400">${t.brute_sessions}</strong></span>
            <span>Port Scans: <strong class="text-purple-400">${t.port_scans || 0}</strong></span>
            <span class="ml-auto">Peak: <strong class="text-white">${peakTotal}</strong> at <strong class="text-white">${peakTime}</strong></span>
        `;
    }
}

// Create incident from IP modal
window.createIncidentFromIP = function () {
    if (!currentModalIP) return;
    document.getElementById('incident-form-title').value = `Suspicious activity from ${currentModalIP}`;
    document.getElementById('incident-form-desc').value = `Automated incident created from IP investigation of ${currentModalIP}. Review the attack timeline and enrichment data for details.`;
    document.getElementById('incident-form-severity').value = 'high';
    document.getElementById('incident-form-ips').value = currentModalIP;
    // Close the IP details modal
    document.getElementById('ip-modal').classList.add('hidden');
    if (modalMap) { modalMap.remove(); modalMap = null; }
    // Open the incident creation modal
    document.getElementById('incident-create-modal').classList.remove('hidden');
}

// ── Incident Management ──────────────────────────────────
let currentIncidentId = null;

function statusBadge(status) {
    return `<span class="badge badge-${status}">${status}</span>`;
}

async function loadIncidents() {
    const status = document.getElementById('incident-filter-status')?.value || '';
    const severity = document.getElementById('incident-filter-severity')?.value || '';
    let url = `/api/incidents?page=${incidentPage}&limit=20`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;

    try {
        const data = await fetchJSON(url);
        const list = document.getElementById('incident-list');

        if (!data.incidents.length) {
            list.innerHTML = '<div class="text-sm text-gray-500" style="padding:2rem;text-align:center">No incidents found. Create one to start tracking.</div>';
        } else {
            list.innerHTML = data.incidents.map(inc => `
                <div class="incident-card" onclick="window.showIncident(${inc.id})">
                    <div class="incident-id">#${inc.id}</div>
                    <div class="incident-info">
                        <div class="incident-title">${inc.title}</div>
                        <div class="incident-meta">
                            <span>Created ${formatTime(inc.created_at)}</span>
                            <span>Updated ${formatTime(inc.updated_at)}</span>
                            ${inc.source_ips.length ? `<span>${inc.source_ips.length} IP(s)</span>` : ''}
                        </div>
                    </div>
                    <div class="incident-badges">
                        ${severityBadge(inc.severity)}
                        ${statusBadge(inc.status)}
                    </div>
                </div>
            `).join('');
        }

        const totalPages = Math.ceil(data.total / data.limit) || 1;
        document.getElementById('incident-page-info').textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
        document.getElementById('incident-prev').disabled = data.page <= 1;
        document.getElementById('incident-next').disabled = data.page >= totalPages;

        // Update stat counters
        await loadIncidentStats();
    } catch (e) {
        console.error('Failed to load incidents:', e);
    }
}

async function loadIncidentStats() {
    try {
        const statuses = ['open', 'investigating', 'resolved', 'closed'];
        const counts = await Promise.all(
            statuses.map(s => fetchJSON(`/api/incidents?status=${s}&limit=1`).then(d => d.total))
        );
        statuses.forEach((s, i) => {
            const el = document.getElementById(`incident-stat-${s}`);
            if (el) el.textContent = formatNumber(counts[i]);
        });
    } catch (e) {
        console.error('Failed to load incident stats:', e);
    }
}

// Create incident
document.getElementById('incident-create-btn')?.addEventListener('click', () => {
    document.getElementById('incident-form-title').value = '';
    document.getElementById('incident-form-desc').value = '';
    document.getElementById('incident-form-severity').value = 'medium';
    document.getElementById('incident-form-ips').value = '';
    document.getElementById('incident-create-modal').classList.remove('hidden');
});

document.getElementById('incident-form-submit')?.addEventListener('click', async () => {
    const title = document.getElementById('incident-form-title').value.trim();
    if (!title) { document.getElementById('incident-form-title').focus(); return; }

    const ipsRaw = document.getElementById('incident-form-ips').value.trim();
    const source_ips = ipsRaw ? ipsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

    try {
        await fetch('/api/incidents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title,
                description: document.getElementById('incident-form-desc').value.trim(),
                severity: document.getElementById('incident-form-severity').value,
                source_ips,
            }),
        });
        document.getElementById('incident-create-modal').classList.add('hidden');
        await loadIncidents();
    } catch (e) {
        console.error('Failed to create incident:', e);
    }
});

document.getElementById('incident-filter-btn')?.addEventListener('click', () => { incidentPage = 1; loadIncidents(); });

// Show incident detail
window.showIncident = async function (id) {
    currentIncidentId = id;
    try {
        const inc = await fetchJSON(`/api/incidents/${id}`);
        if (inc.error) { console.error(inc.error); return; }

        document.getElementById('incident-detail-title').textContent = `Incident #${inc.id}: ${inc.title}`;
        document.getElementById('incident-detail-desc').textContent = inc.description || 'No description provided.';

        // Meta cards
        document.getElementById('incident-detail-meta').innerHTML = `
            <div class="stat-card"><div class="stat-label">Severity</div><div class="stat-value text-sm">${severityBadge(inc.severity)}</div></div>
            <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value text-sm">${statusBadge(inc.status)}</div></div>
            <div class="stat-card"><div class="stat-label">Created</div><div class="stat-value text-sm">${formatTime(inc.created_at)}</div></div>
            <div class="stat-card"><div class="stat-label">Updated</div><div class="stat-value text-sm">${formatTime(inc.updated_at)}</div></div>
        `;

        // Status actions
        const allStatuses = ['open', 'investigating', 'resolved', 'closed'];
        document.getElementById('incident-status-actions').innerHTML = allStatuses.map(s =>
            `<button class="btn-status ${s === inc.status ? 'current' : ''}" ${s === inc.status ? 'disabled' : ''} onclick="window.updateIncidentStatus(${id}, '${s}')">${s}</button>`
        ).join('');

        // Source IPs
        const ipsEl = document.getElementById('incident-detail-ips');
        if (inc.source_ips.length) {
            ipsEl.innerHTML = inc.source_ips.map(ip =>
                `<span class="badge badge-high cursor-pointer" onclick="window.showIP('${ip}')">${ip}</span>`
            ).join('');
        } else {
            ipsEl.innerHTML = '<span class="text-sm text-gray-500">No source IPs linked</span>';
        }

        // Linked events
        const eventsBody = document.getElementById('incident-events-body');
        if (inc.linked_events.length) {
            eventsBody.innerHTML = inc.linked_events.map(ev => {
                let detailsHtml = '';
                let timestampHtml = ev.timestamp ? formatTime(ev.timestamp) : '';

                if (ev.event_type === 'ssh') {
                    detailsHtml = `<div class="text-xs" style="line-height: 1.6;">
                        ${ev.source_ip ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">IP:</span> <span class="font-mono text-blue-400">${ev.source_ip}</span></div>` : ''}
                        ${ev.type ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Type:</span> <span class="badge badge-low">${ev.type}</span></div>` : ''}
                        ${ev.username ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Username:</span> <span class="font-mono font-semibold text-orange-400">${ev.username}</span></div>` : ''}
                        ${ev.auth_method ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Auth:</span> ${ev.auth_method}</div>` : ''}
                        ${ev.source_port ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Port:</span> ${ev.source_port}</div>` : ''}
                    </div>`;
                } else if (ev.event_type === 'http') {
                    timestampHtml = ev.timestamp ? formatTime(ev.timestamp) : '';
                    const attackTypes = ev.attack_types && ev.attack_types.length > 0
                        ? ev.attack_types.map(a => `<span class="badge badge-high">${a}</span>`).join(' ')
                        : '<span class="text-gray-500">none</span>';
                    detailsHtml = `<div class="text-xs" style="line-height: 1.6;">
                        ${ev.source_ip ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">IP:</span> <span class="font-mono text-blue-400">${ev.source_ip}</span></div>` : ''}
                        ${ev.method && ev.path ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Request:</span> <span class="font-mono font-semibold text-green-400">${ev.method}</span> <span class="font-mono" title="${ev.path}">${ev.path.length > 60 ? ev.path.substring(0, 60) + '...' : ev.path}</span></div>` : ''}
                        ${ev.status_code ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Status:</span> <span class="font-mono">${ev.status_code}</span></div>` : ''}
                        ${ev.severity ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Severity:</span> ${severityBadge(ev.severity)}</div>` : ''}
                        ${ev.scanner_name ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Scanner:</span> <span class="badge badge-medium">${ev.scanner_name}</span></div>` : ''}
                        <div style="margin-bottom: 2px;"><span class="text-gray-500">Attacks:</span> ${attackTypes}</div>
                    </div>`;
                } else if (ev.event_type === 'brute_force') {
                    timestampHtml = ev.session_start ? formatTime(ev.session_start) : '';
                    const usernamesList = ev.usernames_tried && ev.usernames_tried.length > 0
                        ? ev.usernames_tried
                        : [];
                    const displayUsernames = usernamesList.slice(0, 5).map(u => `<span class="font-mono text-orange-400">${u}</span>`).join(', ');
                    const remainingCount = usernamesList.length > 5 ? ` <span class="text-gray-500">+${usernamesList.length - 5} more</span>` : '';
                    detailsHtml = `<div class="text-xs" style="line-height: 1.6;">
                        ${ev.source_ip ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">IP:</span> <span class="font-mono text-blue-400">${ev.source_ip}</span></div>` : ''}
                        ${ev.attempt_count ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Attempts:</span> <span class="font-semibold">${ev.attempt_count}</span></div>` : ''}
                        ${usernamesList.length > 0 ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Usernames tried:</span> ${displayUsernames}${remainingCount}</div>` : ''}
                        ${ev.status ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Status:</span> <span class="badge badge-${ev.status === 'active' ? 'high' : 'medium'}">${ev.status}</span></div>` : ''}
                        ${ev.session_end ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Duration:</span> ${Math.round((ev.session_end - ev.session_start) / 60)} min</div>` : ''}
                    </div>`;
                } else if (ev.event_type === 'port_scan') {
                    const portsList = ev.ports_hit && ev.ports_hit.length > 0 ? ev.ports_hit : [];
                    const displayPorts = portsList.slice(0, 10).join(', ');
                    const remainingCount = portsList.length > 10 ? ` +${portsList.length - 10} more` : '';
                    detailsHtml = `<div class="text-xs" style="line-height: 1.6;">
                        ${ev.source_ip ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">IP:</span> <span class="font-mono text-blue-400">${ev.source_ip}</span></div>` : ''}
                        ${ev.port_count ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Total ports:</span> <span class="font-semibold">${ev.port_count}</span></div>` : ''}
                        ${portsList.length > 0 ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Ports:</span> <span class="font-mono">${displayPorts}${remainingCount}</span></div>` : ''}
                        ${ev.status ? `<div style="margin-bottom: 2px;"><span class="text-gray-500">Status:</span> <span class="badge badge-medium">${ev.status}</span></div>` : ''}
                    </div>`;
                }

                return `
                    <tr>
                        <td>${eventTypeBadge(ev.event_type) || `<span class="badge badge-low">${ev.event_type}</span>`}</td>
                        <td class="font-mono">${ev.event_id}</td>
                        <td class="text-xs">${timestampHtml}</td>
                        <td>${detailsHtml}</td>
                        <td><button class="btn-secondary" onclick="window.unlinkEvent(${id}, '${ev.event_type}', ${ev.event_id})">Unlink</button></td>
                    </tr>
                `;
            }).join('');
        } else {
            eventsBody.innerHTML = '<tr><td colspan="5" class="text-gray-500">No events linked yet</td></tr>';
        }

        // Enrichment data
        const enrichmentSection = document.getElementById('incident-enrichment-section');
        const enrichmentData = document.getElementById('incident-enrichment-data');
        if (inc.enrichment_data && Object.keys(inc.enrichment_data).length > 0) {
            enrichmentSection.style.display = 'block';
            enrichmentData.innerHTML = Object.entries(inc.enrichment_data).map(([ip, data]) => `
                <div class="border border-gray-700 rounded p-3">
                    <h4 class="text-sm font-semibold mb-2 text-blue-400">${ip}</h4>
                    <div class="grid grid-cols-2 gap-2 text-xs">
                        ${data.country_name ? `<div><span class="text-gray-500">Country:</span> ${data.country_name} (${data.country_code})</div>` : ''}
                        ${data.city ? `<div><span class="text-gray-500">City:</span> ${data.city}</div>` : ''}
                        ${data.org ? `<div><span class="text-gray-500">Org:</span> ${data.org}</div>` : ''}
                        ${data.isp ? `<div><span class="text-gray-500">ISP:</span> ${data.isp}</div>` : ''}
                        ${data.asn ? `<div><span class="text-gray-500">ASN:</span> ${data.asn}</div>` : ''}
                        ${data.rdns ? `<div class="col-span-2"><span class="text-gray-500">rDNS:</span> <span class="font-mono">${data.rdns}</span></div>` : ''}
                        ${data.enriched_at ? `<div class="col-span-2"><span class="text-gray-500">Enriched:</span> ${formatTime(data.enriched_at)}</div>` : ''}
                        ${data.shodan_data ? `<div class="col-span-2"><span class="text-gray-500">Shodan:</span> ${data.shodan_data.open_ports ? data.shodan_data.open_ports.length + ' open ports' : 'Data available'}</div>` : ''}
                        ${data.virustotal_data ? `<div class="col-span-2"><span class="text-gray-500">VirusTotal:</span> ${data.virustotal_data.malicious_count || 0} malicious detections</div>` : ''}
                        ${data.censys_data ? `<div class="col-span-2"><span class="text-gray-500">Censys:</span> Data available</div>` : ''}
                    </div>
                </div>
            `).join('');
        } else {
            enrichmentSection.style.display = 'none';
        }

        document.getElementById('incident-detail-modal').classList.remove('hidden');
    } catch (e) {
        console.error('Failed to load incident detail:', e);
    }
};

window.updateIncidentStatus = async function (id, status) {
    try {
        await fetch(`/api/incidents/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status }),
        });
        await window.showIncident(id);
        await loadIncidents();
    } catch (e) {
        console.error('Failed to update incident status:', e);
    }
};

window.unlinkEvent = async function (incidentId, eventType, eventId) {
    try {
        await fetch(`/api/incidents/${incidentId}/events/${eventType}/${eventId}`, { method: 'DELETE' });
        await window.showIncident(incidentId);
    } catch (e) {
        console.error('Failed to unlink event:', e);
    }
};

window.enrichIncident = async function (provider) {
    if (!currentIncidentId) return;

    const providerLabel = provider === 'all' ? 'All APIs' :
                         provider === 'threat-intel' ? 'Threat Intel' :
                         provider.charAt(0).toUpperCase() + provider.slice(1);

    const message = provider === 'all'
        ? `Enrich incident #${currentIncidentId} IPs using all configured APIs (Shodan, VirusTotal, Censys, Threat Intel)? This may take several moments.`
        : `Enrich incident #${currentIncidentId} IPs using ${providerLabel}? This may take a few moments.`;

    const confirmed = confirm(message);
    if (!confirmed) return;

    // Show loading indicator in enrichment section
    const enrichmentSection = document.getElementById('incident-enrichment-section');
    const enrichmentData = document.getElementById('incident-enrichment-data');
    enrichmentSection.style.display = 'block';
    enrichmentData.innerHTML = '<div class="text-sm text-gray-400" style="padding: 1rem; text-align: center;">Enriching data, please wait...</div>';

    try {
        const response = await fetch(`/api/incidents/${currentIncidentId}/enrich/${provider}`, {
            method: 'POST',
        });
        const data = await response.json();

        if (data.error) {
            alert(`Enrichment failed: ${data.error}`);
            enrichmentSection.style.display = 'none';
        } else {
            // Refresh incident details to show new enrichment data
            await window.showIncident(currentIncidentId);

            // Show success message briefly
            if (provider === 'all' && data.results) {
                const successCount = Object.values(data.results).filter(r =>
                    Object.values(r).some(status => status === 'ok')
                ).length;
                console.log(`Enrichment completed for ${successCount} IPs using ${providerLabel}`);
            } else {
                console.log(`Enrichment completed using ${providerLabel}`);
            }
        }
    } catch (e) {
        console.error('Failed to enrich incident:', e);
        alert('Enrichment failed. Check console for details.');
        enrichmentSection.style.display = 'none';
    }
};

window.deleteIncident = async function () {
    if (!currentIncidentId) return;

    const confirmed = confirm(`Are you sure you want to delete incident #${currentIncidentId}? This action cannot be undone.`);
    if (!confirmed) return;

    try {
        await fetch(`/api/incidents/${currentIncidentId}`, { method: 'DELETE' });
        document.getElementById('incident-detail-modal').classList.add('hidden');
        await loadIncidents();
    } catch (e) {
        console.error('Failed to delete incident:', e);
        alert('Failed to delete incident. Check console for details.');
    }
};

// Close modals on overlay click
document.getElementById('incident-create-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
});
document.getElementById('incident-detail-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
});

// ── Scanner ──────────────────────────────────────────────────
let scannerPage = 1;
const scannerLimit = 50;
let scanPollTimer = null;
let liveSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let scanBatchStates = {}; // label -> status

async function loadScannerView() {
    await Promise.all([loadScannerSummary(), loadScannerStatus(), loadScannerFindings()]);
}

async function loadScannerSummary() {
    try {
        const res = await fetch('/api/scanner/summary');
        const data = await res.json();

        document.getElementById('scanner-count-critical').textContent = data.severity_counts?.critical || 0;
        document.getElementById('scanner-count-high').textContent = data.severity_counts?.high || 0;
        document.getElementById('scanner-count-medium').textContent = data.severity_counts?.medium || 0;
        document.getElementById('scanner-count-low').textContent = data.severity_counts?.low || 0;
        document.getElementById('scanner-count-info').textContent = data.severity_counts?.info || 0;

        const tbody = document.getElementById('scanner-history-body');
        if (!data.scan_history || data.scan_history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-gray-500 text-center">No scans yet</td></tr>';
            return;
        }
        tbody.innerHTML = data.scan_history.map(s => {
            const started = s.started_at ? new Date(s.started_at * 1000).toLocaleString() : '-';
            let duration = '-';
            if (s.finished_at && s.started_at) {
                const secs = Math.round(s.finished_at - s.started_at);
                duration = secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
            } else if (s.status === 'running') {
                duration = 'Running...';
            }
            const statusCls = s.status === 'completed' ? 'badge-resolved' :
                s.status === 'running' ? 'badge-investigating' :
                    s.status === 'stopped' ? 'badge-high' :
                    s.status === 'failed' ? 'badge-open' : 'badge-closed';
            return `<tr>
                <td>${s.id}</td>
                <td class="text-xs">${(s.targets || []).join(', ')}</td>
                <td><span class="badge ${statusCls}">${s.status}</span></td>
                <td>${s.finding_count}</td>
                <td>${started}</td>
                <td>${duration}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('Failed to load scanner summary:', e);
    }
}

async function loadScannerStatus() {
    try {
        const res = await fetch('/api/scanner/status');
        const data = await res.json();
        updateScannerStatus(data);
        if (data.status === 'running' && !scanPollTimer) {
            pollScanStatus();
        }
    } catch (e) {
        console.error('Failed to load scanner status:', e);
    }
}

function updateScannerStatus(data) {
    const bar = document.getElementById('scanner-status-bar');
    const icon = document.getElementById('scanner-status-icon');
    const text = document.getElementById('scanner-status-text');
    const progress = document.getElementById('scanner-progress-bar');
    const progressFill = document.getElementById('scanner-progress-fill');
    const btn = document.getElementById('scanner-start-btn');
    const stopBtn = document.getElementById('scanner-stop-btn');
    const batchInfo = document.getElementById('scanner-batch-info');
    const batchList = document.getElementById('scanner-batch-list');
    const liveFeed = document.getElementById('scanner-live-feed');

    // Handle batch events
    if (data.batch_label !== undefined) {
        if (data.batch_status !== undefined) {
            // scan_batch_complete
            scanBatchStates[data.batch_label] = data.batch_status;
        } else if (data.batch_targets !== undefined) {
            // scan_batch_start
            scanBatchStates[data.batch_label] = 'running';
        }
        renderBatchPills(batchList);

        // Update progress bar based on batch progress
        if (data.total_batches > 0) {
            const completedBatches = Object.values(scanBatchStates).filter(s => s !== 'running').length;
            const pct = Math.round((completedBatches / data.total_batches) * 100);
            progressFill.style.width = `${pct}%`;
        }
        return;
    }

    if (data.status === 'running') {
        bar.classList.remove('hidden');
        bar.style.borderColor = 'var(--color-accent)';
        icon.innerHTML = '<span class="inline-block w-2 h-2 rounded-full bg-blue-500" style="animation:pulse 1s infinite"></span>';

        const batchLabel = data.current_batch ? ` [${data.current_batch}]` : '';
        const batchProgress = data.total_batches > 1
            ? ` — batch ${(data.current_batch_index || 0) + 1}/${data.total_batches}`
            : '';
        text.textContent = `Scanning${batchLabel}... ${data.findings_so_far || 0} findings${batchProgress}`;

        progress.classList.remove('hidden');
        btn.disabled = true;
        btn.textContent = 'Scanning...';
        stopBtn.classList.remove('hidden');
        stopBtn.disabled = false;
        stopBtn.textContent = 'Stop Scan';

        // Show live feed
        liveFeed.classList.remove('hidden');

        // Show batch pills
        if (data.batches && data.batches.length > 1) {
            batchInfo.classList.remove('hidden');
            if (Object.keys(scanBatchStates).length === 0) {
                for (const label of data.batches) {
                    scanBatchStates[label] = 'pending';
                }
                if (data.current_batch) scanBatchStates[data.current_batch] = 'running';
            }
            renderBatchPills(batchList);
        }

        // Update progress from batch
        if (data.total_batches > 0) {
            const completedBatches = Object.values(scanBatchStates).filter(s => s !== 'running' && s !== 'pending').length;
            const pct = Math.round((completedBatches / data.total_batches) * 100);
            progressFill.style.width = `${pct}%`;
        }
    } else if (data.status === 'completed') {
        bar.classList.remove('hidden');
        bar.style.borderColor = '#22c55e';
        icon.innerHTML = '<span class="inline-block w-2 h-2 rounded-full bg-green-500"></span>';
        const findings = data.findings_so_far || 0;
        text.textContent = `Scan completed: ${findings} finding${findings !== 1 ? 's' : ''}`;
        progress.classList.add('hidden');
        batchInfo.classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'Run Scan';
        stopBtn.classList.add('hidden');
        scanBatchStates = {};
        loadScannerSummary();
        loadScannerFindings();
    } else if (data.status === 'stopped') {
        bar.classList.remove('hidden');
        bar.style.borderColor = '#f97316';
        icon.innerHTML = '<span class="inline-block w-2 h-2 rounded-full bg-orange-500"></span>';
        const findings = data.findings_so_far || 0;
        text.textContent = `Scan stopped: ${findings} finding${findings !== 1 ? 's' : ''} before cancellation`;
        progress.classList.add('hidden');
        batchInfo.classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'Run Scan';
        stopBtn.classList.add('hidden');
        scanBatchStates = {};
        loadScannerSummary();
        loadScannerFindings();
    } else if (data.status === 'failed') {
        bar.classList.remove('hidden');
        bar.style.borderColor = '#ef4444';
        icon.innerHTML = '<span class="inline-block w-2 h-2 rounded-full bg-red-500"></span>';
        text.textContent = 'Scan failed';
        progress.classList.add('hidden');
        batchInfo.classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'Run Scan';
        stopBtn.classList.add('hidden');
        scanBatchStates = {};
    } else {
        if (data.last_scan) {
            bar.classList.remove('hidden');
            bar.style.borderColor = 'var(--color-border)';
            icon.innerHTML = '<span class="inline-block w-2 h-2 rounded-full bg-gray-500"></span>';
            text.textContent = `Last scan: ${new Date(data.last_scan * 1000).toLocaleString()}`;
        } else {
            bar.classList.add('hidden');
        }
        progress.classList.add('hidden');
        batchInfo.classList.add('hidden');
        btn.disabled = false;
        btn.textContent = 'Run Scan';
        stopBtn.classList.add('hidden');
    }
}

function renderBatchPills(container) {
    container.innerHTML = Object.entries(scanBatchStates).map(([label, status]) => {
        const cls = status === 'completed' ? 'badge-resolved' :
            status === 'running' ? 'badge-investigating' :
            status === 'stopped' ? 'badge-high' :
            status === 'failed' ? 'badge-open' : 'badge-info';
        return `<span class="badge ${cls}" style="font-size:0.7rem">${escapeHtml(label)}${status === 'running' ? ' ...' : ''}</span>`;
    }).join('');
}

// ── Live finding insertion via WebSocket ──
function appendLiveFinding(f) {
    const liveFeed = document.getElementById('scanner-live-feed');
    const liveBody = document.getElementById('scanner-live-body');
    liveFeed.classList.remove('hidden');

    const item = document.createElement('div');
    item.className = 'feed-item new';
    item.style.cursor = 'pointer';
    item.innerHTML = `
        <span style="width:5rem;flex-shrink:0">${severityBadge(f.severity)}</span>
        <span class="text-sm font-medium" style="min-width:0;flex:1">${escapeHtml(f.name)}</span>
        <span class="text-xs text-gray-400" style="flex-shrink:0">${escapeHtml(f.host || '')}</span>
        ${f.batch_label ? `<span class="badge badge-info" style="font-size:0.6rem;flex-shrink:0">${escapeHtml(f.batch_label)}</span>` : ''}
    `;
    item.addEventListener('click', () => showFindingFromData(f));

    // Prepend to top
    liveBody.insertBefore(item, liveBody.firstChild);

    // Keep max 200 items
    while (liveBody.children.length > 200) liveBody.removeChild(liveBody.lastChild);

    // Update live count
    const count = liveBody.children.length;
    document.getElementById('scanner-live-count').textContent = `${count} finding${count !== 1 ? 's' : ''}`;
}

function updateLiveSeverityCounts(f) {
    const sev = f.severity || 'info';
    if (sev in liveSeverityCounts) {
        liveSeverityCounts[sev]++;
        const el = document.getElementById(`scanner-count-${sev}`);
        if (el) {
            el.textContent = liveSeverityCounts[sev];
            // Flash effect
            el.style.transition = 'none';
            el.style.color = '#fff';
            requestAnimationFrame(() => {
                el.style.transition = 'color 1s';
                el.style.color = '';
            });
        }
    }
}

// ── Target preview ──
async function previewTargets() {
    try {
        const res = await fetch('/api/scanner/profile');
        const data = await res.json();
        if (data.error) { alert(data.error); return; }

        const panel = document.getElementById('scanner-targets-panel');
        const list = document.getElementById('scanner-targets-list');
        const profileInfo = document.getElementById('scanner-profile-info');

        list.innerHTML = (data.targets || []).map(t =>
            `<label class="flex items-center gap-2 text-sm" style="padding:0.25rem 0">
                <input type="checkbox" class="scanner-target-cb" value="${escapeHtml(t)}" checked>
                <span class="font-mono text-xs">${escapeHtml(t)}</span>
            </label>`
        ).join('');

        if (data.detected_technologies) {
            const techs = Object.keys(data.detected_technologies);
            profileInfo.innerHTML = `Detected: <strong>${techs.join(', ')}</strong> — ${data.tag_count || 0} Nuclei tags selected`;
        }

        panel.classList.remove('hidden');
    } catch (e) {
        console.error('Failed to preview targets:', e);
        alert('Failed to load target preview');
    }
}

async function startScan(selectedTargets) {
    const body = {};
    if (selectedTargets && selectedTargets.length > 0) {
        body.targets = selectedTargets;
    }
    body.auto_profile = true;

    try {
        const res = await fetch('/api/scanner/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.error) {
            alert(data.error);
            return;
        }

        // Reset live state
        liveSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        scanBatchStates = {};
        document.getElementById('scanner-live-body').innerHTML = '';
        document.getElementById('scanner-targets-panel').classList.add('hidden');

        // Reset displayed counts to 0 for live tracking
        for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
            document.getElementById(`scanner-count-${sev}`).textContent = '0';
        }

        updateScannerStatus({ status: 'running', findings_so_far: 0, batches: data.batches || [], total_batches: (data.batches || []).length });
        pollScanStatus();
    } catch (e) {
        console.error('Failed to start scan:', e);
        alert('Failed to start scan');
    }
}

function pollScanStatus() {
    if (scanPollTimer) clearInterval(scanPollTimer);
    scanPollTimer = setInterval(async () => {
        try {
            const res = await fetch('/api/scanner/status');
            const data = await res.json();
            updateScannerStatus(data);
            if (data.status !== 'running') {
                clearInterval(scanPollTimer);
                scanPollTimer = null;
                await loadScannerSummary();
                await loadScannerFindings();
            }
        } catch (e) {
            console.error('Scan poll error:', e);
        }
    }, 3000);
}

async function loadScannerFindings() {
    try {
        const severity = document.getElementById('scanner-filter-severity')?.value || '';
        let url = `/api/scanner/results?page=${scannerPage}&limit=${scannerLimit}`;
        if (severity) url += `&severity=${severity}`;

        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById('scanner-findings-body');

        if (!data.findings || data.findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-gray-500 text-center">No findings</td></tr>';
            document.getElementById('scanner-page-info').textContent = '';
            return;
        }

        tbody.innerHTML = data.findings.map(f => {
            const tags = (f.tags || []).slice(0, 4).map(t => `<span class="badge badge-low mr-1">${t}</span>`).join('');
            return `<tr>
                <td>${severityBadge(f.severity)}</td>
                <td class="font-medium">${escapeHtml(f.name)}</td>
                <td class="text-xs">${escapeHtml(f.host || '-')}</td>
                <td class="text-xs" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(f.matched_url || '-')}</td>
                <td>${tags}</td>
                <td><button class="btn-secondary" style="padding:2px 8px;font-size:0.75rem" onclick="showFinding(${f.id})">View</button></td>
            </tr>`;
        }).join('');

        const totalPages = Math.ceil(data.total / scannerLimit);
        document.getElementById('scanner-page-info').textContent = `Page ${data.page} of ${totalPages} (${data.total} total)`;
        document.getElementById('scanner-prev').disabled = data.page <= 1;
        document.getElementById('scanner-next').disabled = data.page >= totalPages;
    } catch (e) {
        console.error('Failed to load scanner findings:', e);
    }
}

// Show finding detail from DB (by ID)
window.showFinding = async function (findingId) {
    try {
        const res = await fetch(`/api/scanner/results?limit=500`);
        const data = await res.json();
        const f = data.findings.find(x => x.id === findingId);
        if (!f) return;
        showFindingFromData(f);
    } catch (e) {
        console.error('Failed to show finding:', e);
    }
};

// Show finding detail from data object (works for both DB and live WebSocket data)
function showFindingFromData(f) {
    document.getElementById('finding-detail-title').textContent = f.name;
    document.getElementById('finding-detail-desc').textContent = f.description || 'No description available.';

    const meta = document.getElementById('finding-detail-meta');
    meta.innerHTML = `
        <div class="stat-card"><div class="stat-label">Severity</div><div class="stat-value">${severityBadge(f.severity)}</div></div>
        <div class="stat-card"><div class="stat-label">Template</div><div class="stat-value text-xs">${escapeHtml(f.template_id)}</div></div>
        <div class="stat-card"><div class="stat-label">Host</div><div class="stat-value text-xs">${escapeHtml(f.host || '-')}${f.ip ? ' (' + escapeHtml(f.ip) + ')' : ''}</div></div>
        <div class="stat-card"><div class="stat-label">Protocol</div><div class="stat-value text-xs">${escapeHtml(f.protocol || '-')}</div></div>
        <div class="stat-card"><div class="stat-label">Matched URL</div><div class="stat-value text-xs" style="word-break:break-all">${escapeHtml(f.matched_url || '-')}</div></div>
        <div class="stat-card"><div class="stat-label">Found</div><div class="stat-value text-xs">${f.found_at ? new Date(f.found_at * 1000).toLocaleString() : '-'}</div></div>
    `;

    const remCard = document.getElementById('finding-remediation-card');
    const remText = document.getElementById('finding-detail-remediation');
    if (f.remediation) { remCard.classList.remove('hidden'); remText.textContent = f.remediation; }
    else { remCard.classList.add('hidden'); }

    const curlCard = document.getElementById('finding-curl-card');
    const curlText = document.getElementById('finding-detail-curl');
    if (f.curl_command) { curlCard.classList.remove('hidden'); curlText.textContent = f.curl_command; }
    else { curlCard.classList.add('hidden'); }

    const refsCard = document.getElementById('finding-refs-card');
    const refsList = document.getElementById('finding-detail-refs');
    if (f.reference && f.reference.length > 0) {
        refsCard.classList.remove('hidden');
        refsList.innerHTML = f.reference.map(r =>
            `<li><a href="${escapeHtml(r)}" target="_blank" rel="noopener" class="external-link">${escapeHtml(r)}</a></li>`
        ).join('');
    } else { refsCard.classList.add('hidden'); }

    const extractedCard = document.getElementById('finding-extracted-card');
    const extractedList = document.getElementById('finding-detail-extracted');
    if (f.extracted_results && f.extracted_results.length > 0) {
        extractedCard.classList.remove('hidden');
        extractedList.innerHTML = f.extracted_results.map(e =>
            `<li class="text-green-400 font-mono">${escapeHtml(e)}</li>`
        ).join('');
    } else { extractedCard.classList.add('hidden'); }

    const requestCard = document.getElementById('finding-request-card');
    const requestText = document.getElementById('finding-detail-request');
    if (f.request) { requestCard.classList.remove('hidden'); requestText.textContent = f.request; }
    else { requestCard.classList.add('hidden'); }

    const responseCard = document.getElementById('finding-response-card');
    const responseText = document.getElementById('finding-detail-response');
    if (f.response) { responseCard.classList.remove('hidden'); responseText.textContent = f.response; }
    else { responseCard.classList.add('hidden'); }

    document.getElementById('finding-detail-modal').classList.remove('hidden');
}

async function clearScanResults() {
    if (!confirm('Clear all scan results?')) return;
    try {
        await fetch('/api/scanner/results', { method: 'DELETE' });
        document.getElementById('scanner-live-body').innerHTML = '';
        document.getElementById('scanner-live-feed').classList.add('hidden');
        liveSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        await loadScannerView();
    } catch (e) {
        console.error('Failed to clear results:', e);
    }
}

// Scanner event listeners
async function stopScan() {
    if (!confirm('Stop the current scan? Findings collected so far will be kept.')) return;
    try {
        const stopBtn = document.getElementById('scanner-stop-btn');
        stopBtn.disabled = true;
        stopBtn.textContent = 'Stopping...';
        await fetch('/api/scanner/stop', { method: 'POST' });
    } catch (e) {
        console.error('Failed to stop scan:', e);
    }
}

document.getElementById('scanner-start-btn')?.addEventListener('click', () => startScan());
document.getElementById('scanner-stop-btn')?.addEventListener('click', stopScan);
document.getElementById('scanner-preview-btn')?.addEventListener('click', previewTargets);
document.getElementById('scanner-clear-btn')?.addEventListener('click', clearScanResults);
document.getElementById('scanner-filter-btn')?.addEventListener('click', () => { scannerPage = 1; loadScannerFindings(); });
document.getElementById('scanner-prev')?.addEventListener('click', () => { if (scannerPage > 1) { scannerPage--; loadScannerFindings(); } });
document.getElementById('scanner-next')?.addEventListener('click', () => { scannerPage++; loadScannerFindings(); });
document.getElementById('finding-detail-modal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
});

// Target panel controls
document.getElementById('scanner-select-all')?.addEventListener('click', () => {
    document.querySelectorAll('.scanner-target-cb').forEach(cb => cb.checked = true);
});
document.getElementById('scanner-select-none')?.addEventListener('click', () => {
    document.querySelectorAll('.scanner-target-cb').forEach(cb => cb.checked = false);
});
document.getElementById('scanner-close-targets')?.addEventListener('click', () => {
    document.getElementById('scanner-targets-panel').classList.add('hidden');
});
document.getElementById('scanner-run-selected')?.addEventListener('click', () => {
    const selected = [];
    document.querySelectorAll('.scanner-target-cb:checked').forEach(cb => selected.push(cb.value));
    if (selected.length === 0) { alert('Select at least one target'); return; }
    startScan(selected);
});

// ── Firewall ─────────────────────────────────────────────────
let currentFwTab = 'rules';

window.loadFwTab = function (tab) {
    currentFwTab = tab;
    document.querySelectorAll('[data-fwtab]').forEach(b => b.classList.toggle('active', b.dataset.fwtab === tab));
    document.querySelectorAll('.fwtab-panel').forEach(p => p.classList.add('hidden'));
    document.getElementById(`fwtab-${tab}`)?.classList.remove('hidden');
    if (tab === 'rules') {
        loadFirewallRulesTab();
    } else if (tab === 'fail2ban') {
        loadFail2BanTab();
    }
};

async function loadFirewallView() {
    loadFwTab(currentFwTab);
}

async function loadFirewallRulesTab() {
    await Promise.all([loadFirewallStatus(), loadFirewallBlocked(), loadFirewallHistory()]);
}

async function loadFirewallStatus() {
    try {
        const res = await fetch('/api/firewall/status');
        const data = await res.json();

        // Backend badge
        const badge = document.getElementById('fw-backend-badge');
        if (data.available) {
            badge.textContent = data.backend.toUpperCase();
            badge.className = 'badge badge-resolved';
        } else {
            badge.textContent = 'No firewall detected';
            badge.className = 'badge badge-open';
        }

        // Permission warning
        let permWarn = document.getElementById('fw-perm-warning');
        if (!permWarn) {
            permWarn = document.createElement('div');
            permWarn.id = 'fw-perm-warning';
            permWarn.style.cssText = 'color:#fbbf24;font-size:0.8rem;margin-top:4px;display:none';
            badge.parentElement?.appendChild(permWarn);
        }
        if (data.available && !data.can_execute) {
            permWarn.textContent = 'Cannot execute firewall commands — configure passwordless sudo for ' + (data.backend || 'firewall');
            permWarn.style.display = '';
        } else {
            permWarn.style.display = 'none';
        }

        // Auto-block toggle
        const toggle = document.getElementById('fw-autoblock-toggle');
        if (data.auto_block?.enabled !== undefined) {
            toggle.checked = data.auto_block.enabled;
        }

        // Populate threshold inputs
        const ab = data.auto_block || {};
        if (ab.ssh_block_threshold !== undefined) {
            document.getElementById('fw-thresh-ssh').value = ab.ssh_block_threshold;
            document.getElementById('fw-thresh-brute').value = ab.brute_session_block_threshold;
            document.getElementById('fw-thresh-http').value = ab.http_block_threshold;
            document.getElementById('fw-thresh-score').value = ab.score_block_threshold;
            document.getElementById('fw-thresh-window').value = ab.auto_block_window_seconds;
            document.getElementById('fw-thresh-duration').value = ab.auto_block_duration_hours;
        }
    } catch (e) {
        console.error('Failed to load firewall status:', e);
    }
}

async function loadFirewallBlocked() {
    try {
        const res = await fetch('/api/firewall/blocked');
        const data = await res.json();
        const tbody = document.getElementById('fw-blocked-body');
        const blocked = data.blocked || [];

        // Update stats
        document.getElementById('fw-stat-blocked').textContent = blocked.length;
        document.getElementById('fw-stat-auto').textContent = blocked.filter(b => b.source === 'auto').length;
        document.getElementById('fw-stat-manual').textContent = blocked.filter(b => b.source === 'manual').length;
        document.getElementById('fw-stat-temp').textContent = blocked.filter(b => b.expires_at).length;

        if (blocked.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-gray-500 text-center">No active blocks</td></tr>';
            return;
        }

        tbody.innerHTML = blocked.map(b => {
            const blockedAt = b.blocked_at ? new Date(b.blocked_at * 1000).toLocaleString() : '-';
            let expires = '-';
            if (b.expires_at) {
                const remaining = b.expires_at - Date.now() / 1000;
                if (remaining > 0) {
                    const hrs = Math.floor(remaining / 3600);
                    const mins = Math.floor((remaining % 3600) / 60);
                    expires = `${hrs}h ${mins}m remaining`;
                } else {
                    expires = 'Expiring...';
                }
            } else {
                expires = 'Permanent';
            }
            const srcBadge = b.source === 'auto' ? 'badge-investigating' : b.source === 'system' ? 'badge-closed' : 'badge-info';
            return `<tr>
                <td class="font-medium">${escapeHtml(b.ip)}</td>
                <td class="text-xs" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(b.reason || '-')}</td>
                <td><span class="badge ${srcBadge}">${b.source}</span></td>
                <td>${blockedAt}</td>
                <td>${expires}</td>
                <td>${countryFlag(b.country_code)} ${b.country_code || '-'}</td>
                <td class="text-xs">${escapeHtml(b.org || '-')}</td>
                <td><button class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;color:#f87171" onclick="firewallUnblock('${escapeHtml(b.ip)}')">Unblock</button></td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('Failed to load firewall blocked list:', e);
    }
}

async function loadFirewallHistory() {
    try {
        const res = await fetch('/api/firewall/history?limit=50');
        const data = await res.json();
        const tbody = document.getElementById('fw-history-body');
        const history = data.history || [];

        if (history.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-gray-500 text-center">No block history</td></tr>';
            return;
        }

        tbody.innerHTML = history.map(h => {
            const blockedAt = h.blocked_at ? new Date(h.blocked_at * 1000).toLocaleString() : '-';
            const unblockedAt = h.unblocked_at ? new Date(h.unblocked_at * 1000).toLocaleString() : '-';
            const statusBadge = h.active ? '<span class="badge badge-open">Active</span>' : '<span class="badge badge-closed">Inactive</span>';
            const srcBadge = h.source === 'auto' ? 'badge-investigating' : 'badge-info';
            return `<tr>
                <td class="font-medium">${escapeHtml(h.ip)}</td>
                <td class="text-xs" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(h.reason || '-')}</td>
                <td><span class="badge ${srcBadge}">${h.source}</span></td>
                <td>${blockedAt}</td>
                <td>${unblockedAt}</td>
                <td>${statusBadge}</td>
                <td>${countryFlag(h.country_code)} ${h.country_code || '-'}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        console.error('Failed to load firewall history:', e);
    }
}

window.firewallUnblock = async function (ip) {
    if (!confirm(`Unblock ${ip}?`)) return;
    try {
        const res = await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await res.json();
        if (data.error) {
            alert(data.error);
            return;
        }
        await loadFirewallView();
    } catch (e) {
        console.error('Failed to unblock IP:', e);
    }
};

async function firewallBlockIP() {
    const ip = document.getElementById('fw-block-ip').value.trim();
    if (!ip) { alert('Enter an IP address'); return; }
    const reason = document.getElementById('fw-block-reason').value.trim();
    const durationInput = document.getElementById('fw-block-duration').value.trim();
    const duration_hours = durationInput ? parseInt(durationInput, 10) : null;

    try {
        const res = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason, duration_hours }),
        });
        const data = await res.json();
        if (!data.ok) {
            alert(data.error || 'Block failed');
            return;
        }
        document.getElementById('fw-block-ip').value = '';
        document.getElementById('fw-block-reason').value = '';
        document.getElementById('fw-block-duration').value = '';
        await loadFirewallView();
    } catch (e) {
        console.error('Failed to block IP:', e);
        alert('Failed to block IP');
    }
}

async function firewallSaveThresholds() {
    const settings = {
        ssh_block_threshold: parseInt(document.getElementById('fw-thresh-ssh').value, 10),
        brute_session_block_threshold: parseInt(document.getElementById('fw-thresh-brute').value, 10),
        http_block_threshold: parseInt(document.getElementById('fw-thresh-http').value, 10),
        score_block_threshold: parseInt(document.getElementById('fw-thresh-score').value, 10),
        auto_block_window_seconds: parseInt(document.getElementById('fw-thresh-window').value, 10),
        auto_block_duration_hours: parseInt(document.getElementById('fw-thresh-duration').value, 10),
    };

    try {
        const res = await fetch('/api/firewall/settings', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings),
        });
        const data = await res.json();
        if (data.error) {
            alert(data.error);
            return;
        }
        // Brief visual feedback
        const btn = document.getElementById('fw-save-thresholds');
        btn.textContent = 'Saved!';
        setTimeout(() => { btn.textContent = 'Save Thresholds'; }, 1500);
    } catch (e) {
        console.error('Failed to save thresholds:', e);
    }
}

async function firewallToggleAutoBlock() {
    const enabled = document.getElementById('fw-autoblock-toggle').checked;
    try {
        await fetch('/api/firewall/settings', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ auto_block_enabled: enabled }),
        });
    } catch (e) {
        console.error('Failed to toggle auto-block:', e);
    }
}

window.blockIPFromModal = async function () {
    if (!currentModalIP) return;
    const reason = prompt(`Block ${currentModalIP}? Enter a reason (optional):`, 'Blocked from IP detail view');
    if (reason === null) return; // cancelled
    try {
        const res = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: currentModalIP, reason }),
        });
        const data = await res.json();
        if (!data.ok) {
            alert(data.error || 'Block failed');
            return;
        }
        const btn = document.getElementById('modal-block-btn');
        btn.textContent = 'Blocked';
        btn.disabled = true;
    } catch (e) {
        console.error('Failed to block IP:', e);
        alert('Failed to block IP');
    }
};

// Firewall event listeners
document.getElementById('fw-block-btn')?.addEventListener('click', firewallBlockIP);
document.getElementById('fw-save-thresholds')?.addEventListener('click', firewallSaveThresholds);
document.getElementById('fw-autoblock-toggle')?.addEventListener('change', firewallToggleAutoBlock);

// ── Fail2Ban ─────────────────────────────────────────────────
let _f2bJailNames = [];

async function loadFail2BanTab() {
    await Promise.all([loadF2BStatus(), loadF2BConfig()]);
}

async function loadF2BStatus() {
    try {
        const res = await fetch('/api/fail2ban/status');
        const data = await res.json();

        const statusBadge = document.getElementById('f2b-status-badge');
        const notInstalled = document.getElementById('f2b-not-installed');
        const jailsSection = document.getElementById('f2b-jails-section');
        const bansSection = document.getElementById('f2b-bans-section');

        if (!data.installed) {
            statusBadge.textContent = 'Not Installed';
            statusBadge.className = 'badge badge-closed';
            notInstalled.classList.remove('hidden');
            jailsSection.classList.add('hidden');
            bansSection.classList.add('hidden');
            return;
        }

        notInstalled.classList.add('hidden');
        jailsSection.classList.remove('hidden');
        bansSection.classList.remove('hidden');

        if (!data.running) {
            statusBadge.textContent = data.error ? 'Error' : 'Stopped';
            statusBadge.className = 'badge badge-open';
            document.getElementById('f2b-stat-version').textContent = '-';
            document.getElementById('f2b-stat-jails').textContent = '0';
            document.getElementById('f2b-stat-banned').textContent = '0';

            if (data.error) {
                jailsSection.classList.remove('hidden');
                document.getElementById('f2b-jails-grid').innerHTML = `
                    <div class="card" style="grid-column: 1 / -1; border-color: #ef4444;">
                        <span class="text-red-400 font-bold mb-2 block">Error Communicating with Fail2Ban</span>
                        <pre class="text-xs text-gray-400 p-3 bg-gray-900 rounded" style="white-space: pre-wrap; font-family: monospace;">${escapeHtml(data.error)}</pre>
                        <p class="text-sm text-gray-400 mt-3">
                            DefenseWatch requires password-less sudo for <code>fail2ban-client</code> to read status and modify jails.<br>
                            Ensure <code>fail2ban</code> is running and add the following to your sudoers file:<br><br>
                            <code class="text-gray-300 bg-gray-800 p-1 rounded">defensewatch ALL=(root) NOPASSWD: /usr/bin/fail2ban-client</code>
                        </p>
                    </div>`;
                bansSection.classList.add('hidden');
            }

            return;
        }

        statusBadge.textContent = 'Running';
        statusBadge.className = 'badge badge-resolved';
        document.getElementById('f2b-stat-version').textContent = data.version || '-';
        document.getElementById('f2b-stat-jails').textContent = data.jail_count || 0;
        document.getElementById('f2b-stat-banned').textContent = data.total_banned || 0;

        // Populate jail select dropdown
        _f2bJailNames = (data.jails || []).map(j => j.name);
        const jailSelect = document.getElementById('f2b-ban-jail');
        jailSelect.innerHTML = _f2bJailNames.map(n => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join('');

        // Render jail cards
        renderF2BJails(data.jails || []);

        // Render combined banned IPs table
        renderF2BBannedTable(data.jails || []);
    } catch (e) {
        console.error('Failed to load Fail2Ban status:', e);
    }
}

function renderF2BJails(jails) {
    const grid = document.getElementById('f2b-jails-grid');
    if (jails.length === 0) {
        grid.innerHTML = '<p class="text-gray-500 text-center">No active jails</p>';
        return;
    }

    grid.innerHTML = jails.map(j => {
        const bannedCount = j.currently_banned || 0;
        const bantimeHrs = j.bantime ? (j.bantime >= 3600 ? `${Math.round(j.bantime / 3600)}h` : `${j.bantime}s`) : '-';
        const findtimeMin = j.findtime ? (j.findtime >= 60 ? `${Math.round(j.findtime / 60)}m` : `${j.findtime}s`) : '-';

        return `<div class="card" style="background:var(--bg)">
            <div class="flex items-center justify-between mb-2">
                <span class="font-medium text-blue-400">${escapeHtml(j.name)}</span>
                <span class="badge ${bannedCount > 0 ? 'badge-open' : 'badge-resolved'}">${bannedCount} banned</span>
            </div>
            <div class="grid grid-cols-3 gap-2 text-xs text-gray-400 mb-2">
                <div><span class="text-gray-600">Max Retry:</span> ${j.maxretry ?? '-'}</div>
                <div><span class="text-gray-600">Find Time:</span> ${findtimeMin}</div>
                <div><span class="text-gray-600">Ban Time:</span> ${bantimeHrs}</div>
            </div>
            <div class="text-xs text-gray-400 mb-2">
                <span class="text-gray-600">Failed:</span> ${j.currently_failed || 0} current / ${j.total_failed || 0} total &nbsp;
                <span class="text-gray-600">Banned:</span> ${j.currently_banned || 0} current / ${j.total_banned || 0} total
            </div>
            ${j.log_files && j.log_files.length ? `<div class="text-xs text-gray-500" style="word-break:break-all"><span class="text-gray-600">Logs:</span> ${j.log_files.map(f => escapeHtml(f)).join(', ')}</div>` : ''}
            <div class="flex gap-2 mt-2">
                <input type="number" class="input-dark" style="width:60px;font-size:0.7rem" id="f2b-param-maxretry-${j.name}" value="${j.maxretry ?? ''}" placeholder="retry" title="maxretry">
                <input type="number" class="input-dark" style="width:70px;font-size:0.7rem" id="f2b-param-findtime-${j.name}" value="${j.findtime ?? ''}" placeholder="findtime" title="findtime (s)">
                <input type="number" class="input-dark" style="width:70px;font-size:0.7rem" id="f2b-param-bantime-${j.name}" value="${j.bantime ?? ''}" placeholder="bantime" title="bantime (s)">
                <button class="btn-secondary" style="font-size:0.7rem;padding:2px 8px" onclick="f2bUpdateJail('${escapeHtml(j.name)}')">Apply</button>
            </div>
        </div>`;
    }).join('');
}

function renderF2BBannedTable(jails) {
    const tbody = document.getElementById('f2b-banned-body');
    const rows = [];
    for (const j of jails) {
        for (const ip of (j.banned_ips || [])) {
            rows.push({ ip, jail: j.name });
        }
    }

    if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-gray-500 text-center">No banned IPs</td></tr>';
        return;
    }

    tbody.innerHTML = rows.map(r => `<tr>
        <td class="font-medium font-mono">${escapeHtml(r.ip)}</td>
        <td><span class="badge badge-info">${escapeHtml(r.jail)}</span></td>
        <td><button class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;color:#f87171" onclick="f2bUnban('${escapeHtml(r.jail)}','${escapeHtml(r.ip)}')">Unban</button></td>
    </tr>`).join('');
}

window.f2bUnban = async function (jail, ip) {
    if (!confirm(`Unban ${ip} from ${jail}?`)) return;
    try {
        const res = await fetch('/api/fail2ban/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jail, ip }),
        });
        const data = await res.json();
        if (!data.ok) { alert(data.error || 'Unban failed'); return; }
        await loadF2BStatus();
    } catch (e) {
        console.error('Failed to unban:', e);
    }
};

window.f2bUpdateJail = async function (jail) {
    const maxretry = document.getElementById(`f2b-param-maxretry-${jail}`)?.value;
    const findtime = document.getElementById(`f2b-param-findtime-${jail}`)?.value;
    const bantime = document.getElementById(`f2b-param-bantime-${jail}`)?.value;

    const updates = [];
    if (maxretry) updates.push({ jail, param: 'maxretry', value: maxretry });
    if (findtime) updates.push({ jail, param: 'findtime', value: findtime });
    if (bantime) updates.push({ jail, param: 'bantime', value: bantime });

    try {
        for (const u of updates) {
            const res = await fetch('/api/fail2ban/jail', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(u),
            });
            const data = await res.json();
            if (!data.ok) {
                alert(`Failed to set ${u.param}: ${data.error}`);
                return;
            }
        }
        await loadF2BStatus();
    } catch (e) {
        console.error('Failed to update jail:', e);
    }
};

async function f2bBanIP() {
    const ip = document.getElementById('f2b-ban-ip').value.trim();
    const jail = document.getElementById('f2b-ban-jail').value;
    if (!ip) { alert('Enter an IP address'); return; }
    if (!jail) { alert('Select a jail'); return; }

    try {
        const res = await fetch('/api/fail2ban/ban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jail, ip }),
        });
        const data = await res.json();
        if (!data.ok) { alert(data.error || 'Ban failed'); return; }
        document.getElementById('f2b-ban-ip').value = '';
        await loadF2BStatus();
    } catch (e) {
        console.error('Failed to ban IP:', e);
        alert('Failed to ban IP');
    }
}

async function loadF2BConfig() {
    try {
        const res = await fetch('/api/fail2ban/config');
        const data = await res.json();
        if (!data.installed) return;

        document.getElementById('f2b-stat-configs').textContent = (data.files || []).length;
        document.getElementById('f2b-config-files').textContent = 'Files: ' + (data.files || []).join(', ');

        // Format config as readable text
        let configText = '';
        if (data.defaults && Object.keys(data.defaults).length) {
            configText += '[DEFAULT]\n';
            for (const [k, v] of Object.entries(data.defaults)) {
                configText += `${k} = ${v}\n`;
            }
            configText += '\n';
        }
        for (const [name, values] of Object.entries(data.jails || {})) {
            configText += `[${name}]\n`;
            for (const [k, v] of Object.entries(values)) {
                configText += `${k} = ${v}\n`;
            }
            configText += '\n';
        }
        document.getElementById('f2b-config-raw').textContent = configText || 'No configuration found';
    } catch (e) {
        console.error('Failed to load F2B config:', e);
    }
}

async function f2bReload() {
    if (!confirm('Reload Fail2Ban configuration?')) return;
    try {
        const res = await fetch('/api/fail2ban/reload', { method: 'POST' });
        const data = await res.json();
        if (!data.ok) { alert(data.error || 'Reload failed'); return; }
        await loadFail2BanTab();
    } catch (e) {
        console.error('Failed to reload F2B:', e);
    }
}

async function f2bGenRecommended() {
    try {
        const res = await fetch('/api/fail2ban/recommended');
        const data = await res.json();
        if (data.error) { alert(data.error); return; }

        let output = '# Recommended Fail2Ban configuration for DefenseWatch\n';
        output += '# Generated based on your monitored services\n\n';

        if (data.defaults?.config) {
            output += '# ─── Defaults ─────────────────────────────────────\n';
            output += data.defaults.config + '\n\n';
        }

        for (const [name, jail] of Object.entries(data.jails || {})) {
            output += `# ─── ${jail.description || name} ───\n`;
            if (!jail.filter_exists) {
                output += `# NOTE: Filter "${name}" may need a custom filter file\n`;
            }
            output += jail.config + '\n\n';
        }

        if (data.custom_filters && Object.keys(data.custom_filters).length) {
            output += '\n# ═══ Custom filter files (create these separately) ═══\n\n';
            for (const [name, filter] of Object.entries(data.custom_filters)) {
                output += `# File: ${filter.path}\n`;
                output += filter.content + '\n';
            }
        }

        output += '\n# ─── Installation Steps ───────────────────────────\n';
        output += '# 1. Copy the jail config above into /etc/fail2ban/jail.local\n';
        output += '# 2. Create any custom filter files listed above\n';
        output += '# 3. Reload: sudo fail2ban-client reload\n';
        output += '# 4. Verify: sudo fail2ban-client status\n';

        document.getElementById('f2b-recommended-raw').textContent = output;
        document.getElementById('f2b-recommended-content').classList.remove('hidden');
    } catch (e) {
        console.error('Failed to generate recommended config:', e);
    }
}

function f2bCopyConfig() {
    const text = document.getElementById('f2b-recommended-raw').textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('f2b-copy-config');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy to Clipboard'; }, 1500);
    });
}

// Fail2Ban event listeners
document.getElementById('f2b-ban-btn')?.addEventListener('click', f2bBanIP);
document.getElementById('f2b-reload-btn')?.addEventListener('click', f2bReload);
document.getElementById('f2b-show-config-btn')?.addEventListener('click', () => {
    document.getElementById('f2b-config-content')?.classList.toggle('hidden');
});
document.getElementById('f2b-gen-config-btn')?.addEventListener('click', f2bGenRecommended);
document.getElementById('f2b-copy-config')?.addEventListener('click', f2bCopyConfig);

// ── Settings ──────────────────────────────────────────────────
let currentSettab = 'webhooks';

document.querySelectorAll('[data-settab]').forEach(btn => {
    btn.addEventListener('click', () => {
        currentSettab = btn.dataset.settab;
        document.querySelectorAll('[data-settab]').forEach(b => b.classList.toggle('active', b.dataset.settab === currentSettab));
        document.querySelectorAll('.settab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById(`settab-${currentSettab}`)?.classList.remove('hidden');
        loadSettingsTab(currentSettab);
    });
});

async function loadSettingsView() {
    loadSettingsTab(currentSettab);
}

async function loadSettingsTab(tab) {
    if (tab === 'telegram') {
        await loadTelegramView();
        return;
    }
    try {
        const res = await fetch('/api/settings/status');
        const data = await res.json();
        if (data.error) return;

        if (tab === 'webhooks') populateWebhooks(data.webhooks);
        else if (tab === 'apikeys') populateApiKeys(data.api_keys);
        else if (tab === 'services') populateServices(data.services);
        else if (tab === 'detection') populateDetection(data.detection);
        else if (tab === 'general') populateGeneral(data.general);
    } catch (e) {
        console.error('Failed to load settings:', e);
    }
}

function showSettingsFeedback(msg, isError) {
    const el = document.getElementById('settings-feedback');
    el.textContent = msg;
    el.className = `mb-3 text-sm ${isError ? 'text-red-400' : 'text-green-400'}`;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
}

// ── Webhooks ──
function populateWebhooks(wh) {
    document.getElementById('set-wh-enabled').checked = wh.notifications_enabled || false;
    document.getElementById('set-wh-url').value = wh.webhook_url || '';
    document.getElementById('set-wh-severity').value = wh.min_severity || 'high';
    document.getElementById('set-wh-cooldown').value = wh.cooldown_seconds ?? 300;
    const whEvents = wh.notify_events || ['brute_force', 'http_attack', 'anomaly', 'firewall_block'];
    document.getElementById('set-wh-evt-brute').checked = whEvents.includes('brute_force');
    document.getElementById('set-wh-evt-http').checked = whEvents.includes('http_attack');
    document.getElementById('set-wh-evt-anomaly').checked = whEvents.includes('anomaly');
    document.getElementById('set-wh-evt-firewall').checked = whEvents.includes('firewall_block');
    document.getElementById('set-wh-evt-portscan').checked = whEvents.includes('port_scan');
    document.getElementById('set-rpt-enabled').checked = wh.reports_enabled || false;
    document.getElementById('set-rpt-url').value = wh.reports_webhook_url || '';
    document.getElementById('set-rpt-interval').value = wh.reports_interval_hours ?? 24;
}

document.getElementById('set-wh-save')?.addEventListener('click', async () => {
    const notifyEvents = [];
    if (document.getElementById('set-wh-evt-brute').checked) notifyEvents.push('brute_force');
    if (document.getElementById('set-wh-evt-http').checked) notifyEvents.push('http_attack');
    if (document.getElementById('set-wh-evt-anomaly').checked) notifyEvents.push('anomaly');
    if (document.getElementById('set-wh-evt-firewall').checked) notifyEvents.push('firewall_block');
    if (document.getElementById('set-wh-evt-portscan').checked) notifyEvents.push('port_scan');
    const body = {
        notifications_enabled: document.getElementById('set-wh-enabled').checked,
        webhook_url: document.getElementById('set-wh-url').value.trim(),
        min_severity: document.getElementById('set-wh-severity').value,
        cooldown_seconds: parseInt(document.getElementById('set-wh-cooldown').value, 10),
        notify_events: notifyEvents,
        reports_enabled: document.getElementById('set-rpt-enabled').checked,
        reports_webhook_url: document.getElementById('set-rpt-url').value.trim(),
        reports_interval_hours: parseInt(document.getElementById('set-rpt-interval').value, 10),
    };
    try {
        const res = await fetch('/api/settings/webhooks', {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const data = await res.json();
        showSettingsFeedback(data.error || 'Webhook settings saved', !!data.error);
    } catch (e) {
        showSettingsFeedback('Failed to save webhook settings', true);
    }
});

// ── API Keys ──
function populateApiKeys(ak) {
    document.getElementById('set-ti-enabled').checked = ak.threat_intel_enabled || false;
    document.getElementById('set-ti-refresh').value = ak.threat_intel_refresh_hours ?? 6;

    const keyStatuses = [
        ['set-abuseipdb-status', ak.abuseipdb_api_key_set],
        ['set-otx-status', ak.otx_api_key_set],
        ['set-shodan-status', ak.shodan_api_key_set],
        ['set-vt-status', ak.virustotal_api_key_set],
        ['set-censys-id-status', ak.censys_api_id_set],
        ['set-censys-secret-status', ak.censys_api_secret_set],
    ];
    for (const [id, isSet] of keyStatuses) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = isSet ? 'configured' : 'not set';
            el.className = `badge ${isSet ? 'badge-resolved' : 'badge-open'}`;
            el.style.marginLeft = '6px';
            el.style.fontSize = '0.6rem';
        }
    }
}

document.getElementById('set-apikeys-save')?.addEventListener('click', async () => {
    const body = {
        threat_intel_enabled: document.getElementById('set-ti-enabled').checked,
        threat_intel_refresh_hours: parseInt(document.getElementById('set-ti-refresh').value, 10),
    };
    const fields = [
        ['set-abuseipdb-key', 'abuseipdb_api_key'],
        ['set-otx-key', 'otx_api_key'],
        ['set-shodan-key', 'shodan_api_key'],
        ['set-vt-key', 'virustotal_api_key'],
        ['set-censys-id', 'censys_api_id'],
        ['set-censys-secret', 'censys_api_secret'],
    ];
    for (const [elId, key] of fields) {
        const val = document.getElementById(elId).value.trim();
        if (val) body[key] = val;
    }
    try {
        const res = await fetch('/api/settings/api-keys', {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const data = await res.json();
        showSettingsFeedback(data.error || 'API keys saved', !!data.error);
        if (!data.error) {
            // Clear password fields after save
            for (const [elId] of fields) document.getElementById(elId).value = '';
            loadSettingsTab('apikeys');
        }
    } catch (e) {
        showSettingsFeedback('Failed to save API keys', true);
    }
});

// ── Services ──
function populateServices(services) {
    const container = document.getElementById('set-svc-list');
    container.innerHTML = '';

    const typeLabels = { ssh: 'SSH', http: 'HTTP', mysql: 'MySQL', postgresql: 'PostgreSQL', mail: 'Mail', ftp: 'FTP' };

    let hasAny = false;
    for (const [svcType, entries] of Object.entries(services)) {
        for (const entry of entries) {
            hasAny = true;
            const div = document.createElement('div');
            div.className = 'svc-entry';
            div.innerHTML = `
                <span class="svc-type">${escapeHtml(typeLabels[svcType] || svcType)}</span>
                <span class="svc-path" title="${escapeHtml(entry.path)}">${escapeHtml(entry.path)}</span>
                ${entry.vhost ? `<span class="svc-vhost">${escapeHtml(entry.vhost)}</span>` : ''}
                <span class="svc-port">:${entry.port}</span>
                <button class="svc-remove" data-type="${svcType}" data-path="${escapeHtml(entry.path)}">Remove</button>
            `;
            container.appendChild(div);
        }
    }

    if (!hasAny) {
        container.innerHTML = '<p class="text-sm text-gray-500">No services configured.</p>';
    }

    container.querySelectorAll('.svc-remove').forEach(btn => {
        btn.addEventListener('click', async () => {
            const svcType = btn.dataset.type;
            const path = btn.dataset.path;
            try {
                const res = await fetch('/api/settings/services', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ service_type: svcType, path }),
                });
                const data = await res.json();
                showSettingsFeedback(data.error || data.message || 'Service removed', !!data.error);
                if (!data.error) loadSettingsTab('services');
            } catch (e) {
                showSettingsFeedback('Failed to remove service', true);
            }
        });
    });
}

document.getElementById('set-svc-add-btn')?.addEventListener('click', () => {
    document.getElementById('set-svc-form').classList.toggle('hidden');
});
document.getElementById('set-svc-cancel')?.addEventListener('click', () => {
    document.getElementById('set-svc-form').classList.add('hidden');
});

// Update port placeholder when service type changes
document.getElementById('set-svc-type')?.addEventListener('change', () => {
    const defaults = { ssh: 22, http: 80, mysql: 3306, postgresql: 5432, mail: 25, ftp: 21 };
    const t = document.getElementById('set-svc-type').value;
    document.getElementById('set-svc-port').placeholder = defaults[t] || '';
});

document.getElementById('set-svc-submit')?.addEventListener('click', async () => {
    const svcType = document.getElementById('set-svc-type').value;
    const path = document.getElementById('set-svc-path').value.trim();
    const portVal = document.getElementById('set-svc-port').value.trim();

    if (!path) { showSettingsFeedback('Log file path is required', true); return; }

    const body = { service_type: svcType, path };
    if (portVal) body.port = parseInt(portVal, 10);

    try {
        const res = await fetch('/api/settings/services', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        showSettingsFeedback(data.error || data.message || 'Service added', !!data.error);
        if (!data.error) {
            document.getElementById('set-svc-path').value = '';
            document.getElementById('set-svc-port').value = '';
            document.getElementById('set-svc-form').classList.add('hidden');
            loadSettingsTab('services');
        }
    } catch (e) {
        showSettingsFeedback('Failed to add service', true);
    }
});

// Save config to file
document.getElementById('set-save-config')?.addEventListener('click', async () => {
    const msgEl = document.getElementById('set-save-config-msg');
    try {
        const res = await fetch('/api/settings/save-config', { method: 'POST' });
        const data = await res.json();
        msgEl.textContent = data.error || data.message || 'Saved';
        msgEl.className = `text-sm ml-3 ${data.error ? 'text-red-400' : 'text-green-400'}`;
        msgEl.classList.remove('hidden');
        setTimeout(() => msgEl.classList.add('hidden'), 5000);
    } catch (e) {
        msgEl.textContent = 'Failed to save';
        msgEl.className = 'text-sm ml-3 text-red-400';
        msgEl.classList.remove('hidden');
    }
});

// ── Detection ──
function populateDetection(det) {
    document.getElementById('set-det-ssh-thresh').value = det.ssh_brute_threshold;
    document.getElementById('set-det-ssh-window').value = det.ssh_brute_window_seconds;
    document.getElementById('set-det-http-thresh').value = det.http_scan_threshold;
    document.getElementById('set-det-http-window').value = det.http_scan_window_seconds;
    document.getElementById('set-det-portscan-thresh').value = det.portscan_threshold;
    document.getElementById('set-det-portscan-window').value = det.portscan_window_seconds;
}

document.getElementById('set-det-save')?.addEventListener('click', async () => {
    const body = {
        ssh_brute_threshold: parseInt(document.getElementById('set-det-ssh-thresh').value, 10),
        ssh_brute_window_seconds: parseInt(document.getElementById('set-det-ssh-window').value, 10),
        http_scan_threshold: parseInt(document.getElementById('set-det-http-thresh').value, 10),
        http_scan_window_seconds: parseInt(document.getElementById('set-det-http-window').value, 10),
        portscan_threshold: parseInt(document.getElementById('set-det-portscan-thresh').value, 10),
        portscan_window_seconds: parseInt(document.getElementById('set-det-portscan-window').value, 10),
    };
    try {
        const res = await fetch('/api/settings/detection', {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const data = await res.json();
        showSettingsFeedback(data.error || 'Detection settings saved', !!data.error);
    } catch (e) {
        showSettingsFeedback('Failed to save detection settings', true);
    }
});

// ── General ──
function populateGeneral(gen) {
    document.getElementById('set-gen-hostname').value = gen.host_name || '';
    document.getElementById('set-gen-lat').value = gen.host_latitude ?? '';
    document.getElementById('set-gen-lon').value = gen.host_longitude ?? '';
    document.getElementById('set-gen-retention').value = gen.database_retention_days ?? 30;
    document.getElementById('set-gen-reenrich').value = gen.geoip_re_enrich_days ?? 7;
    document.getElementById('set-gen-whois').checked = gen.enrichment_whois_enabled ?? true;
}

document.getElementById('set-gen-save')?.addEventListener('click', async () => {
    const body = {
        host_name: document.getElementById('set-gen-hostname').value.trim(),
        host_latitude: parseFloat(document.getElementById('set-gen-lat').value) || null,
        host_longitude: parseFloat(document.getElementById('set-gen-lon').value) || null,
        database_retention_days: parseInt(document.getElementById('set-gen-retention').value, 10),
        geoip_re_enrich_days: parseInt(document.getElementById('set-gen-reenrich').value, 10),
        enrichment_whois_enabled: document.getElementById('set-gen-whois').checked,
    };
    try {
        const res = await fetch('/api/settings/general', {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const data = await res.json();
        showSettingsFeedback(data.error || 'General settings saved', !!data.error);
    } catch (e) {
        showSettingsFeedback('Failed to save general settings', true);
    }
});

// ── Telegram (within settings) ──
async function loadTelegramView() {
    try {
        const res = await fetch('/api/telegram/status');
        const data = await res.json();

        const badge = document.getElementById('tg-status-badge');
        const infoDiv = document.getElementById('tg-bot-info');

        if (data.configured && data.bot_info) {
            badge.textContent = `@${data.bot_info.username}`;
            badge.className = 'badge badge-resolved';
            infoDiv.innerHTML = `Bot: <strong>${escapeHtml(data.bot_info.name || '')}</strong> (@${escapeHtml(data.bot_info.username || '')})`;
        } else if (data.bot_token_set) {
            badge.textContent = 'Token set';
            badge.className = 'badge badge-investigating';
            infoDiv.textContent = '';
        } else {
            badge.textContent = 'Not configured';
            badge.className = 'badge badge-open';
            infoDiv.textContent = '';
        }

        document.getElementById('tg-enabled-toggle').checked = data.enabled || false;
        document.getElementById('tg-min-severity').value = data.min_severity || 'high';
        document.getElementById('tg-cooldown').value = data.cooldown_seconds ?? 300;
        const tgEvents = data.notify_events || ['brute_force', 'http_attack', 'anomaly', 'firewall_block'];
        document.getElementById('tg-evt-brute').checked = tgEvents.includes('brute_force');
        document.getElementById('tg-evt-http').checked = tgEvents.includes('http_attack');
        document.getElementById('tg-evt-anomaly').checked = tgEvents.includes('anomaly');
        document.getElementById('tg-evt-firewall').checked = tgEvents.includes('firewall_block');
        document.getElementById('tg-evt-portscan').checked = tgEvents.includes('port_scan');
        document.getElementById('tg-daily-reports').checked = data.daily_reports || false;
        document.getElementById('tg-weekly-reports').checked = data.weekly_reports || false;
        document.getElementById('tg-report-hour').value = data.report_hour ?? 8;

        if (data.chat_ids && data.chat_ids.length) {
            document.getElementById('tg-chat-ids').value = data.chat_ids.join(', ');
        }
    } catch (e) {
        console.error('Failed to load Telegram status:', e);
    }
}

function showTelegramFeedback(msg, isError) {
    const el = document.getElementById('tg-feedback');
    el.textContent = msg;
    el.className = `mt-3 text-sm ${isError ? 'text-red-400' : 'text-green-400'}`;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 5000);
}

async function telegramSaveSettings() {
    const tokenInput = document.getElementById('tg-bot-token').value.trim();
    const chatIdsRaw = document.getElementById('tg-chat-ids').value.trim();
    const chatIds = chatIdsRaw ? chatIdsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

    const tgNotifyEvents = [];
    if (document.getElementById('tg-evt-brute').checked) tgNotifyEvents.push('brute_force');
    if (document.getElementById('tg-evt-http').checked) tgNotifyEvents.push('http_attack');
    if (document.getElementById('tg-evt-anomaly').checked) tgNotifyEvents.push('anomaly');
    if (document.getElementById('tg-evt-firewall').checked) tgNotifyEvents.push('firewall_block');
    if (document.getElementById('tg-evt-portscan').checked) tgNotifyEvents.push('port_scan');
    const settings = {
        enabled: document.getElementById('tg-enabled-toggle').checked,
        min_severity: document.getElementById('tg-min-severity').value,
        cooldown_seconds: parseInt(document.getElementById('tg-cooldown').value, 10),
        notify_events: tgNotifyEvents,
        daily_reports: document.getElementById('tg-daily-reports').checked,
        weekly_reports: document.getElementById('tg-weekly-reports').checked,
        report_hour: parseInt(document.getElementById('tg-report-hour').value, 10),
        chat_ids: chatIds,
    };
    if (tokenInput) settings.bot_token = tokenInput;

    try {
        const res = await fetch('/api/telegram/settings', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings),
        });
        const data = await res.json();
        if (data.error) { showTelegramFeedback(data.error, true); return; }
        showTelegramFeedback('Settings saved successfully', false);
        await loadTelegramView();
    } catch (e) {
        showTelegramFeedback('Failed to save settings', true);
    }
}

async function telegramSendTest() {
    try {
        const res = await fetch('/api/telegram/test', { method: 'POST' });
        const data = await res.json();
        showTelegramFeedback(data.ok ? (data.message || 'Test message sent!') : (data.error || 'Test failed'), !data.ok);
    } catch (e) {
        showTelegramFeedback('Failed to send test message', true);
    }
}

async function telegramSendReport() {
    try {
        const res = await fetch('/api/telegram/report', { method: 'POST' });
        const data = await res.json();
        showTelegramFeedback(data.ok ? (data.message || 'Report sent!') : (data.error || 'Report failed'), !data.ok);
    } catch (e) {
        showTelegramFeedback('Failed to send report', true);
    }
}

document.getElementById('tg-save-btn')?.addEventListener('click', telegramSaveSettings);
document.getElementById('tg-test-btn')?.addEventListener('click', telegramSendTest);
document.getElementById('tg-report-btn')?.addEventListener('click', telegramSendReport);
document.getElementById('tg-enabled-toggle')?.addEventListener('change', async () => {
    const enabled = document.getElementById('tg-enabled-toggle').checked;
    try {
        await fetch('/api/telegram/settings', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled }),
        });
    } catch (e) {
        console.error('Failed to toggle Telegram:', e);
    }
});

// ── Auth ──────────────────────────────────────────────────────────────

function showLoginOverlay() {
    const overlay = document.getElementById('login-overlay');
    overlay.classList.remove('hidden');
    overlay.style.display = 'flex';
}

function hideLoginOverlay() {
    const overlay = document.getElementById('login-overlay');
    overlay.classList.add('hidden');
    overlay.style.display = 'none';
}

function updateUserMenu() {
    const menu = document.getElementById('user-menu');
    const display = document.getElementById('user-display');
    const user = JSON.parse(localStorage.getItem('dw_user') || 'null');
    if (user && authEnabled) {
        menu.classList.remove('hidden');
        menu.style.display = '';
        display.textContent = `${user.username} (${user.role})`;
    } else {
        menu.classList.add('hidden');
        menu.style.display = 'none';
    }
}

document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');
    errorEl.classList.add('hidden');
    try {
        const data = await postJSON('/api/auth/login', { username, password });
        setAuthToken(data.access_token);
        localStorage.setItem('dw_user', JSON.stringify(data.user));
        localStorage.setItem('dw_refresh_token', data.refresh_token);
        hideLoginOverlay();
        updateUserMenu();
        init();
    } catch (err) {
        errorEl.textContent = 'Invalid username or password';
        errorEl.classList.remove('hidden');
    }
});

document.getElementById('logout-btn')?.addEventListener('click', async () => {
    try { await postJSON('/api/auth/logout', {}); } catch {}
    clearAuthToken();
    localStorage.removeItem('dw_refresh_token');
    localStorage.removeItem('dw_user');
    updateUserMenu();
    if (authEnabled) {
        showLoginOverlay();
    }
});

window.addEventListener('dw-auth-required', () => {
    if (authEnabled) showLoginOverlay();
});

async function checkAuth() {
    try {
        // Check if auth is enabled by trying the /me endpoint
        const resp = await _origFetch('/api/auth/me', { headers: getAuthHeaders() });
        if (resp.status === 401) {
            // Auth is enabled but no valid token
            authEnabled = true;
            showLoginOverlay();
            return false;
        }
        const data = await resp.json();
        if (data.username === 'system' && data.role === 'admin' && data.id === 0) {
            // Auth disabled - synthetic user
            authEnabled = false;
        } else {
            authEnabled = true;
            localStorage.setItem('dw_user', JSON.stringify(data));
        }
        updateUserMenu();
        return true;
    } catch {
        // Server likely down or auth not configured
        return true;
    }
}


// ── Honeypot ──────────────────────────────────────────────────────────

let hpPage = 0;
const HP_LIMIT = 50;

async function loadHoneypotView() {
    try {
        const stats = await fetchJSON('/api/honeypot/stats');
        document.getElementById('hp-stat-total').textContent = formatNumber(stats.total_hits);
        document.getElementById('hp-stat-ips').textContent = formatNumber(stats.unique_ips);
        document.getElementById('hp-stat-24h').textContent = formatNumber(stats.hits_24h);
        document.getElementById('hp-stat-blocked').textContent = formatNumber(stats.auto_blocked);

        const pathsEl = document.getElementById('hp-top-paths');
        pathsEl.innerHTML = (stats.top_paths || []).map(p =>
            `<div class="flex justify-between"><code class="text-gray-300">${escapeHtml(p.path)}</code><span class="text-gray-500">${p.count}</span></div>`
        ).join('') || '<span class="text-gray-500">No data yet</span>';

        const ipsEl = document.getElementById('hp-top-ips');
        ipsEl.innerHTML = (stats.top_ips || []).map(i =>
            `<div class="flex justify-between"><span><a href="#" class="ip-link" data-ip="${escapeHtml(i.ip)}">${escapeHtml(i.ip)}</a> ${countryFlag(i.country_code)}</span><span class="text-gray-500">${i.count}</span></div>`
        ).join('') || '<span class="text-gray-500">No data yet</span>';
    } catch {}

    loadHoneypotEvents();
}

async function loadHoneypotEvents() {
    const ip = document.getElementById('hp-filter-ip')?.value || '';
    const offset = hpPage * HP_LIMIT;
    let url = `/api/honeypot/events?limit=${HP_LIMIT}&offset=${offset}`;
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;

    try {
        const data = await fetchJSON(url);
        const tbody = document.getElementById('hp-events-body');
        tbody.innerHTML = data.events.map(e =>
            `<tr>
                <td>${formatTime(e.timestamp)}</td>
                <td><a href="#" class="ip-link" data-ip="${escapeHtml(e.source_ip)}">${escapeHtml(e.source_ip)}</a></td>
                <td>${escapeHtml(e.method)}</td>
                <td><code>${escapeHtml(e.path)}</code></td>
                <td>${e.status_code}</td>
                <td class="text-xs">${truncate(e.user_agent, 50)}</td>
                <td>${countryFlag(e.country_code)} ${e.country_code || ''}</td>
                <td>${e.auto_blocked ? '<span class="badge badge-critical">Yes</span>' : '-'}</td>
            </tr>`
        ).join('') || '<tr><td colspan="8" class="text-center text-gray-500">No honeypot events</td></tr>';

        const total = data.total;
        const pageInfo = document.getElementById('hp-page-info');
        pageInfo.textContent = `${offset + 1}-${Math.min(offset + HP_LIMIT, total)} of ${total}`;
        document.getElementById('hp-prev').disabled = hpPage === 0;
        document.getElementById('hp-next').disabled = (offset + HP_LIMIT) >= total;
    } catch {}
}

document.getElementById('hp-prev')?.addEventListener('click', () => { if (hpPage > 0) { hpPage--; loadHoneypotEvents(); } });
document.getElementById('hp-next')?.addEventListener('click', () => { hpPage++; loadHoneypotEvents(); });
document.getElementById('hp-filter-ip')?.addEventListener('change', () => { hpPage = 0; loadHoneypotEvents(); });


// ── Audit Log ─────────────────────────────────────────────────────────

let auditPage = 0;
const AUDIT_LIMIT = 50;

async function loadAuditView() {
    loadAuditEvents();
}

async function loadAuditEvents() {
    const action = document.getElementById('audit-filter-action')?.value || '';
    const actor = document.getElementById('audit-filter-actor')?.value || '';
    const offset = auditPage * AUDIT_LIMIT;
    let url = `/api/audit?limit=${AUDIT_LIMIT}&offset=${offset}`;
    if (action) url += `&action=${encodeURIComponent(action)}`;
    if (actor) url += `&actor=${encodeURIComponent(actor)}`;

    try {
        const data = await fetchJSON(url);
        const tbody = document.getElementById('audit-events-body');
        tbody.innerHTML = data.entries.map(e =>
            `<tr>
                <td>${formatTime(e.timestamp)}</td>
                <td>${escapeHtml(e.actor)}</td>
                <td><span class="badge badge-info">${escapeHtml(e.action)}</span></td>
                <td>${escapeHtml(e.target)}</td>
                <td class="text-xs">${truncate(e.detail, 60)}</td>
                <td>${escapeHtml(e.ip_address) || '-'}</td>
            </tr>`
        ).join('') || '<tr><td colspan="6" class="text-center text-gray-500">No audit entries</td></tr>';

        const total = data.total;
        const pageInfo = document.getElementById('audit-page-info');
        pageInfo.textContent = `${Math.min(offset + 1, total)}-${Math.min(offset + AUDIT_LIMIT, total)} of ${total}`;
        document.getElementById('audit-prev').disabled = auditPage === 0;
        document.getElementById('audit-next').disabled = (offset + AUDIT_LIMIT) >= total;
    } catch {}
}

document.getElementById('audit-prev')?.addEventListener('click', () => { if (auditPage > 0) { auditPage--; loadAuditEvents(); } });
document.getElementById('audit-next')?.addEventListener('click', () => { auditPage++; loadAuditEvents(); });
document.getElementById('audit-filter-action')?.addEventListener('change', () => { auditPage = 0; loadAuditEvents(); });
document.getElementById('audit-filter-actor')?.addEventListener('change', () => { auditPage = 0; loadAuditEvents(); });


// ── Playbooks ─────────────────────────────────────────────────────────

let pbPage = 0;
const PB_LIMIT = 20;

async function loadPlaybooksView() {
    try {
        const status = await fetchJSON('/api/playbooks/status');
        document.getElementById('pb-stat-enabled').textContent = status.enabled ? 'Yes' : 'No';
        document.getElementById('pb-stat-interval').textContent = status.check_interval || '-';
        document.getElementById('pb-stat-rules').textContent = formatNumber(status.rules?.length || 0);
        document.getElementById('pb-stat-cooldowns').textContent = formatNumber(status.cooldown_entries || 0);

        const rulesBody = document.getElementById('pb-rules-body');
        rulesBody.innerHTML = (status.rules || []).map(r =>
            `<tr>
                <td>${escapeHtml(r.name)}</td>
                <td>${escapeHtml(r.description || '')}</td>
                <td class="text-xs"><code>${escapeHtml(r.condition || '')}</code></td>
                <td class="text-xs">${escapeHtml((r.actions || []).join(', '))}</td>
                <td>${escapeHtml(String(r.cooldown || '-'))}</td>
            </tr>`
        ).join('') || '<tr><td colspan="5" class="text-center text-gray-500">No playbook rules configured</td></tr>';
    } catch {}

    loadPlaybookExecutions();
}

async function loadPlaybookExecutions() {
    const offset = pbPage * PB_LIMIT;
    try {
        const data = await fetchJSON(`/api/playbooks/executions?limit=${PB_LIMIT}&offset=${offset}`);
        const tbody = document.getElementById('pb-exec-body');
        tbody.innerHTML = (data.executions || []).map(e =>
            `<tr>
                <td>${formatTime(e.timestamp)}</td>
                <td>${escapeHtml(e.rule_name || '')}</td>
                <td><a href="#" class="ip-link" data-ip="${escapeHtml(e.source_ip || '')}">${escapeHtml(e.source_ip || '-')}</a></td>
                <td class="text-xs">${escapeHtml((e.actions_taken || []).join(', '))}</td>
                <td class="text-xs">${truncate(e.detail || '', 60)}</td>
            </tr>`
        ).join('') || '<tr><td colspan="5" class="text-center text-gray-500">No executions yet</td></tr>';

        const total = data.total || 0;
        const pageInfo = document.getElementById('pb-page-info');
        pageInfo.textContent = total > 0 ? `${offset + 1}-${Math.min(offset + PB_LIMIT, total)} of ${total}` : '0 of 0';
        document.getElementById('pb-prev').disabled = pbPage === 0;
        document.getElementById('pb-next').disabled = (offset + PB_LIMIT) >= total;
    } catch {}
}

document.getElementById('pb-prev')?.addEventListener('click', () => { if (pbPage > 0) { pbPage--; loadPlaybookExecutions(); } });
document.getElementById('pb-next')?.addEventListener('click', () => { pbPage++; loadPlaybookExecutions(); });


// ── Geo Policy ────────────────────────────────────────────────────────

let geoCountries = [];

async function loadGeoPolicyView() {
    try {
        const status = await fetchJSON('/api/geo-policy/status');
        document.getElementById('geo-stat-enabled').textContent = status.enabled ? 'Yes' : 'No';
        document.getElementById('geo-stat-mode').textContent = status.mode || '-';
        document.getElementById('geo-stat-action').textContent = status.action || '-';
        document.getElementById('geo-stat-countries').textContent = formatNumber(status.countries?.length || 0);
        document.getElementById('geo-stat-enforcements').textContent = formatNumber(status.recent_enforcements || 0);

        // Populate config form
        document.getElementById('geo-cfg-enabled').value = String(!!status.enabled);
        document.getElementById('geo-cfg-mode').value = status.mode || 'blacklist';
        document.getElementById('geo-cfg-action').value = status.action || 'block';
        document.getElementById('geo-cfg-duration').value = status.block_duration || '';
        document.getElementById('geo-cfg-exempt').value = (status.exempt_ips || []).join('\n');

        geoCountries = [...(status.countries || [])];
        renderGeoCountryTags();
    } catch {}
}

function renderGeoCountryTags() {
    const container = document.getElementById('geo-cfg-countries-tags');
    container.innerHTML = geoCountries.map(c =>
        `<span class="badge badge-info flex items-center gap-1">${escapeHtml(c)}
            <button class="geo-remove-country" data-code="${escapeHtml(c)}" style="cursor:pointer;background:none;border:none;color:inherit;font-size:14px;line-height:1">&times;</button>
        </span>`
    ).join('') || '<span class="text-gray-500 text-sm">No countries configured</span>';

    container.querySelectorAll('.geo-remove-country').forEach(btn => {
        btn.addEventListener('click', () => {
            geoCountries = geoCountries.filter(c => c !== btn.dataset.code);
            renderGeoCountryTags();
        });
    });
}

document.getElementById('geo-add-country-btn')?.addEventListener('click', () => {
    const input = document.getElementById('geo-cfg-country-input');
    const code = input.value.trim().toUpperCase();
    if (code && !geoCountries.includes(code)) {
        geoCountries.push(code);
        renderGeoCountryTags();
    }
    input.value = '';
});

document.getElementById('geo-save-btn')?.addEventListener('click', async () => {
    const body = {
        enabled: document.getElementById('geo-cfg-enabled').value === 'true',
        mode: document.getElementById('geo-cfg-mode').value,
        action: document.getElementById('geo-cfg-action').value,
        block_duration: parseInt(document.getElementById('geo-cfg-duration').value) || 0,
        countries: geoCountries,
        exempt_ips: document.getElementById('geo-cfg-exempt').value.split('\n').map(s => s.trim()).filter(Boolean)
    };
    try {
        await patchJSON('/api/geo-policy/config', body);
        loadGeoPolicyView();
    } catch {}
});

document.getElementById('geo-check-btn')?.addEventListener('click', async () => {
    const ip = document.getElementById('geo-check-ip').value.trim();
    if (!ip) return;
    const resultEl = document.getElementById('geo-check-result');
    resultEl.textContent = 'Checking...';
    try {
        const data = await fetchJSON(`/api/geo-policy/check/${encodeURIComponent(ip)}`);
        resultEl.innerHTML = `<div class="card p-3 mt-2">
            <div><strong>IP:</strong> ${escapeHtml(data.ip || ip)}</div>
            <div><strong>Country:</strong> ${escapeHtml(data.country_code || 'Unknown')} ${countryFlag(data.country_code)}</div>
            <div><strong>Allowed:</strong> ${data.allowed ? '<span class="text-green-400">Yes</span>' : '<span class="text-red-400">No</span>'}</div>
            <div><strong>Reason:</strong> ${escapeHtml(data.reason || '-')}</div>
        </div>`;
    } catch {
        resultEl.textContent = 'Failed to check IP.';
    }
});


// ── UA Class Badge ────────────────────────────────────────────
function uaClassBadge(cls) {
    if (!cls) return '';
    const colors = {
        browser: 'badge-accepted',
        bot: 'badge-disconnected',
        crawler: 'badge-disconnected',
        attack_tool: 'badge-brute',
        library: 'badge-invalid',
        unknown: '',
    };
    const badgeCls = colors[cls] || '';
    return `<span class="badge ${badgeCls}">${cls}</span>`;
}

// ── System Health ─────────────────────────────────────────────
let currentSystab = 'health';

document.querySelectorAll('[data-systab]').forEach(btn => {
    btn.addEventListener('click', () => {
        currentSystab = btn.dataset.systab;
        document.querySelectorAll('[data-systab]').forEach(b => b.classList.toggle('active', b.dataset.systab === currentSystab));
        document.getElementById('systab-health').classList.toggle('hidden', currentSystab !== 'health');
        document.getElementById('systab-dedup').classList.toggle('hidden', currentSystab !== 'dedup');
        if (currentSystab === 'health') loadSystemHealth();
        else if (currentSystab === 'dedup') loadDedupStats();
    });
});

async function loadSystemView() {
    if (currentSystab === 'health') await loadSystemHealth();
    else await loadDedupStats();
}

async function loadSystemHealth() {
    try {
        const data = await fetchJSON('/api/health-monitor/status');
        document.getElementById('sys-uptime').textContent = data.uptime || '-';
        document.getElementById('sys-db-size').textContent = data.db_size || '-';
        document.getElementById('sys-enrich-queue').textContent = data.enrichment_queue ?? '-';
        document.getElementById('sys-watchers').textContent = data.watchers_active ?? '-';

        // Deadman alerts
        const deadmanAlerts = data.deadman_alerts || [];
        document.getElementById('sys-deadman-count').textContent = deadmanAlerts.length;
        const tbody = document.getElementById('deadman-table-body');
        tbody.innerHTML = deadmanAlerts.map(a => `
            <tr>
                <td class="font-mono text-xs">${escapeHtml(a.file_path || '-')}</td>
                <td>${a.last_event_ago || '-'}</td>
                <td>${a.status === 'alert' ? '<span class="badge badge-brute">ALERT</span>' : '<span class="badge badge-accepted">OK</span>'}</td>
            </tr>
        `).join('') || '<tr><td colspan="3" class="text-gray-500 text-center">No deadman alerts</td></tr>';
    } catch (e) {
        console.error('Failed to load system health:', e);
    }

    // Event rates chart
    try {
        const rates = await fetchJSON('/api/health-monitor/event-rates?last=60');
        const container = document.getElementById('system-rate-chart');
        if (rates.points && rates.points.length) {
            const chart = echarts.init(container);
            chart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'axis' },
                xAxis: { type: 'category', data: rates.points.map(p => p.time), axisLabel: { color: '#9ca3af' } },
                yAxis: { type: 'value', axisLabel: { color: '#9ca3af' } },
                series: [{ data: rates.points.map(p => p.count), type: 'line', smooth: true, areaStyle: { opacity: 0.15 }, lineStyle: { color: '#3b82f6' }, itemStyle: { color: '#3b82f6' } }]
            });
        } else {
            container.innerHTML = '<div class="text-gray-500 text-center" style="padding-top:80px">No event rate data</div>';
        }
    } catch (e) {
        document.getElementById('system-rate-chart').innerHTML = '<div class="text-gray-500 text-center" style="padding-top:80px">Event rate data unavailable</div>';
    }

    // DB growth chart
    try {
        const growth = await fetchJSON('/api/health-monitor/db-growth?last=60');
        const container = document.getElementById('system-db-chart');
        if (growth.points && growth.points.length) {
            const chart = echarts.init(container);
            chart.setOption({
                backgroundColor: 'transparent',
                tooltip: { trigger: 'axis' },
                xAxis: { type: 'category', data: growth.points.map(p => p.time), axisLabel: { color: '#9ca3af' } },
                yAxis: { type: 'value', axisLabel: { color: '#9ca3af' } },
                series: [{ data: growth.points.map(p => p.size), type: 'line', smooth: true, areaStyle: { opacity: 0.15 }, lineStyle: { color: '#10b981' }, itemStyle: { color: '#10b981' } }]
            });
        } else {
            container.innerHTML = '<div class="text-gray-500 text-center" style="padding-top:80px">No DB growth data</div>';
        }
    } catch (e) {
        document.getElementById('system-db-chart').innerHTML = '<div class="text-gray-500 text-center" style="padding-top:80px">DB growth data unavailable</div>';
    }
}

async function loadDedupStats() {
    try {
        const data = await fetchJSON('/api/dedup/stats');
        document.getElementById('dedup-enabled').textContent = data.enabled ? 'Yes' : 'No';
        document.getElementById('dedup-ssh-buckets').textContent = data.ssh_buckets ?? '-';
        document.getElementById('dedup-http-buckets').textContent = data.http_buckets ?? '-';
        document.getElementById('dedup-ssh-pending').textContent = data.ssh_pending ?? '-';
        document.getElementById('dedup-http-pending').textContent = data.http_pending ?? '-';

        const configEl = document.getElementById('dedup-config-display');
        if (data.config) {
            configEl.innerHTML = `
                <div class="grid grid-cols-2 gap-4">
                    <div><span class="text-gray-500">SSH Window:</span> ${data.config.ssh_window ?? '-'}s</div>
                    <div><span class="text-gray-500">HTTP Window:</span> ${data.config.http_window ?? '-'}s</div>
                </div>
            `;
        } else {
            configEl.textContent = 'No dedup configuration available';
        }
    } catch (e) {
        console.error('Failed to load dedup stats:', e);
        document.getElementById('dedup-config-display').textContent = 'Failed to load dedup stats';
    }
}

// Init
async function init() {
    initCharts();
    await loadSummary();
    await loadDashboardData();
    await loadRecentEvents();
    liveSocket.connect();

    // Periodic refresh
    setInterval(async () => {
        await loadSummary();
        if (currentSection === 'dashboard') {
            await loadDashboardData();
        }
    }, 30000);
}

// Boot: check auth first, then init
(async () => {
    const ok = await checkAuth();
    if (ok) init();
})();
