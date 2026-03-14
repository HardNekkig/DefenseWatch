import { fetchJSON, countryFlag } from './utils.js';

let map = null;
let arcLayer = null;
let hostMarker = null;
let refreshTimer = null;
let _arcData = []; // cached arc data for filtering

// Active filters
const _mapFilters = { ssh: true, http: true, mixed: true, active: true };

export async function initMap() {
    if (map) return;

    map = L.map('attack-map', {
        center: [30, 0],
        zoom: 3,
        minZoom: 3,
        maxZoom: 12,
        zoomControl: true,
        attributionControl: false,
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19,
    }).addTo(map);

    arcLayer = L.layerGroup().addTo(map);

    // Load host position
    try {
        const host = await fetchJSON('/api/map/host');
        if (host.latitude && host.longitude) {
            hostMarker = L.circleMarker([host.latitude, host.longitude], {
                radius: 8,
                fillColor: '#22c55e',
                color: '#16a34a',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.8,
            }).addTo(map);
            hostMarker.bindPopup(`<b>${host.name || 'Server'}</b><br>Host Location`);
        }
    } catch (e) {
        console.error('Failed to load host location:', e);
    }

    // Time range selector
    document.getElementById('map-range')?.addEventListener('change', () => loadArcs());

    // Filter buttons
    document.querySelectorAll('#map-filters .map-filter').forEach(btn => {
        btn.addEventListener('click', () => {
            const key = btn.dataset.filter;
            _mapFilters[key] = !_mapFilters[key];
            btn.classList.toggle('active', _mapFilters[key]);
            renderArcs();
        });
    });

    // Auto-refresh every 30s to keep active states current
    startAutoRefresh();
}

function getSelectedHours() {
    return parseInt(document.getElementById('map-range')?.value || '6', 10);
}

function startAutoRefresh() {
    stopAutoRefresh();
    refreshTimer = setInterval(() => loadArcs(), 30000);
}

function stopAutoRefresh() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}

function arcMatchesFilters(arc) {
    // "active" filter: when ON, show active arcs; when OFF, hide active arcs
    // The type filters (ssh/http/mixed) control which types are shown
    // If only "active" is on, show only active arcs of any type
    // If "active" is off and a type filter is off, hide that combination

    const typeMatch = _mapFilters[arc.type] !== false;

    // If all type filters are on and active is on: show everything
    // If active filter is off: only show non-active arcs that match type
    // If active filter is on but type is off: still show active arcs of that type? No — filter is per-type.

    // Simple approach: arc must match its type filter. "active" is an independent toggle.
    if (_mapFilters.active && arc.active) return typeMatch || _mapFilters.active;
    if (!_mapFilters.active && arc.active) return false;
    return typeMatch;
}

export async function loadArcs() {
    if (!map || !arcLayer) return;

    const hours = getSelectedHours();

    try {
        const data = await fetchJSON(`/api/map/arcs?hours=${hours}`);
        _arcData = data.arcs || [];
        renderArcs();
    } catch (e) {
        console.error('Failed to load arcs:', e);
    }
}

function renderArcs() {
    if (!map || !arcLayer) return;
    arcLayer.clearLayers();

    const filtered = _arcData.filter(arc => {
        const typeKey = arc.type || 'mixed';
        const typeOn = _mapFilters[typeKey] !== false;
        const isActive = !!arc.active;

        // If "active" filter is off, hide all active arcs
        if (isActive && !_mapFilters.active) return false;
        // If only "active" filter is on (all types off), show active arcs regardless of type
        if (isActive && _mapFilters.active) return typeOn || (!_mapFilters.ssh && !_mapFilters.http && !_mapFilters.mixed);
        // Non-active arcs: must match type filter
        return typeOn;
    });

    const activeCount = filtered.filter(a => a.active).length;
    const countEl = document.getElementById('map-arc-count');
    if (countEl) {
        countEl.textContent = `${filtered.length} sources${activeCount ? ` · ${activeCount} active` : ''}`;
    }

    for (const arc of filtered) {
        const color = arc.type === 'ssh' ? '#ef4444' :
            arc.type === 'http' ? '#f97316' : '#eab308';
        const opacity = arc.active ? 0.9 : Math.min(0.3 + Math.log10(arc.count + 1) * 0.2, 0.7);

        // Draw curved line
        const latlngs = computeArc(
            [arc.src_lat, arc.src_lon],
            [arc.dst_lat, arc.dst_lon]
        );

        const arcClasses = ['arc-path'];
        if (arc.active) arcClasses.push('arc-active');

        const polyline = L.polyline(latlngs, {
            color: arc.active ? '#22c55e' : color,
            weight: arc.active
                ? Math.min(2 + Math.log10(arc.count + 1), 5)
                : Math.min(1 + Math.log10(arc.count + 1), 4),
            opacity: opacity,
            smoothFactor: 1,
            className: arcClasses.join(' '),
        }).addTo(arcLayer);

        const lastSeenStr = arc.last_seen
            ? new Date(arc.last_seen * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
            : 'unknown';

        polyline.bindPopup(`
            <div class="text-sm">
                <b>${countryFlag(arc.country)} ${arc.ip}</b>
                ${arc.active ? ' <span style="color:#22c55e;font-weight:600;">● ACTIVE</span>' : ''}
                <br>
                ${arc.org || 'Unknown'}<br>
                SSH: ${arc.ssh_count} | HTTP: ${arc.http_count}<br>
                Total: ${arc.count} events<br>
                Last seen: ${lastSeenStr}
            </div>
        `);

        // Source marker
        const markerClasses = arc.active ? 'marker-active' : '';
        const marker = L.circleMarker([arc.src_lat, arc.src_lon], {
            radius: arc.active
                ? Math.min(5 + Math.log10(arc.count + 1) * 2, 10)
                : Math.min(3 + Math.log10(arc.count + 1) * 2, 8),
            fillColor: arc.active ? '#22c55e' : color,
            color: arc.active ? '#16a34a' : color,
            weight: arc.active ? 2 : 1,
            opacity: arc.active ? 1 : 0.7,
            fillOpacity: arc.active ? 0.8 : 0.5,
            className: markerClasses,
        }).addTo(arcLayer);

        marker.bindPopup(polyline.getPopup());
    }
}

function computeArc(start, end, numPoints = 30) {
    const points = [];
    for (let i = 0; i <= numPoints; i++) {
        const t = i / numPoints;
        const lat = start[0] + (end[0] - start[0]) * t;
        const lon = start[1] + (end[1] - start[1]) * t;
        // Add curvature
        const altitude = Math.sin(Math.PI * t) * 15;
        points.push([lat + altitude, lon]);
    }
    return points;
}

export function invalidateMap() {
    if (map) {
        setTimeout(() => map.invalidateSize(), 100);
    }
}

let refreshDebounce = null;
export function refreshMapOnEvent() {
    if (!map || !arcLayer) return;
    if (refreshDebounce) return;
    refreshDebounce = setTimeout(() => {
        refreshDebounce = null;
        loadArcs();
    }, 3000);
}
