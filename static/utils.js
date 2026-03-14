const COUNTRY_FLAGS = {};

export function formatTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts * 1000);
    return d.toLocaleString('en-GB', {
        month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false,
    });
}

export function formatTimeShort(ts) {
    if (!ts) return '-';
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function countryFlag(code) {
    if (!code) return '';
    return code.toUpperCase().replace(/./g, c =>
        String.fromCodePoint(0x1F1E6 - 65 + c.charCodeAt(0))
    );
}

export function severityBadge(severity) {
    if (!severity) return '';
    const cls = `badge badge-${severity}`;
    return `<span class="${cls}">${severity}</span>`;
}

export function eventTypeBadge(type) {
    if (!type) return '';
    const map = {
        'failed_password': 'failed',
        'invalid_user': 'invalid',
        'accepted_password': 'accepted',
        'accepted_publickey': 'accepted',
        'disconnected': 'disconnected',
        'brute_force': 'brute',
    };
    const cls = `badge badge-${map[type] || 'disconnected'}`;
    return `<span class="${cls}">${type.replace(/_/g, ' ')}</span>`;
}

export function truncate(str, len = 40) {
    if (!str) return '-';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

export function formatNumber(n) {
    if (n === null || n === undefined || n === '-') return '-';
    return new Intl.NumberFormat().format(n);
}

export function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

export function getAuthToken() {
    return localStorage.getItem('dw_token');
}

export function setAuthToken(token) {
    localStorage.setItem('dw_token', token);
}

export function clearAuthToken() {
    localStorage.removeItem('dw_token');
    localStorage.removeItem('dw_user');
}

export function getAuthHeaders() {
    const token = getAuthToken();
    return token ? { 'Authorization': `Bearer ${token}` } : {};
}

export async function fetchJSON(url) {
    const resp = await fetch(url, { headers: getAuthHeaders() });
    if (resp.status === 401) {
        clearAuthToken();
        window.dispatchEvent(new Event('dw-auth-required'));
        throw new Error('Authentication required');
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
}

export async function postJSON(url, body) {
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(body),
    });
    if (resp.status === 401) {
        clearAuthToken();
        window.dispatchEvent(new Event('dw-auth-required'));
        throw new Error('Authentication required');
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
}

export async function patchJSON(url, body) {
    const resp = await fetch(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(body),
    });
    if (resp.status === 401) {
        clearAuthToken();
        window.dispatchEvent(new Event('dw-auth-required'));
        throw new Error('Authentication required');
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
}

export async function deleteJSON(url, body) {
    const opts = { method: 'DELETE', headers: { ...getAuthHeaders() } };
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    const resp = await fetch(url, opts);
    if (resp.status === 401) {
        clearAuthToken();
        window.dispatchEvent(new Event('dw-auth-required'));
        throw new Error('Authentication required');
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
}
