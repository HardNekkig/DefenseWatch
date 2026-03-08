const charts = {};

// Vibrant color palette for dark backgrounds - inspired by modern financial dashboards
const SUBTLE_COLORS = [
    '#10b981', // emerald green
    '#3b82f6', // bright blue
    '#f59e0b', // amber/orange
    '#ec4899', // pink
    '#14b8a6', // teal
    '#8b5cf6', // purple
    '#ef4444', // red
    '#06b6d4', // cyan
    '#f97316', // orange
    '#a855f7', // violet
    '#22c55e', // green
    '#6366f1', // indigo
    '#eab308', // yellow
    '#84cc16', // lime
    '#0ea5e9', // sky blue
];

const LABEL_COLOR = 'rgba(156, 163, 175, 0.8)';
const GRID_COLOR = 'rgba(255, 255, 255, 0.06)';
const SPLIT_LINE = { lineStyle: { color: GRID_COLOR } };
const AXIS_LABEL = { color: LABEL_COLOR, fontSize: 11 };

function getOrCreate(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return null;
    if (charts[containerId]) {
        return charts[containerId];
    }
    const chart = echarts.init(el, 'dark');
    chart.getZr().dom.style.background = 'transparent';
    charts[containerId] = chart;

    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(el);

    return chart;
}

function createLineChart(containerId, label, color) {
    const chart = getOrCreate(containerId);
    if (!chart) return null;

    chart.setOption({
        backgroundColor: 'transparent',
        grid: { left: 45, right: 16, top: 20, bottom: 30 },
        tooltip: {
            trigger: 'axis',
            backgroundColor: 'rgba(17, 24, 39, 0.95)',
            borderColor: 'rgba(255,255,255,0.08)',
            textStyle: { color: '#d1d5db', fontSize: 12 },
        },
        xAxis: {
            type: 'category',
            data: [],
            axisLabel: AXIS_LABEL,
            axisLine: { show: false },
            axisTick: { show: false },
            splitLine: { show: false },
        },
        yAxis: {
            type: 'value',
            axisLabel: AXIS_LABEL,
            splitLine: SPLIT_LINE,
        },
        series: [{
            name: label,
            type: 'line',
            smooth: true,
            symbol: 'none',
            lineStyle: { color, width: 2 },
            areaStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                    { offset: 0, color: color + '40' },
                    { offset: 1, color: color + '05' },
                ]),
            },
            itemStyle: { color },
            data: [],
        }],
    });

    return chart;
}

function createBarChart(containerId, horizontal = false) {
    const chart = getOrCreate(containerId);
    if (!chart) return null;

    const catAxis = {
        type: 'category',
        data: [],
        axisLabel: { ...AXIS_LABEL, width: horizontal ? 100 : undefined, overflow: 'truncate' },
        axisLine: { show: false },
        axisTick: { show: false },
    };
    const valAxis = {
        type: 'value',
        axisLabel: AXIS_LABEL,
        splitLine: SPLIT_LINE,
    };

    chart.setOption({
        backgroundColor: 'transparent',
        grid: { left: horizontal ? 110 : 45, right: 16, top: 12, bottom: 30 },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            backgroundColor: 'rgba(17, 24, 39, 0.95)',
            borderColor: 'rgba(255,255,255,0.08)',
            textStyle: { color: '#d1d5db', fontSize: 12 },
        },
        xAxis: horizontal ? valAxis : catAxis,
        yAxis: horizontal ? { ...catAxis, inverse: true } : valAxis,
        series: [{
            name: 'Count',
            type: 'bar',
            barMaxWidth: 28,
            itemStyle: {
                borderRadius: horizontal ? [0, 3, 3, 0] : [3, 3, 0, 0],
                color: (params) => SUBTLE_COLORS[params.dataIndex % SUBTLE_COLORS.length],
            },
            data: [],
        }],
    });

    return chart;
}

function createDoughnutChart(containerId) {
    const chart = getOrCreate(containerId);
    if (!chart) return null;

    chart.setOption({
        backgroundColor: 'transparent',
        tooltip: {
            trigger: 'item',
            backgroundColor: 'rgba(17, 24, 39, 0.95)',
            borderColor: 'rgba(255,255,255,0.08)',
            textStyle: { color: '#d1d5db', fontSize: 12 },
            formatter: '{b}: {c} ({d}%)',
        },
        legend: {
            type: 'scroll',
            orient: 'horizontal',
            bottom: 0,
            left: 'center',
            textStyle: { color: '#d1d5db', fontSize: 11 },
            icon: 'circle',
            itemWidth: 8,
            itemHeight: 8,
            itemGap: 12,
            pageIconColor: '#3b82f6',
            pageIconInactiveColor: 'rgba(156, 163, 175, 0.4)',
            pageTextStyle: { color: '#d1d5db', fontSize: 11 },
        },
        color: SUBTLE_COLORS,
        series: [{
            type: 'pie',
            radius: ['50%', '75%'],
            center: ['50%', '42%'],
            avoidLabelOverlap: true,
            label: {
                show: true,
                position: 'inside',
                formatter: '{d}%',
                fontSize: 12,
                fontWeight: 'bold',
                color: '#ffffff',
            },
            labelLine: {
                show: false,
            },
            emphasis: {
                label: {
                    show: true,
                    fontSize: 14,
                    fontWeight: 'bold',
                },
                itemStyle: {
                    shadowBlur: 15,
                    shadowOffsetX: 0,
                    shadowColor: 'rgba(0, 0, 0, 0.5)',
                },
            },
            itemStyle: {
                borderColor: 'rgba(17, 24, 39, 1)',
                borderWidth: 3,
            },
            data: [],
        }],
    });

    return chart;
}

function hourLabel(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
}

export function initCharts() {
    createLineChart('chart-ssh-timeline', 'SSH Attempts', '#c27c7c');
    createLineChart('chart-http-timeline', 'HTTP Attacks', '#c9a66b');
    createBarChart('chart-countries', true);
    createDoughnutChart('chart-attack-types');
    createBarChart('chart-usernames', true);
    createBarChart('chart-endpoints', true);
    createBarChart('chart-asns', true);
}

export function updateSSHTimeline(data) {
    const chart = charts['chart-ssh-timeline'];
    if (!chart || !data.timeseries) return;
    chart.setOption({
        xAxis: { data: data.timeseries.map(d => hourLabel(d.hour)) },
        series: [{ data: data.timeseries.map(d => d.count) }],
    });
}

export function updateHTTPTimeline(data) {
    const chart = charts['chart-http-timeline'];
    if (!chart || !data.timeseries) return;
    chart.setOption({
        xAxis: { data: data.timeseries.map(d => hourLabel(d.hour)) },
        series: [{ data: data.timeseries.map(d => d.count) }],
    });
}

export function updateCountries(data) {
    const chart = charts['chart-countries'];
    if (!chart || !data.countries) return;
    const top = data.countries.slice(0, 12);
    chart.setOption({
        yAxis: { data: top.map(d => d.name || d.code) },
        series: [{ data: top.map(d => d.count) }],
    });
}

export function updateAttackTypes(data) {
    const chart = charts['chart-attack-types'];
    if (!chart || !data.attack_types) return;
    chart.setOption({
        series: [{
            data: data.attack_types.map(d => ({ name: d.type, value: d.count })),
        }],
    });
}

export function updateUsernames(data) {
    const chart = charts['chart-usernames'];
    if (!chart || !data.top_usernames) return;
    const top = data.top_usernames.slice(0, 12);
    chart.setOption({
        yAxis: { data: top.map(d => d.username) },
        series: [{ data: top.map(d => d.count) }],
    });
}

export function updateEndpoints(data) {
    const chart = charts['chart-endpoints'];
    if (!chart || !data.top_paths) return;
    const top = data.top_paths.slice(0, 12);
    chart.setOption({
        yAxis: { data: top.map(d => d.path.length > 30 ? d.path.substring(0, 30) + '...' : d.path) },
        series: [{ data: top.map(d => d.count) }],
    });
}

export function updateASNs(data) {
    const chart = charts['chart-asns'];
    if (!chart || !data.top_ips) return;
    const orgMap = {};
    for (const ip of data.top_ips) {
        const org = ip.org || 'Unknown';
        orgMap[org] = (orgMap[org] || 0) + ip.count;
    }
    const sorted = Object.entries(orgMap).sort((a, b) => b[1] - a[1]).slice(0, 10);
    chart.setOption({
        yAxis: { data: sorted.map(d => d[0].length > 25 ? d[0].substring(0, 25) + '...' : d[0]) },
        series: [{ data: sorted.map(d => d[1]) }],
    });
}
