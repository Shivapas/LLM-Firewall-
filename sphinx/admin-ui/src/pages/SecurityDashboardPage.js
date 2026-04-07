import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    page: { maxWidth: 1200, margin: '0 auto' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 },
    title: { fontSize: 24, fontWeight: 700, color: '#1a1a2e' },
    card: {
        background: '#fff', borderRadius: 8, padding: 24, marginBottom: 16,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    },
    grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 },
    statCard: (color) => ({
        background: '#fff', borderRadius: 8, padding: 20, textAlign: 'center',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)', borderTop: `3px solid ${color}`,
    }),
    statValue: { fontSize: 28, fontWeight: 700, color: '#1a1a2e', marginBottom: 4 },
    statLabel: { fontSize: 13, color: '#666', textTransform: 'uppercase', fontWeight: 600 },
    table: { width: '100%', borderCollapse: 'collapse' },
    th: {
        textAlign: 'left', padding: '12px 16px', borderBottom: '2px solid #e0e0e0',
        color: '#666', fontSize: 13, fontWeight: 600, textTransform: 'uppercase',
    },
    td: { padding: '12px 16px', borderBottom: '1px solid #f0f0f0', fontSize: 14 },
    badge: (color) => ({
        display: 'inline-block', padding: '4px 10px', borderRadius: 12,
        fontSize: 12, fontWeight: 600, background: color + '20', color: color,
    }),
    sectionTitle: { fontSize: 18, fontWeight: 600, color: '#1a1a2e', marginBottom: 12 },
    btn: {
        padding: '8px 16px', border: 'none', borderRadius: 6, cursor: 'pointer',
        fontWeight: 600, fontSize: 13, background: '#1a73e8', color: '#fff',
    },
};

const severityColor = {
    critical: '#d32f2f', high: '#e65100', medium: '#f9a825', low: '#2e7d32',
};

export default function SecurityDashboardPage() {
    const { apiFetch } = useAuth();
    const [data, setData] = useState(null);
    const [periodHours, setPeriodHours] = useState(24);
    const [loading, setLoading] = useState(true);

    const fetchData = useCallback(async () => {
        setLoading(true);
        try {
            const res = await apiFetch(`/admin/dashboard/security-ops?period_hours=${periodHours}`);
            if (!res.ok) throw new Error('Failed to load security dashboard');
            setData(await res.json());
        } catch (e) { console.error(e); }
        setLoading(false);
    }, [periodHours]);

    useEffect(() => { fetchData(); }, [fetchData]);

    if (loading || !data) return <div style={styles.page}><p>Loading security dashboard...</p></div>;

    const vol = data.request_volume || {};
    return (
        <div style={styles.page}>
            <div style={styles.header}>
                <h1 style={styles.title}>Security Operations Dashboard</h1>
                <div>
                    <select value={periodHours} onChange={e => setPeriodHours(Number(e.target.value))}
                        style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd', marginRight: 8 }}>
                        <option value={1}>Last 1h</option>
                        <option value={6}>Last 6h</option>
                        <option value={24}>Last 24h</option>
                        <option value={72}>Last 3d</option>
                        <option value={168}>Last 7d</option>
                    </select>
                    <button style={styles.btn} onClick={fetchData}>Refresh</button>
                </div>
            </div>

            {/* Stats Grid */}
            <div style={styles.grid}>
                <div style={styles.statCard('#1a73e8')}>
                    <div style={styles.statValue}>{vol.total_requests || 0}</div>
                    <div style={styles.statLabel}>Total Requests</div>
                </div>
                <div style={styles.statCard('#2e7d32')}>
                    <div style={styles.statValue}>{vol.allowed_requests || 0}</div>
                    <div style={styles.statLabel}>Allowed</div>
                </div>
                <div style={styles.statCard('#d32f2f')}>
                    <div style={styles.statValue}>{vol.blocked_requests || 0}</div>
                    <div style={styles.statLabel}>Blocked</div>
                </div>
                <div style={styles.statCard('#e65100')}>
                    <div style={styles.statValue}>{vol.block_rate || 0}%</div>
                    <div style={styles.statLabel}>Block Rate</div>
                </div>
            </div>

            {/* Top Threats */}
            <div style={styles.card}>
                <h2 style={styles.sectionTitle}>Top Threats</h2>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Category</th>
                        <th style={styles.th}>Severity</th>
                        <th style={styles.th}>Count</th>
                    </tr></thead>
                    <tbody>
                        {(data.top_threats || []).map((t, i) => (
                            <tr key={i}>
                                <td style={styles.td}>{t.category}</td>
                                <td style={styles.td}><span style={styles.badge(severityColor[t.severity] || '#666')}>{t.severity}</span></td>
                                <td style={styles.td}>{t.count}</td>
                            </tr>
                        ))}
                        {(!data.top_threats || data.top_threats.length === 0) && <tr><td style={styles.td} colSpan={3}>No threats detected</td></tr>}
                    </tbody>
                </table>
            </div>

            {/* Top Tenants */}
            <div style={styles.card}>
                <h2 style={styles.sectionTitle}>Top Tenants</h2>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Tenant</th>
                        <th style={styles.th}>Requests</th>
                        <th style={styles.th}>Blocked</th>
                        <th style={styles.th}>Block Rate</th>
                        <th style={styles.th}>Tokens</th>
                    </tr></thead>
                    <tbody>
                        {(data.top_tenants || []).map((t, i) => (
                            <tr key={i}>
                                <td style={styles.td}>{t.tenant_id}</td>
                                <td style={styles.td}>{t.request_count}</td>
                                <td style={styles.td}>{t.block_count}</td>
                                <td style={styles.td}>{t.block_rate}%</td>
                                <td style={styles.td}>{t.total_tokens?.toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Active Kill-Switches */}
            <div style={styles.card}>
                <h2 style={styles.sectionTitle}>Active Kill-Switches ({(data.active_kill_switches || []).length})</h2>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Model</th>
                        <th style={styles.th}>Action</th>
                        <th style={styles.th}>Fallback</th>
                        <th style={styles.th}>Reason</th>
                    </tr></thead>
                    <tbody>
                        {(data.active_kill_switches || []).map((ks, i) => (
                            <tr key={i}>
                                <td style={styles.td}>{ks.model_name}</td>
                                <td style={styles.td}><span style={styles.badge(ks.action === 'block' ? '#d32f2f' : '#1565c0')}>{ks.action}</span></td>
                                <td style={styles.td}>{ks.fallback_model || '—'}</td>
                                <td style={styles.td}>{ks.reason}</td>
                            </tr>
                        ))}
                        {(!data.active_kill_switches || data.active_kill_switches.length === 0) && <tr><td style={styles.td} colSpan={4}>No active kill-switches</td></tr>}
                    </tbody>
                </table>
            </div>

            {/* Recent Incidents */}
            <div style={styles.card}>
                <h2 style={styles.sectionTitle}>Recent Incidents</h2>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Type</th>
                        <th style={styles.th}>Severity</th>
                        <th style={styles.th}>Title</th>
                        <th style={styles.th}>Status</th>
                        <th style={styles.th}>Created</th>
                    </tr></thead>
                    <tbody>
                        {(data.recent_incidents || []).map((inc, i) => (
                            <tr key={i}>
                                <td style={styles.td}>{inc.incident_type}</td>
                                <td style={styles.td}><span style={styles.badge(severityColor[inc.severity] || '#666')}>{inc.severity}</span></td>
                                <td style={styles.td}>{inc.title}</td>
                                <td style={styles.td}>{inc.status}</td>
                                <td style={styles.td}>{inc.created_at ? new Date(inc.created_at).toLocaleString() : ''}</td>
                            </tr>
                        ))}
                        {(!data.recent_incidents || data.recent_incidents.length === 0) && <tr><td style={styles.td} colSpan={5}>No recent incidents</td></tr>}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
