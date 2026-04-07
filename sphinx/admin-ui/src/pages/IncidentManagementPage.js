import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    page: { maxWidth: 1100, margin: '0 auto' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 },
    title: { fontSize: 24, fontWeight: 700, color: '#1a1a2e' },
    card: {
        background: '#fff', borderRadius: 8, padding: 24, marginBottom: 16,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    },
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
    btn: (variant) => ({
        padding: '8px 16px', border: 'none', borderRadius: 6, cursor: 'pointer',
        fontWeight: 600, fontSize: 13, marginRight: 8,
        ...(variant === 'primary' ? { background: '#1a73e8', color: '#fff' } : {}),
        ...(variant === 'secondary' ? { background: '#e0e0e0', color: '#333' } : {}),
    }),
    formGroup: { marginBottom: 16 },
    label: { display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13, color: '#333' },
    input: {
        width: '100%', padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd',
        fontSize: 14, boxSizing: 'border-box',
    },
    select: {
        padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd', fontSize: 14, marginRight: 8,
    },
    statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 24 },
    statBox: (color) => ({
        background: '#fff', borderRadius: 8, padding: 16, textAlign: 'center',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)', borderLeft: `4px solid ${color}`,
    }),
};

const sevColor = { critical: '#d32f2f', high: '#e65100', medium: '#f9a825', low: '#2e7d32' };
const statusColor = { open: '#d32f2f', investigating: '#e65100', resolved: '#2e7d32', dismissed: '#9e9e9e' };

export default function IncidentManagementPage() {
    const { apiFetch } = useAuth();
    const [incidents, setIncidents] = useState([]);
    const [stats, setStats] = useState(null);
    const [filters, setFilters] = useState({ status: '', severity: '', incident_type: '' });
    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState({ incident_type: 'critical_threat', severity: 'high', title: '', description: '', tenant_id: '' });

    const fetchIncidents = useCallback(async () => {
        const params = new URLSearchParams();
        if (filters.status) params.set('status', filters.status);
        if (filters.severity) params.set('severity', filters.severity);
        if (filters.incident_type) params.set('incident_type', filters.incident_type);
        try {
            const res = await apiFetch(`/admin/incidents?${params}`);
            if (res.ok) setIncidents(await res.json());
        } catch (e) { console.error(e); }
    }, [filters]);

    const fetchStats = useCallback(async () => {
        try {
            const res = await apiFetch('/admin/incidents/stats');
            if (res.ok) setStats(await res.json());
        } catch (e) { console.error(e); }
    }, []);

    useEffect(() => { fetchIncidents(); fetchStats(); }, [fetchIncidents, fetchStats]);

    const createIncident = async () => {
        try {
            const res = await apiFetch('/admin/incidents', {
                method: 'POST',
                body: JSON.stringify(form),
            });
            if (!res.ok) throw new Error('Failed to create incident');
            setShowCreate(false);
            fetchIncidents();
            fetchStats();
        } catch (e) { console.error(e); }
    };

    const updateStatus = async (id, newStatus) => {
        try {
            const res = await apiFetch(`/admin/incidents/${id}`, {
                method: 'PATCH',
                body: JSON.stringify({ status: newStatus }),
            });
            if (!res.ok) throw new Error('Failed to update incident');
            fetchIncidents();
            fetchStats();
        } catch (e) { console.error(e); }
    };

    return (
        <div style={styles.page}>
            <div style={styles.header}>
                <h1 style={styles.title}>Incident Management</h1>
                <button style={styles.btn('primary')} onClick={() => setShowCreate(!showCreate)}>
                    {showCreate ? 'Cancel' : '+ New Incident'}
                </button>
            </div>

            {/* Stats */}
            {stats && (
                <div style={styles.statsGrid}>
                    <div style={styles.statBox('#1a73e8')}><div style={{ fontSize: 24, fontWeight: 700 }}>{stats.total}</div><div style={{ fontSize: 12, color: '#666' }}>Total</div></div>
                    <div style={styles.statBox('#d32f2f')}><div style={{ fontSize: 24, fontWeight: 700 }}>{stats.open}</div><div style={{ fontSize: 12, color: '#666' }}>Open</div></div>
                    <div style={styles.statBox('#e65100')}><div style={{ fontSize: 24, fontWeight: 700 }}>{stats.investigating}</div><div style={{ fontSize: 12, color: '#666' }}>Investigating</div></div>
                    <div style={styles.statBox('#2e7d32')}><div style={{ fontSize: 24, fontWeight: 700 }}>{stats.resolved}</div><div style={{ fontSize: 12, color: '#666' }}>Resolved</div></div>
                </div>
            )}

            {/* Create form */}
            {showCreate && (
                <div style={styles.card}>
                    <h3 style={{ marginBottom: 16 }}>Create Incident</h3>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Type</label>
                        <select style={styles.select} value={form.incident_type} onChange={e => setForm({ ...form, incident_type: e.target.value })}>
                            <option value="critical_threat">Critical Threat</option>
                            <option value="namespace_breach">Namespace Breach</option>
                            <option value="kill_switch_activation">Kill-Switch Activation</option>
                            <option value="tier2_finding">Tier 2 ML Finding</option>
                        </select>
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Severity</label>
                        <select style={styles.select} value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Title</label>
                        <input style={styles.input} value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Description</label>
                        <input style={styles.input} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
                    </div>
                    <button style={styles.btn('primary')} onClick={createIncident}>Create</button>
                </div>
            )}

            {/* Filters */}
            <div style={{ marginBottom: 16 }}>
                <select style={styles.select} value={filters.status} onChange={e => setFilters({ ...filters, status: e.target.value })}>
                    <option value="">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="dismissed">Dismissed</option>
                </select>
                <select style={styles.select} value={filters.severity} onChange={e => setFilters({ ...filters, severity: e.target.value })}>
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>

            {/* Incidents table */}
            <div style={styles.card}>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Type</th>
                        <th style={styles.th}>Severity</th>
                        <th style={styles.th}>Title</th>
                        <th style={styles.th}>Status</th>
                        <th style={styles.th}>Tenant</th>
                        <th style={styles.th}>Created</th>
                        <th style={styles.th}>Actions</th>
                    </tr></thead>
                    <tbody>
                        {incidents.map((inc) => (
                            <tr key={inc.id}>
                                <td style={styles.td}>{inc.incident_type}</td>
                                <td style={styles.td}><span style={styles.badge(sevColor[inc.severity] || '#666')}>{inc.severity}</span></td>
                                <td style={styles.td}>{inc.title}</td>
                                <td style={styles.td}><span style={styles.badge(statusColor[inc.status] || '#666')}>{inc.status}</span></td>
                                <td style={styles.td}>{inc.tenant_id}</td>
                                <td style={styles.td}>{inc.created_at ? new Date(inc.created_at).toLocaleString() : ''}</td>
                                <td style={styles.td}>
                                    {inc.status === 'open' && <button style={styles.btn('secondary')} onClick={() => updateStatus(inc.id, 'investigating')}>Investigate</button>}
                                    {inc.status === 'investigating' && <button style={styles.btn('primary')} onClick={() => updateStatus(inc.id, 'resolved')}>Resolve</button>}
                                    {inc.status !== 'dismissed' && inc.status !== 'resolved' && <button style={styles.btn('secondary')} onClick={() => updateStatus(inc.id, 'dismissed')}>Dismiss</button>}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
