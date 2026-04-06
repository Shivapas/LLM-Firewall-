import React, { useState, useEffect, useCallback } from 'react';

const API = process.env.REACT_APP_API_URL || '';

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
        ...(variant === 'danger' ? { background: '#e74c3c', color: '#fff' } : {}),
        ...(variant === 'secondary' ? { background: '#e0e0e0', color: '#333' } : {}),
        ...(variant === 'success' ? { background: '#2e7d32', color: '#fff' } : {}),
    }),
    formGroup: { marginBottom: 16 },
    label: { display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13, color: '#333' },
    input: {
        width: '100%', padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd',
        fontSize: 14, boxSizing: 'border-box',
    },
    select: {
        width: '100%', padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd', fontSize: 14,
    },
    sectionTitle: { fontSize: 18, fontWeight: 600, color: '#1a1a2e', marginBottom: 12, marginTop: 24 },
};

const deliveryColor = { sent: '#2e7d32', failed: '#d32f2f', pending: '#f9a825', cooldown: '#9e9e9e' };

export default function AlertManagementPage() {
    const [rules, setRules] = useState([]);
    const [events, setEvents] = useState([]);
    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState({
        name: '', description: '', condition_type: 'block_rate_spike',
        delivery_channel: 'webhook', delivery_target: '', cooldown_seconds: 300,
    });

    const fetchRules = useCallback(async () => {
        try {
            const res = await fetch(`${API}/admin/alerts/rules`);
            setRules(await res.json());
        } catch (e) { console.error(e); }
    }, []);

    const fetchEvents = useCallback(async () => {
        try {
            const res = await fetch(`${API}/admin/alerts/events?limit=20`);
            setEvents(await res.json());
        } catch (e) { console.error(e); }
    }, []);

    useEffect(() => { fetchRules(); fetchEvents(); }, [fetchRules, fetchEvents]);

    const createRule = async () => {
        await fetch(`${API}/admin/alerts/rules`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(form),
        });
        setShowCreate(false);
        fetchRules();
    };

    const deleteRule = async (id) => {
        await fetch(`${API}/admin/alerts/rules/${id}`, { method: 'DELETE' });
        fetchRules();
    };

    const evaluateAll = async () => {
        try {
            const res = await fetch(`${API}/admin/alerts/evaluate`, { method: 'POST' });
            const data = await res.json();
            alert(`Evaluated: ${data.fired_count} alert(s) fired`);
            fetchEvents();
        } catch (e) { console.error(e); }
    };

    return (
        <div style={styles.page}>
            <div style={styles.header}>
                <h1 style={styles.title}>Alert Management</h1>
                <div>
                    <button style={styles.btn('success')} onClick={evaluateAll}>Evaluate Now</button>
                    <button style={styles.btn('primary')} onClick={() => setShowCreate(!showCreate)}>
                        {showCreate ? 'Cancel' : '+ New Rule'}
                    </button>
                </div>
            </div>

            {/* Create form */}
            {showCreate && (
                <div style={styles.card}>
                    <h3 style={{ marginBottom: 16 }}>Create Alert Rule</h3>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Name</label>
                        <input style={styles.input} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Condition Type</label>
                        <select style={styles.select} value={form.condition_type} onChange={e => setForm({ ...form, condition_type: e.target.value })}>
                            <option value="block_rate_spike">Block Rate Spike</option>
                            <option value="budget_exhaustion">Budget Exhaustion</option>
                            <option value="new_critical_mcp_tool">New Critical MCP Tool</option>
                            <option value="kill_switch_activation">Kill-Switch Activation</option>
                            <option value="anomaly_score_breach">Anomaly Score Breach</option>
                        </select>
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Delivery Channel</label>
                        <select style={styles.select} value={form.delivery_channel} onChange={e => setForm({ ...form, delivery_channel: e.target.value })}>
                            <option value="webhook">Webhook</option>
                            <option value="email">Email</option>
                        </select>
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Delivery Target (URL or email)</label>
                        <input style={styles.input} value={form.delivery_target} onChange={e => setForm({ ...form, delivery_target: e.target.value })} />
                    </div>
                    <div style={styles.formGroup}>
                        <label style={styles.label}>Cooldown (seconds)</label>
                        <input style={styles.input} type="number" value={form.cooldown_seconds} onChange={e => setForm({ ...form, cooldown_seconds: Number(e.target.value) })} />
                    </div>
                    <button style={styles.btn('primary')} onClick={createRule}>Create Rule</button>
                </div>
            )}

            {/* Rules table */}
            <div style={styles.card}>
                <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 12 }}>Alert Rules ({rules.length})</h2>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Name</th>
                        <th style={styles.th}>Condition</th>
                        <th style={styles.th}>Channel</th>
                        <th style={styles.th}>Target</th>
                        <th style={styles.th}>Active</th>
                        <th style={styles.th}>Actions</th>
                    </tr></thead>
                    <tbody>
                        {rules.map((r) => (
                            <tr key={r.id}>
                                <td style={styles.td}>{r.name}</td>
                                <td style={styles.td}>{r.condition_type}</td>
                                <td style={styles.td}>{r.delivery_channel}</td>
                                <td style={styles.td} title={r.delivery_target}>{r.delivery_target?.substring(0, 40)}</td>
                                <td style={styles.td}><span style={styles.badge(r.is_active ? '#2e7d32' : '#9e9e9e')}>{r.is_active ? 'Active' : 'Disabled'}</span></td>
                                <td style={styles.td}><button style={styles.btn('danger')} onClick={() => deleteRule(r.id)}>Delete</button></td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Recent events */}
            <h2 style={styles.sectionTitle}>Recent Alert Events</h2>
            <div style={styles.card}>
                <table style={styles.table}>
                    <thead><tr>
                        <th style={styles.th}>Rule</th>
                        <th style={styles.th}>Condition</th>
                        <th style={styles.th}>Message</th>
                        <th style={styles.th}>Delivery</th>
                        <th style={styles.th}>Time</th>
                    </tr></thead>
                    <tbody>
                        {events.map((e) => (
                            <tr key={e.id}>
                                <td style={styles.td}>{e.alert_rule_name}</td>
                                <td style={styles.td}>{e.condition_type}</td>
                                <td style={styles.td}>{e.message?.substring(0, 60)}</td>
                                <td style={styles.td}><span style={styles.badge(deliveryColor[e.delivery_status] || '#666')}>{e.delivery_status}</span></td>
                                <td style={styles.td}>{e.created_at ? new Date(e.created_at).toLocaleString() : ''}</td>
                            </tr>
                        ))}
                        {events.length === 0 && <tr><td style={styles.td} colSpan={5}>No alert events yet</td></tr>}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
