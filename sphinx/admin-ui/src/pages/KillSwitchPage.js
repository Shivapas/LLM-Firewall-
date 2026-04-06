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
    badge: (active) => ({
        display: 'inline-block', padding: '4px 10px', borderRadius: 12,
        fontSize: 12, fontWeight: 600,
        background: active ? '#ffe0e0' : '#e8f5e9',
        color: active ? '#c62828' : '#2e7d32',
    }),
    actionBadge: (action) => ({
        display: 'inline-block', padding: '4px 10px', borderRadius: 12,
        fontSize: 12, fontWeight: 600,
        background: action === 'block' ? '#fff3e0' : '#e3f2fd',
        color: action === 'block' ? '#e65100' : '#1565c0',
    }),
    btn: (variant) => ({
        padding: '8px 16px', border: 'none', borderRadius: 6, cursor: 'pointer',
        fontWeight: 600, fontSize: 13, marginRight: 8,
        ...(variant === 'primary' ? { background: '#1a73e8', color: '#fff' } : {}),
        ...(variant === 'danger' ? { background: '#e74c3c', color: '#fff' } : {}),
        ...(variant === 'secondary' ? { background: '#e0e0e0', color: '#333' } : {}),
    }),
    formGroup: { marginBottom: 16 },
    label: { display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13, color: '#333' },
    input: {
        width: '100%', padding: '10px 12px', border: '1px solid #ddd', borderRadius: 6,
        fontSize: 14, boxSizing: 'border-box',
    },
    select: {
        width: '100%', padding: '10px 12px', border: '1px solid #ddd', borderRadius: 6,
        fontSize: 14, boxSizing: 'border-box', background: '#fff',
    },
    textarea: {
        width: '100%', padding: '10px 12px', border: '1px solid #ddd', borderRadius: 6,
        fontSize: 14, minHeight: 60, boxSizing: 'border-box', resize: 'vertical',
    },
    error: { color: '#e74c3c', marginBottom: 16, padding: 12, background: '#fdecea', borderRadius: 6, fontSize: 14 },
    success: { color: '#2e7d32', marginBottom: 16, padding: 12, background: '#e8f5e9', borderRadius: 6, fontSize: 14 },
    tabs: { display: 'flex', gap: 0, marginBottom: 24, borderBottom: '2px solid #e0e0e0' },
    tab: (active) => ({
        padding: '12px 24px', cursor: 'pointer', fontWeight: 600, fontSize: 14,
        borderBottom: active ? '2px solid #1a73e8' : '2px solid transparent',
        color: active ? '#1a73e8' : '#666', marginBottom: -2,
        background: 'none', border: 'none',
    }),
    auditEvent: (type) => ({
        display: 'inline-block', padding: '3px 8px', borderRadius: 10,
        fontSize: 11, fontWeight: 600,
        background: type === 'activated' ? '#ffe0e0' : '#e8f5e9',
        color: type === 'activated' ? '#c62828' : '#2e7d32',
    }),
    emptyRow: { textAlign: 'center', color: '#999', padding: 32, fontSize: 14 },
};

export default function KillSwitchPage() {
    const [switches, setSwitches] = useState([]);
    const [auditLogs, setAuditLogs] = useState([]);
    const [activeTab, setActiveTab] = useState('switches');
    const [showForm, setShowForm] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [form, setForm] = useState({
        model_name: '',
        action: 'block',
        fallback_model: '',
        activated_by: '',
        reason: '',
        error_message: '',
    });

    const fetchSwitches = useCallback(async () => {
        try {
            const res = await fetch(`${API}/admin/kill-switches`);
            if (res.ok) setSwitches(await res.json());
        } catch (e) { setError('Failed to load kill-switches'); }
    }, []);

    const fetchAuditLogs = useCallback(async () => {
        try {
            const res = await fetch(`${API}/admin/kill-switches/audit`);
            if (res.ok) setAuditLogs(await res.json());
        } catch (e) { setError('Failed to load audit logs'); }
    }, []);

    useEffect(() => { fetchSwitches(); fetchAuditLogs(); }, [fetchSwitches, fetchAuditLogs]);

    const handleActivate = async (e) => {
        e.preventDefault();
        setError(''); setSuccess('');

        if (!form.model_name || !form.activated_by) {
            setError('Model name and activated by are required');
            return;
        }
        if (!form.reason.trim()) {
            setError('Reason is mandatory');
            return;
        }
        if (form.action === 'reroute' && !form.fallback_model) {
            setError('Fallback model is required for reroute action');
            return;
        }

        try {
            const payload = { ...form };
            if (!payload.error_message) delete payload.error_message;
            if (!payload.fallback_model) payload.fallback_model = null;

            const res = await fetch(`${API}/admin/kill-switches`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (res.ok) {
                setSuccess(`Kill-switch activated for ${form.model_name}`);
                setShowForm(false);
                setForm({ model_name: '', action: 'block', fallback_model: '', activated_by: '', reason: '', error_message: '' });
                fetchSwitches();
                fetchAuditLogs();
            } else {
                const data = await res.json();
                setError(data.detail || 'Failed to activate kill-switch');
            }
        } catch (e) { setError('Network error'); }
    };

    const handleDeactivate = async (modelName) => {
        if (!window.confirm(`Deactivate kill-switch for ${modelName}?`)) return;
        setError(''); setSuccess('');

        try {
            const res = await fetch(`${API}/admin/kill-switches/${encodeURIComponent(modelName)}`, {
                method: 'DELETE',
            });
            if (res.ok) {
                setSuccess(`Kill-switch deactivated for ${modelName}`);
                fetchSwitches();
                fetchAuditLogs();
            } else {
                setError('Failed to deactivate kill-switch');
            }
        } catch (e) { setError('Network error'); }
    };

    return (
        <div style={styles.page}>
            <div style={styles.header}>
                <h1 style={styles.title}>Kill-Switch Management</h1>
                <button style={styles.btn('primary')} onClick={() => setShowForm(!showForm)}>
                    {showForm ? 'Cancel' : '+ Activate Kill-Switch'}
                </button>
            </div>

            {error && <div style={styles.error}>{error}</div>}
            {success && <div style={styles.success}>{success}</div>}

            {showForm && (
                <div style={styles.card}>
                    <h3 style={{ marginTop: 0, marginBottom: 16 }}>Activate Kill-Switch</h3>
                    <form onSubmit={handleActivate}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Model Name *</label>
                                <input
                                    style={styles.input}
                                    value={form.model_name}
                                    onChange={(e) => setForm({ ...form, model_name: e.target.value })}
                                    placeholder="e.g., gpt-4, claude-3-opus"
                                />
                            </div>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Action *</label>
                                <select
                                    style={styles.select}
                                    value={form.action}
                                    onChange={(e) => setForm({ ...form, action: e.target.value })}
                                >
                                    <option value="block">Block (503)</option>
                                    <option value="reroute">Reroute to Fallback</option>
                                </select>
                            </div>
                            {form.action === 'reroute' && (
                                <div style={styles.formGroup}>
                                    <label style={styles.label}>Fallback Model *</label>
                                    <input
                                        style={styles.input}
                                        value={form.fallback_model}
                                        onChange={(e) => setForm({ ...form, fallback_model: e.target.value })}
                                        placeholder="e.g., gpt-3.5-turbo"
                                    />
                                </div>
                            )}
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Activated By *</label>
                                <input
                                    style={styles.input}
                                    value={form.activated_by}
                                    onChange={(e) => setForm({ ...form, activated_by: e.target.value })}
                                    placeholder="Admin username"
                                />
                            </div>
                            {form.action === 'block' && (
                                <div style={styles.formGroup}>
                                    <label style={styles.label}>Error Message (optional)</label>
                                    <input
                                        style={styles.input}
                                        value={form.error_message}
                                        onChange={(e) => setForm({ ...form, error_message: e.target.value })}
                                        placeholder="Custom 503 error message"
                                    />
                                </div>
                            )}
                        </div>
                        <div style={styles.formGroup}>
                            <label style={styles.label}>Reason * (mandatory)</label>
                            <textarea
                                style={styles.textarea}
                                value={form.reason}
                                onChange={(e) => setForm({ ...form, reason: e.target.value })}
                                placeholder="Why is this kill-switch being activated?"
                            />
                        </div>
                        <button type="submit" style={styles.btn('danger')}>Activate Kill-Switch</button>
                    </form>
                </div>
            )}

            <div style={styles.tabs}>
                <button style={styles.tab(activeTab === 'switches')} onClick={() => setActiveTab('switches')}>
                    Active Switches ({switches.filter(s => s.is_active).length})
                </button>
                <button style={styles.tab(activeTab === 'all')} onClick={() => setActiveTab('all')}>
                    All Switches ({switches.length})
                </button>
                <button style={styles.tab(activeTab === 'audit')} onClick={() => setActiveTab('audit')}>
                    Audit Log ({auditLogs.length})
                </button>
            </div>

            {(activeTab === 'switches' || activeTab === 'all') && (
                <div style={styles.card}>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Model</th>
                                <th style={styles.th}>Action</th>
                                <th style={styles.th}>Fallback</th>
                                <th style={styles.th}>Activated By</th>
                                <th style={styles.th}>Reason</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Created</th>
                                <th style={styles.th}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(activeTab === 'switches'
                                ? switches.filter(s => s.is_active)
                                : switches
                            ).map((sw) => (
                                <tr key={sw.id}>
                                    <td style={styles.td}><strong>{sw.model_name}</strong></td>
                                    <td style={styles.td}>
                                        <span style={styles.actionBadge(sw.action)}>{sw.action.toUpperCase()}</span>
                                    </td>
                                    <td style={styles.td}>{sw.fallback_model || '-'}</td>
                                    <td style={styles.td}>{sw.activated_by}</td>
                                    <td style={{ ...styles.td, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                        {sw.reason || '-'}
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(sw.is_active)}>
                                            {sw.is_active ? 'ACTIVE' : 'INACTIVE'}
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        {sw.created_at ? new Date(sw.created_at).toLocaleString() : '-'}
                                    </td>
                                    <td style={styles.td}>
                                        {sw.is_active && (
                                            <button
                                                style={styles.btn('danger')}
                                                onClick={() => handleDeactivate(sw.model_name)}
                                            >
                                                Deactivate
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                            {(activeTab === 'switches' ? switches.filter(s => s.is_active) : switches).length === 0 && (
                                <tr><td colSpan={8} style={styles.emptyRow}>No kill-switches found</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}

            {activeTab === 'audit' && (
                <div style={styles.card}>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Timestamp</th>
                                <th style={styles.th}>Model</th>
                                <th style={styles.th}>Event</th>
                                <th style={styles.th}>Action</th>
                                <th style={styles.th}>Fallback</th>
                                <th style={styles.th}>Admin</th>
                                <th style={styles.th}>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            {auditLogs.map((log) => (
                                <tr key={log.id}>
                                    <td style={styles.td}>
                                        {log.created_at ? new Date(log.created_at).toLocaleString() : '-'}
                                    </td>
                                    <td style={styles.td}><strong>{log.model_name}</strong></td>
                                    <td style={styles.td}>
                                        <span style={styles.auditEvent(log.event_type)}>
                                            {log.event_type.toUpperCase()}
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.actionBadge(log.action)}>{log.action.toUpperCase()}</span>
                                    </td>
                                    <td style={styles.td}>{log.fallback_model || '-'}</td>
                                    <td style={styles.td}>{log.activated_by}</td>
                                    <td style={{ ...styles.td, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                        {log.reason || '-'}
                                    </td>
                                </tr>
                            ))}
                            {auditLogs.length === 0 && (
                                <tr><td colSpan={7} style={styles.emptyRow}>No audit records found</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
