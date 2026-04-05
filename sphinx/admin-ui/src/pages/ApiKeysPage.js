import React, { useEffect, useState } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    heading: { fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1a2e' },
    toolbar: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
    createBtn: {
        padding: '10px 20px', background: '#4fc3f7', color: '#fff',
        border: 'none', borderRadius: 4, fontSize: 14, fontWeight: 600, cursor: 'pointer',
    },
    table: {
        width: '100%', borderCollapse: 'collapse', background: '#fff',
        borderRadius: 8, overflow: 'hidden', boxShadow: '0 1px 4px rgba(0,0,0,0.08)',
    },
    th: { textAlign: 'left', padding: '12px 16px', background: '#f8f9fa', fontSize: 13, fontWeight: 600, color: '#555' },
    td: { padding: '12px 16px', borderTop: '1px solid #eee', fontSize: 14 },
    badge: (active) => ({
        display: 'inline-block', padding: '2px 10px', borderRadius: 12, fontSize: 12, fontWeight: 600,
        background: active ? '#e8f5e9' : '#ffebee', color: active ? '#2e7d32' : '#c62828',
    }),
    deleteBtn: {
        padding: '6px 12px', background: '#e74c3c', color: '#fff',
        border: 'none', borderRadius: 4, fontSize: 12, cursor: 'pointer',
    },
    modal: {
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(0,0,0,0.5)', display: 'flex', justifyContent: 'center', alignItems: 'center',
    },
    modalContent: { background: '#fff', borderRadius: 8, padding: 32, width: 420 },
    label: { display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6, color: '#333', marginTop: 12 },
    input: {
        width: '100%', padding: '8px 12px', border: '1px solid #ddd',
        borderRadius: 4, fontSize: 14,
    },
    modalActions: { display: 'flex', gap: 12, marginTop: 20 },
    cancelBtn: {
        padding: '10px 20px', background: '#eee', border: 'none',
        borderRadius: 4, fontSize: 14, cursor: 'pointer',
    },
    newKeyBanner: {
        background: '#e8f5e9', padding: 16, borderRadius: 8, marginBottom: 16,
        border: '1px solid #c8e6c9',
    },
    code: { fontFamily: 'monospace', fontSize: 14, wordBreak: 'break-all', color: '#1b5e20' },
};

export default function ApiKeysPage() {
    const { apiFetch } = useAuth();
    const [keys, setKeys] = useState([]);
    const [showCreate, setShowCreate] = useState(false);
    const [newKey, setNewKey] = useState(null);
    const [form, setForm] = useState({ tenant_id: '', project_id: '', tpm_limit: 100000 });

    const loadKeys = async () => {
        try {
            const res = await apiFetch('/admin/keys');
            setKeys(await res.json());
        } catch { /* ignore */ }
    };

    useEffect(() => { loadKeys(); }, []);  // eslint-disable-line react-hooks/exhaustive-deps

    const handleCreate = async (e) => {
        e.preventDefault();
        try {
            const res = await apiFetch('/admin/keys', {
                method: 'POST',
                body: JSON.stringify(form),
            });
            const data = await res.json();
            setNewKey(data.raw_key);
            setShowCreate(false);
            setForm({ tenant_id: '', project_id: '', tpm_limit: 100000 });
            loadKeys();
        } catch { /* ignore */ }
    };

    const handleDelete = async (keyId) => {
        if (!window.confirm('Revoke this API key?')) return;
        try {
            await apiFetch(`/admin/keys/${keyId}`, { method: 'DELETE' });
            loadKeys();
        } catch { /* ignore */ }
    };

    return (
        <div>
            <h1 style={styles.heading}>API Keys</h1>

            {newKey && (
                <div style={styles.newKeyBanner}>
                    <strong>New API Key Created</strong> (copy it now, it won't be shown again):<br />
                    <span style={styles.code}>{newKey}</span>
                    <button
                        style={{ ...styles.cancelBtn, marginLeft: 12, marginTop: 8 }}
                        onClick={() => setNewKey(null)}
                    >
                        Dismiss
                    </button>
                </div>
            )}

            <div style={styles.toolbar}>
                <span>{keys.length} key(s)</span>
                <button style={styles.createBtn} onClick={() => setShowCreate(true)}>Create Key</button>
            </div>

            <table style={styles.table}>
                <thead>
                    <tr>
                        <th style={styles.th}>Prefix</th>
                        <th style={styles.th}>Tenant</th>
                        <th style={styles.th}>Project</th>
                        <th style={styles.th}>TPM Limit</th>
                        <th style={styles.th}>Status</th>
                        <th style={styles.th}>Created</th>
                        <th style={styles.th}>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {keys.map(k => (
                        <tr key={k.id}>
                            <td style={styles.td}><code>{k.key_prefix}...</code></td>
                            <td style={styles.td}>{k.tenant_id}</td>
                            <td style={styles.td}>{k.project_id}</td>
                            <td style={styles.td}>{k.tpm_limit.toLocaleString()}</td>
                            <td style={styles.td}>
                                <span style={styles.badge(k.is_active)}>
                                    {k.is_active ? 'Active' : 'Revoked'}
                                </span>
                            </td>
                            <td style={styles.td}>{new Date(k.created_at).toLocaleDateString()}</td>
                            <td style={styles.td}>
                                {k.is_active && (
                                    <button style={styles.deleteBtn} onClick={() => handleDelete(k.id)}>
                                        Revoke
                                    </button>
                                )}
                            </td>
                        </tr>
                    ))}
                    {keys.length === 0 && (
                        <tr><td style={styles.td} colSpan={7}>No API keys yet</td></tr>
                    )}
                </tbody>
            </table>

            {showCreate && (
                <div style={styles.modal} onClick={() => setShowCreate(false)}>
                    <form style={styles.modalContent} onClick={e => e.stopPropagation()} onSubmit={handleCreate}>
                        <h2 style={{ fontSize: 18, marginBottom: 8 }}>Create API Key</h2>
                        <label style={styles.label}>Tenant ID</label>
                        <input
                            style={styles.input} required
                            value={form.tenant_id}
                            onChange={e => setForm({ ...form, tenant_id: e.target.value })}
                        />
                        <label style={styles.label}>Project ID</label>
                        <input
                            style={styles.input} required
                            value={form.project_id}
                            onChange={e => setForm({ ...form, project_id: e.target.value })}
                        />
                        <label style={styles.label}>TPM Limit</label>
                        <input
                            style={styles.input} type="number" min={1}
                            value={form.tpm_limit}
                            onChange={e => setForm({ ...form, tpm_limit: parseInt(e.target.value) || 100000 })}
                        />
                        <div style={styles.modalActions}>
                            <button type="button" style={styles.cancelBtn} onClick={() => setShowCreate(false)}>Cancel</button>
                            <button type="submit" style={styles.createBtn}>Create</button>
                        </div>
                    </form>
                </div>
            )}
        </div>
    );
}
