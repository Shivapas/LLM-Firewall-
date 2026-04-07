import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    page: { maxWidth: 1000, margin: '0 auto' },
    h1: { fontSize: 24, fontWeight: 700, marginBottom: 8 },
    subtitle: { color: '#666', marginBottom: 24 },
    card: {
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)', marginBottom: 24,
    },
    table: { width: '100%', borderCollapse: 'collapse' },
    th: {
        textAlign: 'left', padding: '10px 12px', borderBottom: '2px solid #e0e0e0',
        fontSize: 13, color: '#666', textTransform: 'uppercase',
    },
    td: { padding: '10px 12px', borderBottom: '1px solid #f0f0f0', fontSize: 14 },
    badge: (color) => ({
        display: 'inline-block', padding: '2px 10px', borderRadius: 12,
        fontSize: 12, fontWeight: 600, background: color, color: '#fff',
    }),
    form: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 },
    formFull: { gridColumn: '1 / -1' },
    label: { display: 'block', marginBottom: 4, fontSize: 13, fontWeight: 600, color: '#444' },
    input: {
        width: '100%', padding: '8px 12px', border: '1px solid #ddd',
        borderRadius: 4, fontSize: 14, boxSizing: 'border-box',
    },
    select: {
        width: '100%', padding: '8px 12px', border: '1px solid #ddd',
        borderRadius: 4, fontSize: 14, boxSizing: 'border-box',
    },
    btn: (color) => ({
        padding: '8px 20px', background: color, color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', fontWeight: 600,
    }),
    btnSmall: (color) => ({
        padding: '4px 12px', background: color, color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 12,
    }),
    actions: { display: 'flex', gap: 8 },
    error: { color: '#e74c3c', marginBottom: 12 },
    success: { color: '#27ae60', marginBottom: 12 },
};

const ACTION_COLORS = { deny: '#e74c3c', allow: '#27ae60', monitor: '#f39c12' };
const PROVIDER_COLORS = { chromadb: '#4fc3f7', pinecone: '#81c784', milvus: '#ba68c8' };

export default function VectorDBPage() {
    const { apiFetch } = useAuth();
    const [collections, setCollections] = useState([]);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [showForm, setShowForm] = useState(false);
    const [form, setForm] = useState({
        collection_name: '', provider: 'chromadb', default_action: 'deny',
        allowed_operations: [], sensitive_fields: '',
        namespace_field: 'tenant_id', max_results: 10, tenant_id: '*',
    });

    const fetchCollections = useCallback(async () => {
        try {
            const res = await apiFetch(`/admin/vector-collections`);
            if (res.ok) setCollections(await res.json());
        } catch (e) { setError('Failed to fetch collections'); }
    }, []);

    useEffect(() => { fetchCollections(); }, [fetchCollections]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(''); setSuccess('');
        try {
            const payload = {
                ...form,
                sensitive_fields: form.sensitive_fields
                    ? form.sensitive_fields.split(',').map(s => s.trim()).filter(Boolean) : [],
                max_results: parseInt(form.max_results, 10) || 10,
            };
            const res = await apiFetch(`/admin/vector-collections`, {
                method: 'POST',
                body: JSON.stringify(payload),
            });
            if (!res.ok) {
                const data = await res.json();
                setError(data.detail || 'Failed to create collection policy');
                return;
            }
            setSuccess('Collection policy created');
            setShowForm(false);
            setForm({
                collection_name: '', provider: 'chromadb', default_action: 'deny',
                allowed_operations: [], sensitive_fields: '',
                namespace_field: 'tenant_id', max_results: 10, tenant_id: '*',
            });
            fetchCollections();
        } catch (e) { setError('Failed to create collection policy'); }
    };

    const handleDelete = async (id) => {
        if (!window.confirm('Delete this collection policy?')) return;
        try {
            await apiFetch(`/admin/vector-collections/${id}`, { method: 'DELETE' });
            fetchCollections();
        } catch (e) { setError('Failed to delete'); }
    };

    const handleToggle = async (col) => {
        try {
            await apiFetch(`/admin/vector-collections/${col.id}`, {
                method: 'PATCH',
                body: JSON.stringify({ is_active: !col.is_active }),
            });
            fetchCollections();
        } catch (e) { setError('Failed to update'); }
    };

    const toggleOp = (op) => {
        setForm(f => ({
            ...f,
            allowed_operations: f.allowed_operations.includes(op)
                ? f.allowed_operations.filter(o => o !== op)
                : [...f.allowed_operations, op],
        }));
    };

    return (
        <div style={styles.page}>
            <h1 style={styles.h1}>Vector DB Collections</h1>
            <p style={styles.subtitle}>
                Register and manage vector collection policies for namespace isolation and access control.
            </p>

            {error && <div style={styles.error}>{error}</div>}
            {success && <div style={styles.success}>{success}</div>}

            <div style={{ marginBottom: 16 }}>
                <button style={styles.btn('#3498db')} onClick={() => setShowForm(!showForm)}>
                    {showForm ? 'Cancel' : '+ Register Collection'}
                </button>
            </div>

            {showForm && (
                <div style={styles.card}>
                    <h3 style={{ marginBottom: 16 }}>Register New Collection</h3>
                    <form onSubmit={handleSubmit} style={styles.form}>
                        <div>
                            <label style={styles.label}>Collection Name</label>
                            <input style={styles.input} value={form.collection_name}
                                onChange={e => setForm({ ...form, collection_name: e.target.value })}
                                required placeholder="my-embeddings" />
                        </div>
                        <div>
                            <label style={styles.label}>Provider</label>
                            <select style={styles.select} value={form.provider}
                                onChange={e => setForm({ ...form, provider: e.target.value })}>
                                <option value="chromadb">ChromaDB</option>
                                <option value="pinecone">Pinecone</option>
                                <option value="milvus">Milvus</option>
                            </select>
                        </div>
                        <div>
                            <label style={styles.label}>Default Action</label>
                            <select style={styles.select} value={form.default_action}
                                onChange={e => setForm({ ...form, default_action: e.target.value })}>
                                <option value="deny">Deny</option>
                                <option value="allow">Allow</option>
                                <option value="monitor">Monitor</option>
                            </select>
                        </div>
                        <div>
                            <label style={styles.label}>Namespace Field</label>
                            <input style={styles.input} value={form.namespace_field}
                                onChange={e => setForm({ ...form, namespace_field: e.target.value })}
                                placeholder="tenant_id" />
                        </div>
                        <div>
                            <label style={styles.label}>Allowed Operations</label>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
                                {['query', 'insert', 'update', 'delete'].map(op => (
                                    <label key={op} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13 }}>
                                        <input type="checkbox"
                                            checked={form.allowed_operations.includes(op)}
                                            onChange={() => toggleOp(op)} />
                                        {op}
                                    </label>
                                ))}
                            </div>
                        </div>
                        <div>
                            <label style={styles.label}>Max Results (1-100)</label>
                            <input style={styles.input} type="number" min="1" max="100"
                                value={form.max_results}
                                onChange={e => setForm({ ...form, max_results: e.target.value })} />
                        </div>
                        <div style={styles.formFull}>
                            <label style={styles.label}>Sensitive Fields (comma-separated)</label>
                            <input style={styles.input} value={form.sensitive_fields}
                                onChange={e => setForm({ ...form, sensitive_fields: e.target.value })}
                                placeholder="ssn, email, phone" />
                        </div>
                        <div>
                            <label style={styles.label}>Tenant ID (* = global)</label>
                            <input style={styles.input} value={form.tenant_id}
                                onChange={e => setForm({ ...form, tenant_id: e.target.value })}
                                placeholder="*" />
                        </div>
                        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                            <button type="submit" style={styles.btn('#27ae60')}>Create Policy</button>
                        </div>
                    </form>
                </div>
            )}

            <div style={styles.card}>
                <table style={styles.table}>
                    <thead>
                        <tr>
                            <th style={styles.th}>Collection</th>
                            <th style={styles.th}>Provider</th>
                            <th style={styles.th}>Default Action</th>
                            <th style={styles.th}>Operations</th>
                            <th style={styles.th}>Namespace</th>
                            <th style={styles.th}>Max Results</th>
                            <th style={styles.th}>Status</th>
                            <th style={styles.th}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {collections.length === 0 && (
                            <tr><td colSpan={8} style={{ ...styles.td, textAlign: 'center', color: '#999' }}>
                                No collections registered yet.
                            </td></tr>
                        )}
                        {collections.map(col => (
                            <tr key={col.id}>
                                <td style={styles.td}><strong>{col.collection_name}</strong></td>
                                <td style={styles.td}>
                                    <span style={styles.badge(PROVIDER_COLORS[col.provider] || '#999')}>
                                        {col.provider}
                                    </span>
                                </td>
                                <td style={styles.td}>
                                    <span style={styles.badge(ACTION_COLORS[col.default_action] || '#999')}>
                                        {col.default_action}
                                    </span>
                                </td>
                                <td style={styles.td}>
                                    {(col.allowed_operations || []).join(', ') || 'none'}
                                </td>
                                <td style={styles.td}><code>{col.namespace_field}</code></td>
                                <td style={styles.td}>{col.max_results}</td>
                                <td style={styles.td}>
                                    <span style={styles.badge(col.is_active ? '#27ae60' : '#999')}>
                                        {col.is_active ? 'Active' : 'Inactive'}
                                    </span>
                                </td>
                                <td style={styles.td}>
                                    <div style={styles.actions}>
                                        <button style={styles.btnSmall(col.is_active ? '#f39c12' : '#27ae60')}
                                            onClick={() => handleToggle(col)}>
                                            {col.is_active ? 'Disable' : 'Enable'}
                                        </button>
                                        <button style={styles.btnSmall('#e74c3c')}
                                            onClick={() => handleDelete(col.id)}>Delete</button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
