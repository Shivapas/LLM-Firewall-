import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    container: { maxWidth: 1100, margin: '0 auto' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 },
    title: { fontSize: 24, fontWeight: 700 },
    card: {
        background: '#fff', borderRadius: 8, padding: 20, marginBottom: 16,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    },
    row: { display: 'flex', gap: 16, marginBottom: 16 },
    select: { padding: '8px 12px', borderRadius: 4, border: '1px solid #ddd', minWidth: 200 },
    btn: (color = '#4fc3f7') => ({
        padding: '8px 16px', background: color, color: '#fff', border: 'none',
        borderRadius: 4, cursor: 'pointer', fontWeight: 600, fontSize: 14,
    }),
    btnSmall: (color = '#4fc3f7') => ({
        padding: '4px 10px', background: color, color: '#fff', border: 'none',
        borderRadius: 4, cursor: 'pointer', fontSize: 12,
    }),
    table: { width: '100%', borderCollapse: 'collapse' },
    th: { textAlign: 'left', padding: '10px 12px', background: '#f0f0f0', fontWeight: 600, fontSize: 13 },
    td: { padding: '10px 12px', borderBottom: '1px solid #eee', fontSize: 13 },
    badge: (color) => ({
        display: 'inline-block', padding: '2px 8px', borderRadius: 12,
        background: color, color: '#fff', fontSize: 11, fontWeight: 600,
    }),
    diffSection: { marginTop: 12, padding: 12, background: '#f9f9f9', borderRadius: 6, fontSize: 13 },
    added: { color: '#27ae60', fontWeight: 600 },
    removed: { color: '#e74c3c', fontWeight: 600 },
    changed: { color: '#f39c12', fontWeight: 600 },
    textarea: {
        width: '100%', minHeight: 120, padding: 10, borderRadius: 4,
        border: '1px solid #ddd', fontFamily: 'monospace', fontSize: 13, boxSizing: 'border-box',
    },
    input: { padding: '8px 12px', borderRadius: 4, border: '1px solid #ddd', width: 80 },
    simSummary: { display: 'flex', gap: 24, marginTop: 12 },
    simStat: { textAlign: 'center' },
    simLabel: { fontSize: 11, color: '#888' },
    simValue: { fontSize: 20, fontWeight: 700 },
    tabs: { display: 'flex', gap: 0, marginBottom: 24 },
    tab: (active) => ({
        padding: '10px 20px', cursor: 'pointer', fontWeight: active ? 700 : 400,
        background: active ? '#fff' : '#e8e8e8', border: '1px solid #ddd',
        borderBottom: active ? 'none' : '1px solid #ddd', borderRadius: '6px 6px 0 0',
    }),
    alert: (type) => ({
        padding: 12, borderRadius: 6, marginBottom: 16, fontSize: 13,
        background: type === 'success' ? '#e8f5e9' : type === 'error' ? '#fce4ec' : '#fff3e0',
        color: type === 'success' ? '#2e7d32' : type === 'error' ? '#c62828' : '#e65100',
    }),
};

export default function PolicyVersionPage() {
    const { apiFetch } = useAuth();
    const [policies, setPolicies] = useState([]);
    const [selectedPolicyId, setSelectedPolicyId] = useState('');
    const [versions, setVersions] = useState([]);
    const [activeTab, setActiveTab] = useState('versions');
    const [alert, setAlert] = useState(null);

    // Diff state
    const [diffVersionA, setDiffVersionA] = useState('');
    const [diffVersionB, setDiffVersionB] = useState('');
    const [diffResult, setDiffResult] = useState(null);

    // Simulation state
    const [simRules, setSimRules] = useState('{\n  "action_overrides": {\n    "critical": "block",\n    "high": "block",\n    "medium": "block",\n    "low": "allow"\n  }\n}');
    const [simLimit, setSimLimit] = useState(100);
    const [simResult, setSimResult] = useState(null);
    const [simLoading, setSimLoading] = useState(false);

    const showAlert = (type, message) => {
        setAlert({ type, message });
        setTimeout(() => setAlert(null), 5000);
    };

    const loadPolicies = useCallback(async () => {
        try {
            const res = await apiFetch('/admin/policies');
            if (res.ok) {
                const data = await res.json();
                setPolicies(data);
                if (data.length > 0 && !selectedPolicyId) {
                    setSelectedPolicyId(data[0].id);
                }
            }
        } catch { /* ignore */ }
    }, [apiFetch, selectedPolicyId]);

    const loadVersions = useCallback(async () => {
        if (!selectedPolicyId) return;
        try {
            const res = await apiFetch(`/admin/policies/${selectedPolicyId}/versions`);
            if (res.ok) {
                const data = await res.json();
                setVersions(data);
            }
        } catch { /* ignore */ }
    }, [apiFetch, selectedPolicyId]);

    useEffect(() => { loadPolicies(); }, [loadPolicies]);
    useEffect(() => { loadVersions(); }, [selectedPolicyId, loadVersions]);

    const handleDiff = async () => {
        if (!diffVersionA || !diffVersionB) return;
        try {
            const res = await apiFetch(`/admin/policies/${selectedPolicyId}/diff`, {
                method: 'POST',
                body: JSON.stringify({
                    version_a: parseInt(diffVersionA),
                    version_b: parseInt(diffVersionB),
                }),
            });
            if (res.ok) {
                setDiffResult(await res.json());
            } else {
                showAlert('error', 'Failed to compute diff');
            }
        } catch { showAlert('error', 'Failed to compute diff'); }
    };

    const handleRollback = async (targetVersion) => {
        if (!window.confirm(`Rollback policy to version ${targetVersion}? This will update the active policy immediately.`)) return;
        try {
            const res = await apiFetch(`/admin/policies/${selectedPolicyId}/rollback`, {
                method: 'POST',
                body: JSON.stringify({ target_version: targetVersion, rolled_back_by: 'admin' }),
            });
            if (res.ok) {
                const data = await res.json();
                showAlert('success', `Rolled back to version ${targetVersion}. New version: ${data.new_version}`);
                loadVersions();
                loadPolicies();
            } else {
                showAlert('error', 'Rollback failed');
            }
        } catch { showAlert('error', 'Rollback failed'); }
    };

    const handleSimulate = async () => {
        setSimLoading(true);
        try {
            let rules;
            try { rules = JSON.parse(simRules); } catch {
                showAlert('error', 'Invalid JSON in simulation rules');
                setSimLoading(false);
                return;
            }
            const res = await apiFetch(`/admin/policies/${selectedPolicyId}/simulate`, {
                method: 'POST',
                body: JSON.stringify({ rules, limit: simLimit }),
            });
            if (res.ok) {
                setSimResult(await res.json());
            } else {
                showAlert('error', 'Simulation failed');
            }
        } catch { showAlert('error', 'Simulation failed'); }
        setSimLoading(false);
    };

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <h1 style={styles.title}>Policy Version Management</h1>
            </div>

            {alert && <div style={styles.alert(alert.type)}>{alert.message}</div>}

            <div style={styles.card}>
                <div style={styles.row}>
                    <div>
                        <label style={{ fontWeight: 600, marginRight: 8 }}>Policy:</label>
                        <select
                            style={styles.select}
                            value={selectedPolicyId}
                            onChange={(e) => setSelectedPolicyId(e.target.value)}
                        >
                            {policies.map(p => (
                                <option key={p.id} value={p.id}>{p.name} (v{p.version})</option>
                            ))}
                        </select>
                    </div>
                </div>
            </div>

            <div style={styles.tabs}>
                <div style={styles.tab(activeTab === 'versions')} onClick={() => setActiveTab('versions')}>
                    Version History
                </div>
                <div style={styles.tab(activeTab === 'diff')} onClick={() => setActiveTab('diff')}>
                    Compare Versions
                </div>
                <div style={styles.tab(activeTab === 'simulate')} onClick={() => setActiveTab('simulate')}>
                    Simulate Policy
                </div>
            </div>

            {/* Version History Tab */}
            {activeTab === 'versions' && (
                <div style={styles.card}>
                    <h3 style={{ marginBottom: 12 }}>Version History</h3>
                    {versions.length === 0 ? (
                        <p style={{ color: '#888' }}>No versions found. Update a policy to create version snapshots.</p>
                    ) : (
                        <table style={styles.table}>
                            <thead>
                                <tr>
                                    <th style={styles.th}>Version</th>
                                    <th style={styles.th}>Description</th>
                                    <th style={styles.th}>Created By</th>
                                    <th style={styles.th}>Created At</th>
                                    <th style={styles.th}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {versions.map(v => (
                                    <tr key={v.id}>
                                        <td style={styles.td}>
                                            <span style={styles.badge('#4fc3f7')}>v{v.version}</span>
                                        </td>
                                        <td style={styles.td}>{v.description || '-'}</td>
                                        <td style={styles.td}>{v.created_by}</td>
                                        <td style={styles.td}>
                                            {v.created_at ? new Date(v.created_at).toLocaleString() : '-'}
                                        </td>
                                        <td style={styles.td}>
                                            <button
                                                style={styles.btnSmall('#e67e22')}
                                                onClick={() => handleRollback(v.version)}
                                                title="Rollback to this version"
                                            >
                                                Rollback
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            )}

            {/* Diff Tab */}
            {activeTab === 'diff' && (
                <div style={styles.card}>
                    <h3 style={{ marginBottom: 12 }}>Compare Policy Versions</h3>
                    <div style={styles.row}>
                        <div>
                            <label style={{ fontWeight: 600, marginRight: 8 }}>Version A:</label>
                            <select style={styles.select} value={diffVersionA} onChange={e => setDiffVersionA(e.target.value)}>
                                <option value="">Select...</option>
                                {versions.map(v => <option key={v.id} value={v.version}>v{v.version}</option>)}
                            </select>
                        </div>
                        <div>
                            <label style={{ fontWeight: 600, marginRight: 8 }}>Version B:</label>
                            <select style={styles.select} value={diffVersionB} onChange={e => setDiffVersionB(e.target.value)}>
                                <option value="">Select...</option>
                                {versions.map(v => <option key={v.id} value={v.version}>v{v.version}</option>)}
                            </select>
                        </div>
                        <button style={styles.btn('#3498db')} onClick={handleDiff}>
                            Compare
                        </button>
                    </div>

                    {diffResult && (
                        <div style={styles.diffSection}>
                            {!diffResult.has_changes ? (
                                <p>No differences between v{diffResult.version_a} and v{diffResult.version_b}.</p>
                            ) : (
                                <>
                                    {Object.keys(diffResult.added).length > 0 && (
                                        <div style={{ marginBottom: 8 }}>
                                            <span style={styles.added}>+ Added:</span>
                                            <pre style={{ margin: '4px 0', fontSize: 12 }}>
                                                {JSON.stringify(diffResult.added, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                    {Object.keys(diffResult.removed).length > 0 && (
                                        <div style={{ marginBottom: 8 }}>
                                            <span style={styles.removed}>- Removed:</span>
                                            <pre style={{ margin: '4px 0', fontSize: 12 }}>
                                                {JSON.stringify(diffResult.removed, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                    {Object.keys(diffResult.changed).length > 0 && (
                                        <div style={{ marginBottom: 8 }}>
                                            <span style={styles.changed}>~ Changed:</span>
                                            <pre style={{ margin: '4px 0', fontSize: 12 }}>
                                                {JSON.stringify(diffResult.changed, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Simulation Tab */}
            {activeTab === 'simulate' && (
                <div style={styles.card}>
                    <h3 style={{ marginBottom: 12 }}>Policy Simulation (Dry Run)</h3>
                    <p style={{ fontSize: 13, color: '#666', marginBottom: 12 }}>
                        Preview how a new policy configuration would affect recent requests without activating it.
                    </p>
                    <div style={{ marginBottom: 12 }}>
                        <label style={{ fontWeight: 600, display: 'block', marginBottom: 4 }}>
                            Simulation Rules (JSON):
                        </label>
                        <textarea
                            style={styles.textarea}
                            value={simRules}
                            onChange={e => setSimRules(e.target.value)}
                        />
                    </div>
                    <div style={styles.row}>
                        <div>
                            <label style={{ fontWeight: 600, marginRight: 8 }}>Max Requests:</label>
                            <input
                                type="number"
                                style={styles.input}
                                value={simLimit}
                                onChange={e => setSimLimit(parseInt(e.target.value) || 100)}
                                min={1}
                                max={1000}
                            />
                        </div>
                        <button
                            style={styles.btn('#27ae60')}
                            onClick={handleSimulate}
                            disabled={simLoading}
                        >
                            {simLoading ? 'Running...' : 'Run Simulation'}
                        </button>
                    </div>

                    {simResult && (
                        <div style={{ marginTop: 16 }}>
                            <h4>Simulation Results</h4>
                            <div style={styles.simSummary}>
                                <div style={styles.simStat}>
                                    <div style={styles.simValue}>{simResult.total_requests}</div>
                                    <div style={styles.simLabel}>Total Requests</div>
                                </div>
                                <div style={styles.simStat}>
                                    <div style={{ ...styles.simValue, color: '#e74c3c' }}>
                                        {simResult.summary.would_change}
                                    </div>
                                    <div style={styles.simLabel}>Would Change</div>
                                </div>
                                <div style={styles.simStat}>
                                    <div style={{ ...styles.simValue, color: '#e74c3c' }}>
                                        {simResult.summary.would_block || 0}
                                    </div>
                                    <div style={styles.simLabel}>Would Block</div>
                                </div>
                                <div style={styles.simStat}>
                                    <div style={{ ...styles.simValue, color: '#27ae60' }}>
                                        {simResult.summary.would_allow || 0}
                                    </div>
                                    <div style={styles.simLabel}>Would Allow</div>
                                </div>
                                <div style={styles.simStat}>
                                    <div style={{ ...styles.simValue, color: '#2980b9' }}>
                                        {simResult.summary.no_change}
                                    </div>
                                    <div style={styles.simLabel}>No Change</div>
                                </div>
                            </div>

                            {simResult.impact && simResult.impact.length > 0 && (
                                <table style={{ ...styles.table, marginTop: 16 }}>
                                    <thead>
                                        <tr>
                                            <th style={styles.th}>Timestamp</th>
                                            <th style={styles.th}>Model</th>
                                            <th style={styles.th}>Tenant</th>
                                            <th style={styles.th}>Current Action</th>
                                            <th style={styles.th}>Simulated Action</th>
                                            <th style={styles.th}>Risk</th>
                                            <th style={styles.th}>Changed</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {simResult.impact.slice(0, 50).map((entry, i) => (
                                            <tr key={i}>
                                                <td style={styles.td}>
                                                    {new Date(entry.timestamp * 1000).toLocaleString()}
                                                </td>
                                                <td style={styles.td}>{entry.model}</td>
                                                <td style={styles.td}>{entry.tenant_id}</td>
                                                <td style={styles.td}>
                                                    <span style={styles.badge(
                                                        entry.original_action.includes('block') ? '#e74c3c' : '#27ae60'
                                                    )}>
                                                        {entry.original_action}
                                                    </span>
                                                </td>
                                                <td style={styles.td}>
                                                    <span style={styles.badge(
                                                        entry.simulated_action === 'block' ? '#e74c3c' : '#27ae60'
                                                    )}>
                                                        {entry.simulated_action}
                                                    </span>
                                                </td>
                                                <td style={styles.td}>{entry.risk_level}</td>
                                                <td style={styles.td}>
                                                    {entry.changed ? (
                                                        <span style={styles.badge('#e74c3c')}>Changed</span>
                                                    ) : (
                                                        <span style={{ color: '#888' }}>-</span>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
