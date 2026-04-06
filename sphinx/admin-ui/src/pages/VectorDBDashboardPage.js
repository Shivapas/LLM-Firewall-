import React, { useState, useEffect, useCallback } from 'react';

const API_BASE = process.env.REACT_APP_API_URL || '';

const styles = {
    page: { maxWidth: 1200, margin: '0 auto' },
    h1: { fontSize: 24, fontWeight: 700, marginBottom: 8 },
    subtitle: { color: '#666', marginBottom: 24 },
    grid: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 16, marginBottom: 24 },
    statCard: (color) => ({
        background: '#fff', borderRadius: 8, padding: 20,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)', borderLeft: `4px solid ${color}`,
    }),
    statValue: { fontSize: 28, fontWeight: 700, marginBottom: 4 },
    statLabel: { fontSize: 13, color: '#666', textTransform: 'uppercase' },
    card: {
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)', marginBottom: 24,
    },
    cardTitle: { fontSize: 16, fontWeight: 700, marginBottom: 16 },
    table: { width: '100%', borderCollapse: 'collapse' },
    th: {
        textAlign: 'left', padding: '8px 10px', borderBottom: '2px solid #e0e0e0',
        fontSize: 12, color: '#666', textTransform: 'uppercase',
    },
    td: { padding: '8px 10px', borderBottom: '1px solid #f0f0f0', fontSize: 13 },
    badge: (color) => ({
        display: 'inline-block', padding: '2px 8px', borderRadius: 10,
        fontSize: 11, fontWeight: 600, background: color, color: '#fff',
    }),
    refreshBtn: {
        padding: '6px 16px', background: '#3498db', color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 13, fontWeight: 600,
    },
    tabs: { display: 'flex', gap: 0, marginBottom: 24 },
    tab: (active) => ({
        padding: '10px 20px', cursor: 'pointer', fontWeight: 600, fontSize: 14,
        background: active ? '#fff' : '#e8e8e8', border: '1px solid #ddd',
        borderBottom: active ? 'none' : '1px solid #ddd',
        borderRadius: active ? '8px 8px 0 0' : 0,
    }),
    timelineItem: {
        padding: '8px 12px', borderLeft: '3px solid #e74c3c',
        marginBottom: 8, background: '#fdf2f2', borderRadius: '0 4px 4px 0', fontSize: 13,
    },
};

const PROVIDER_COLORS = { chromadb: '#4fc3f7', pinecone: '#81c784', milvus: '#ba68c8' };
const ACTION_COLORS = { deny: '#e74c3c', allow: '#27ae60', monitor: '#f39c12' };

export default function VectorDBDashboardPage() {
    const [dashboard, setDashboard] = useState(null);
    const [auditEntries, setAuditEntries] = useState([]);
    const [activeTab, setActiveTab] = useState('health');
    const [loading, setLoading] = useState(false);

    const fetchDashboard = useCallback(async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/admin/vectordb-dashboard`);
            if (res.ok) setDashboard(await res.json());
        } catch (e) { console.error('Failed to fetch dashboard', e); }
        setLoading(false);
    }, []);

    const fetchAuditEntries = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/admin/collection-audit?limit=50`);
            if (res.ok) setAuditEntries(await res.json());
        } catch (e) { console.error('Failed to fetch audit entries', e); }
    }, []);

    useEffect(() => { fetchDashboard(); fetchAuditEntries(); }, [fetchDashboard, fetchAuditEntries]);

    const summary = dashboard?.summary || {};
    const collections = dashboard?.collection_health || [];
    const anomalies = dashboard?.anomaly_timeline || [];
    const proxyStats = dashboard?.proxy_stats || {};

    return (
        <div style={styles.page}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h1 style={styles.h1}>Vector DB Dashboard</h1>
                <button style={styles.refreshBtn} onClick={() => { fetchDashboard(); fetchAuditEntries(); }} disabled={loading}>
                    {loading ? 'Loading...' : 'Refresh'}
                </button>
            </div>
            <p style={styles.subtitle}>
                Collection policy health, query volume, blocked queries, and anomaly timeline.
            </p>

            {/* Summary Stats */}
            <div style={styles.grid}>
                <div style={styles.statCard('#3498db')}>
                    <div style={styles.statValue}>{summary.total_queries || 0}</div>
                    <div style={styles.statLabel}>Total Queries</div>
                </div>
                <div style={styles.statCard('#e74c3c')}>
                    <div style={styles.statValue}>{summary.total_blocked || 0}</div>
                    <div style={styles.statLabel}>Blocked Queries</div>
                </div>
                <div style={styles.statCard('#f39c12')}>
                    <div style={styles.statValue}>{summary.total_anomalies || 0}</div>
                    <div style={styles.statLabel}>Anomalies</div>
                </div>
                <div style={styles.statCard('#27ae60')}>
                    <div style={styles.statValue}>{dashboard?.registered_collections || 0}</div>
                    <div style={styles.statLabel}>Collections</div>
                </div>
            </div>

            {/* Proxy Stats */}
            <div style={styles.card}>
                <div style={styles.cardTitle}>Proxy Statistics</div>
                <div style={{ display: 'flex', gap: 32 }}>
                    <div><strong>{proxyStats.total_requests || 0}</strong> <span style={{ color: '#666', fontSize: 13 }}>Total Requests</span></div>
                    <div><strong>{proxyStats.allowed || 0}</strong> <span style={{ color: '#666', fontSize: 13 }}>Allowed</span></div>
                    <div><strong>{proxyStats.blocked || 0}</strong> <span style={{ color: '#666', fontSize: 13 }}>Blocked</span></div>
                    <div><strong>{proxyStats.monitored || 0}</strong> <span style={{ color: '#666', fontSize: 13 }}>Monitored</span></div>
                </div>
            </div>

            {/* Tabs */}
            <div style={styles.tabs}>
                <div style={styles.tab(activeTab === 'health')} onClick={() => setActiveTab('health')}>Collection Health</div>
                <div style={styles.tab(activeTab === 'audit')} onClick={() => setActiveTab('audit')}>Audit Log</div>
                <div style={styles.tab(activeTab === 'anomalies')} onClick={() => setActiveTab('anomalies')}>Anomaly Timeline</div>
            </div>

            {/* Collection Health Tab */}
            {activeTab === 'health' && (
                <div style={styles.card}>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Collection</th>
                                <th style={styles.th}>Provider</th>
                                <th style={styles.th}>Action</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Queries</th>
                                <th style={styles.th}>Blocked</th>
                                <th style={styles.th}>Anomalies</th>
                                <th style={styles.th}>Injection Blocks</th>
                                <th style={styles.th}>Avg Latency</th>
                                <th style={styles.th}>Tenants</th>
                            </tr>
                        </thead>
                        <tbody>
                            {collections.length === 0 && (
                                <tr><td colSpan={10} style={{ ...styles.td, textAlign: 'center', color: '#999' }}>
                                    No collections registered.
                                </td></tr>
                            )}
                            {collections.map((c, i) => (
                                <tr key={i}>
                                    <td style={styles.td}><strong>{c.collection_name}</strong></td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(PROVIDER_COLORS[c.provider] || '#999')}>{c.provider}</span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(ACTION_COLORS[c.default_action] || '#999')}>{c.default_action}</span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(c.is_active ? '#27ae60' : '#999')}>
                                            {c.is_active ? 'Active' : 'Inactive'}
                                        </span>
                                    </td>
                                    <td style={styles.td}>{c.total_queries}</td>
                                    <td style={styles.td}>{c.total_blocked}</td>
                                    <td style={styles.td}>{c.total_anomalies}</td>
                                    <td style={styles.td}>{c.total_injection_blocks}</td>
                                    <td style={styles.td}>{c.avg_latency_ms} ms</td>
                                    <td style={styles.td}>{c.unique_tenants}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Audit Log Tab */}
            {activeTab === 'audit' && (
                <div style={styles.card}>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Time</th>
                                <th style={styles.th}>Collection</th>
                                <th style={styles.th}>Tenant</th>
                                <th style={styles.th}>Operation</th>
                                <th style={styles.th}>Action</th>
                                <th style={styles.th}>Chunks</th>
                                <th style={styles.th}>Blocked</th>
                                <th style={styles.th}>Compliance</th>
                                <th style={styles.th}>Latency</th>
                            </tr>
                        </thead>
                        <tbody>
                            {auditEntries.length === 0 && (
                                <tr><td colSpan={9} style={{ ...styles.td, textAlign: 'center', color: '#999' }}>
                                    No audit entries yet.
                                </td></tr>
                            )}
                            {auditEntries.map((e, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{e.timestamp ? new Date(e.timestamp * 1000).toLocaleTimeString() : '-'}</td>
                                    <td style={styles.td}>{e.collection_name}</td>
                                    <td style={styles.td}>{e.tenant_id}</td>
                                    <td style={styles.td}>{e.operation}</td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(ACTION_COLORS[e.action] || '#999')}>{e.action}</span>
                                    </td>
                                    <td style={styles.td}>{e.chunks_returned}</td>
                                    <td style={styles.td}>{e.chunks_blocked}</td>
                                    <td style={styles.td}>
                                        {e.compliance_tags && Object.keys(e.compliance_tags).length > 0
                                            ? Object.entries(e.compliance_tags).map(([k, v]) => (
                                                <span key={k} style={{ ...styles.badge('#9b59b6'), marginRight: 4 }}>{k}:{v}</span>
                                            ))
                                            : <span style={{ color: '#999' }}>-</span>
                                        }
                                    </td>
                                    <td style={styles.td}>{e.latency_ms} ms</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Anomaly Timeline Tab */}
            {activeTab === 'anomalies' && (
                <div style={styles.card}>
                    <div style={styles.cardTitle}>Anomaly Event Timeline</div>
                    {anomalies.length === 0 && (
                        <div style={{ color: '#999', textAlign: 'center', padding: 24 }}>No anomaly events detected.</div>
                    )}
                    {anomalies.map((a, i) => (
                        <div key={i} style={styles.timelineItem}>
                            <strong>{a.collection_name}</strong> — tenant: {a.tenant_id} — score: {a.anomaly_score?.toFixed(4) || 0}
                            <div style={{ fontSize: 11, color: '#999', marginTop: 2 }}>
                                {a.timestamp ? new Date(a.timestamp * 1000).toLocaleString() : '-'}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
