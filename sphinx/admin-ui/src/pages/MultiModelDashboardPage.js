import React, { useEffect, useState } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    header: { fontSize: 24, fontWeight: 700, marginBottom: 24 },
    grid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 },
    fullWidth: { gridColumn: '1 / -1' },
    card: {
        background: '#fff', borderRadius: 8, padding: 20,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    },
    cardTitle: { fontSize: 16, fontWeight: 600, marginBottom: 12, borderBottom: '1px solid #eee', paddingBottom: 8 },
    table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
    th: { textAlign: 'left', padding: '8px 10px', borderBottom: '2px solid #ddd', fontWeight: 600, background: '#fafafa' },
    td: { padding: '8px 10px', borderBottom: '1px solid #eee' },
    badge: (color) => ({
        display: 'inline-block', padding: '2px 8px', borderRadius: 12,
        fontSize: 11, fontWeight: 600, color: '#fff', background: color,
    }),
    refreshBtn: {
        padding: '8px 16px', background: '#2196f3', color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', marginBottom: 16, fontSize: 13,
    },
    statRow: { display: 'flex', gap: 16, marginBottom: 16 },
    statBox: (color) => ({
        flex: 1, background: color, color: '#fff', borderRadius: 8,
        padding: '16px 20px', textAlign: 'center',
    }),
    statValue: { fontSize: 28, fontWeight: 700 },
    statLabel: { fontSize: 12, opacity: 0.9, marginTop: 4 },
    empty: { color: '#999', fontStyle: 'italic', padding: 12 },
};

function healthBadge(isHealthy) {
    return <span style={styles.badge(isHealthy ? '#4caf50' : '#f44336')}>{isHealthy ? 'Healthy' : 'Unhealthy'}</span>;
}

function cbStateBadge(state) {
    const colors = { closed: '#4caf50', open: '#f44336', half_open: '#ff9800' };
    return <span style={styles.badge(colors[state] || '#999')}>{state}</span>;
}

export default function MultiModelDashboardPage() {
    const { apiFetch } = useAuth();
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchDashboard = async () => {
        setLoading(true);
        try {
            const resp = await apiFetch('/admin/multi-model-dashboard');
            if (resp.ok) setData(await resp.json());
        } catch (e) { /* ignore */ }
        setLoading(false);
    };

    useEffect(() => { fetchDashboard(); }, []);

    if (loading && !data) return <div>Loading dashboard...</div>;
    if (!data) return <div>Failed to load dashboard data.</div>;

    const totalProviders = Object.keys(data.model_registry || {}).length;
    const totalModels = Object.values(data.model_registry || {}).reduce((a, b) => a + b.length, 0);
    const healthyCount = (data.provider_health || []).filter(h => h.is_healthy).length;
    const activeKillSwitches = (data.active_kill_switches || []).length;

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h1 style={styles.header}>Multi-Model Dashboard</h1>
                <button style={styles.refreshBtn} onClick={fetchDashboard}>Refresh</button>
            </div>

            {/* Summary Stats */}
            <div style={styles.statRow}>
                <div style={styles.statBox('#1976d2')}>
                    <div style={styles.statValue}>{totalProviders}</div>
                    <div style={styles.statLabel}>Providers</div>
                </div>
                <div style={styles.statBox('#7b1fa2')}>
                    <div style={styles.statValue}>{totalModels}</div>
                    <div style={styles.statLabel}>Models</div>
                </div>
                <div style={styles.statBox(healthyCount === totalProviders ? '#388e3c' : '#d32f2f')}>
                    <div style={styles.statValue}>{healthyCount}/{(data.provider_health || []).length}</div>
                    <div style={styles.statLabel}>Healthy</div>
                </div>
                <div style={styles.statBox(activeKillSwitches > 0 ? '#d32f2f' : '#388e3c')}>
                    <div style={styles.statValue}>{activeKillSwitches}</div>
                    <div style={styles.statLabel}>Kill-Switches</div>
                </div>
            </div>

            <div style={styles.grid}>
                {/* Model Registry */}
                <div style={{ ...styles.card, ...styles.fullWidth }}>
                    <div style={styles.cardTitle}>Model Registry</div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Provider</th>
                                <th style={styles.th}>Models</th>
                                <th style={styles.th}>Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {Object.entries(data.model_registry || {}).map(([provider, models]) => (
                                <tr key={provider}>
                                    <td style={styles.td}><strong>{provider}</strong></td>
                                    <td style={styles.td}>{models.join(', ')}</td>
                                    <td style={styles.td}>{models.length}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {Object.keys(data.model_registry || {}).length === 0 && <div style={styles.empty}>No providers registered</div>}
                </div>

                {/* Provider Health */}
                <div style={styles.card}>
                    <div style={styles.cardTitle}>Provider Health Status</div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Provider</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Latency</th>
                                <th style={styles.th}>Error Rate</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.provider_health || []).map((h, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{h.provider_name}</td>
                                    <td style={styles.td}>{healthBadge(h.is_healthy)}</td>
                                    <td style={styles.td}>{h.latency_ms?.toFixed(1)} ms</td>
                                    <td style={styles.td}>{(h.error_rate * 100).toFixed(1)}%</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {(data.provider_health || []).length === 0 && <div style={styles.empty}>No health data available</div>}
                </div>

                {/* Circuit Breakers */}
                <div style={styles.card}>
                    <div style={styles.cardTitle}>Circuit Breakers</div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Provider</th>
                                <th style={styles.th}>State</th>
                                <th style={styles.th}>Failures</th>
                                <th style={styles.th}>Threshold</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.circuit_breakers || []).map((cb, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{cb.provider_name}</td>
                                    <td style={styles.td}>{cbStateBadge(cb.state)}</td>
                                    <td style={styles.td}>{cb.failure_count}</td>
                                    <td style={styles.td}>{cb.failure_threshold}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {(data.circuit_breakers || []).length === 0 && <div style={styles.empty}>No circuit breakers configured</div>}
                </div>

                {/* Cost Breakdown */}
                <div style={{ ...styles.card, ...styles.fullWidth }}>
                    <div style={styles.cardTitle}>Cost Breakdown (24h)</div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Provider</th>
                                <th style={styles.th}>Prompt Tokens</th>
                                <th style={styles.th}>Completion Tokens</th>
                                <th style={styles.th}>Total Tokens</th>
                                <th style={styles.th}>Est. Cost (USD)</th>
                                <th style={styles.th}>Requests</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.cost_totals_24h || []).map((c, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{c.provider_name}</td>
                                    <td style={styles.td}>{c.total_prompt_tokens?.toLocaleString()}</td>
                                    <td style={styles.td}>{c.total_completion_tokens?.toLocaleString()}</td>
                                    <td style={styles.td}>{c.total_tokens?.toLocaleString()}</td>
                                    <td style={styles.td}>${c.total_cost_usd?.toFixed(4)}</td>
                                    <td style={styles.td}>{c.request_count}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {(data.cost_totals_24h || []).length === 0 && <div style={styles.empty}>No cost data available</div>}
                </div>

                {/* Active Kill-Switches */}
                <div style={styles.card}>
                    <div style={styles.cardTitle}>Active Kill-Switches</div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Model</th>
                                <th style={styles.th}>Action</th>
                                <th style={styles.th}>Fallback</th>
                                <th style={styles.th}>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.active_kill_switches || []).map((ks, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{ks.model_name}</td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(ks.action === 'block' ? '#f44336' : '#ff9800')}>{ks.action}</span>
                                    </td>
                                    <td style={styles.td}>{ks.fallback_model || '-'}</td>
                                    <td style={styles.td}>{ks.reason || '-'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {(data.active_kill_switches || []).length === 0 && <div style={styles.empty}>No active kill-switches</div>}
                </div>

                {/* Routing Rules Summary */}
                <div style={styles.card}>
                    <div style={styles.cardTitle}>Routing Rules</div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Name</th>
                                <th style={styles.th}>Priority</th>
                                <th style={styles.th}>Type</th>
                                <th style={styles.th}>Target</th>
                                <th style={styles.th}>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data.routing_rules || []).map((r, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{r.name}</td>
                                    <td style={styles.td}>{r.priority}</td>
                                    <td style={styles.td}>{r.condition_type}</td>
                                    <td style={styles.td}>{r.target_model || '-'}</td>
                                    <td style={styles.td}>{r.action}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {(data.routing_rules || []).length === 0 && <div style={styles.empty}>No routing rules configured</div>}
                </div>
            </div>
        </div>
    );
}
