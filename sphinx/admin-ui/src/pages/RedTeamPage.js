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
    grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 },
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
        fontWeight: 600, fontSize: 13, background: '#1a73e8', color: '#fff', marginRight: 8,
    },
    btnDanger: {
        padding: '8px 16px', border: 'none', borderRadius: 6, cursor: 'pointer',
        fontWeight: 600, fontSize: 13, background: '#d32f2f', color: '#fff',
    },
    btnSuccess: {
        padding: '8px 16px', border: 'none', borderRadius: 6, cursor: 'pointer',
        fontWeight: 600, fontSize: 13, background: '#2e7d32', color: '#fff', marginRight: 8,
    },
    input: {
        padding: '8px 12px', border: '1px solid #ddd', borderRadius: 6, fontSize: 14, width: '100%',
        boxSizing: 'border-box', marginBottom: 12,
    },
    select: {
        padding: '8px 12px', border: '1px solid #ddd', borderRadius: 6, fontSize: 14,
        marginRight: 8, marginBottom: 8,
    },
    formGroup: { marginBottom: 16 },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#333', marginBottom: 4 },
    modal: {
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 1000,
    },
    modalContent: {
        background: '#fff', borderRadius: 12, padding: 32, maxWidth: 560, width: '90%',
        maxHeight: '80vh', overflowY: 'auto',
    },
};

const severityColor = {
    critical: '#d32f2f', high: '#e65100', medium: '#f9a825', low: '#2e7d32', info: '#1565c0',
};

const statusColor = {
    pending: '#757575', running: '#1a73e8', completed: '#2e7d32', failed: '#d32f2f', cancelled: '#e65100',
};

export default function RedTeamPage() {
    const { apiFetch } = useAuth();
    const [campaigns, setCampaigns] = useState([]);
    const [probeInfo, setProbeInfo] = useState(null);
    const [selectedCampaign, setSelectedCampaign] = useState(null);
    const [results, setResults] = useState([]);
    const [report, setReport] = useState(null);
    const [showCreate, setShowCreate] = useState(false);
    const [loading, setLoading] = useState(true);
    const [filterCategory, setFilterCategory] = useState('');
    const [filterSeverity, setFilterSeverity] = useState('');
    const [filterDetectedOnly, setFilterDetectedOnly] = useState(false);
    const [form, setForm] = useState({
        name: '', target_url: '', description: '',
        probe_categories: ['injection', 'jailbreak', 'pii_extraction'],
        concurrency: 10, timeout_seconds: 30,
    });

    const fetchCampaigns = useCallback(async () => {
        try {
            const res = await apiFetch(`/admin/red-team/campaigns`);
            setCampaigns(await res.json());
        } catch (e) { console.error(e); }
        setLoading(false);
    }, []);

    const fetchProbeInfo = useCallback(async () => {
        try {
            const res = await apiFetch(`/admin/red-team/probes`);
            setProbeInfo(await res.json());
        } catch (e) { console.error(e); }
    }, []);

    useEffect(() => { fetchCampaigns(); fetchProbeInfo(); }, [fetchCampaigns, fetchProbeInfo]);

    // Auto-refresh running campaigns
    useEffect(() => {
        const hasRunning = campaigns.some(c => c.status === 'running');
        if (!hasRunning) return;
        const interval = setInterval(fetchCampaigns, 3000);
        return () => clearInterval(interval);
    }, [campaigns, fetchCampaigns]);

    const handleCreate = async () => {
        try {
            const res = await apiFetch(`/admin/red-team/campaigns`, {
                method: 'POST',
                body: JSON.stringify(form),
            });
            if (res.ok) {
                setShowCreate(false);
                setForm({ name: '', target_url: '', description: '', probe_categories: ['injection', 'jailbreak', 'pii_extraction'], concurrency: 10, timeout_seconds: 30 });
                fetchCampaigns();
            }
        } catch (e) { console.error(e); }
    };

    const handleRun = async (campaignId) => {
        try {
            await apiFetch(`/admin/red-team/campaigns/${campaignId}/run`, { method: 'POST' });
            fetchCampaigns();
        } catch (e) { console.error(e); }
    };

    const handleDelete = async (campaignId) => {
        if (!window.confirm('Delete this campaign?')) return;
        try {
            await apiFetch(`/admin/red-team/campaigns/${campaignId}`, { method: 'DELETE' });
            if (selectedCampaign && selectedCampaign.id === campaignId) setSelectedCampaign(null);
            fetchCampaigns();
        } catch (e) { console.error(e); }
    };

    const handleViewResults = async (campaign) => {
        setSelectedCampaign(campaign);
        setReport(null);
        try {
            let url = `/admin/red-team/campaigns/${campaign.id}/results?`;
            if (filterCategory) url += `category=${filterCategory}&`;
            if (filterSeverity) url += `severity=${filterSeverity}&`;
            if (filterDetectedOnly) url += `detected_only=true&`;
            const res = await apiFetch(url);
            setResults(await res.json());
        } catch (e) { console.error(e); }
    };

    const handleExportReport = async (campaignId) => {
        try {
            const res = await apiFetch(`/admin/red-team/campaigns/${campaignId}/report`);
            if (res.ok) setReport(await res.json());
        } catch (e) { console.error(e); }
    };

    // Re-fetch results when filters change
    useEffect(() => {
        if (selectedCampaign) handleViewResults(selectedCampaign);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [filterCategory, filterSeverity, filterDetectedOnly]);

    if (loading) return <div style={styles.page}><p>Loading red team dashboard...</p></div>;

    return (
        <div style={styles.page}>
            <div style={styles.header}>
                <h1 style={styles.title}>Red Team Engine</h1>
                <button style={styles.btn} onClick={() => setShowCreate(true)}>+ New Campaign</button>
            </div>

            {/* Probe Library Summary */}
            {probeInfo && (
                <div style={styles.grid}>
                    <div style={styles.statCard('#1a73e8')}>
                        <div style={styles.statValue}>{probeInfo.total}</div>
                        <div style={styles.statLabel}>Total Probes</div>
                    </div>
                    {Object.entries(probeInfo.suites || {}).map(([name, info]) => (
                        <div key={name} style={styles.statCard(name === 'injection' ? '#d32f2f' : name === 'jailbreak' ? '#e65100' : '#7b1fa2')}>
                            <div style={styles.statValue}>{info.count}</div>
                            <div style={styles.statLabel}>{name.replace('_', ' ')}</div>
                        </div>
                    ))}
                </div>
            )}

            {/* Campaign List */}
            <div style={styles.card}>
                <h2 style={styles.sectionTitle}>Campaigns</h2>
                {campaigns.length === 0 ? (
                    <p style={{ color: '#666' }}>No campaigns yet. Create one to get started.</p>
                ) : (
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Name</th>
                                <th style={styles.th}>Target</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Probes</th>
                                <th style={styles.th}>Findings</th>
                                <th style={styles.th}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {campaigns.map(c => (
                                <tr key={c.id}>
                                    <td style={styles.td}>{c.name}</td>
                                    <td style={styles.td} title={c.target_url}>
                                        {c.target_url.length > 40 ? c.target_url.slice(0, 40) + '...' : c.target_url}
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(statusColor[c.status] || '#757575')}>{c.status}</span>
                                    </td>
                                    <td style={styles.td}>{c.probes_executed}/{c.total_probes}</td>
                                    <td style={styles.td}>
                                        {c.findings_summary ? (
                                            <span style={styles.badge(c.findings_summary.total_findings > 0 ? '#d32f2f' : '#2e7d32')}>
                                                {c.findings_summary.total_findings} findings
                                            </span>
                                        ) : '-'}
                                    </td>
                                    <td style={styles.td}>
                                        {c.status === 'pending' && (
                                            <button style={styles.btnSuccess} onClick={() => handleRun(c.id)}>Run</button>
                                        )}
                                        {c.status === 'completed' && (
                                            <>
                                                <button style={styles.btn} onClick={() => handleViewResults(c)}>Results</button>
                                                <button style={{ ...styles.btn, background: '#7b1fa2' }} onClick={() => handleExportReport(c.id)}>Export</button>
                                            </>
                                        )}
                                        <button style={styles.btnDanger} onClick={() => handleDelete(c.id)}>Delete</button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Results Panel */}
            {selectedCampaign && (
                <div style={styles.card}>
                    <h2 style={styles.sectionTitle}>Results: {selectedCampaign.name}</h2>
                    <div style={{ marginBottom: 16, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        <select style={styles.select} value={filterCategory} onChange={e => setFilterCategory(e.target.value)}>
                            <option value="">All Categories</option>
                            <option value="injection">Injection</option>
                            <option value="jailbreak">Jailbreak</option>
                            <option value="pii_extraction">PII Extraction</option>
                        </select>
                        <select style={styles.select} value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}>
                            <option value="">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13 }}>
                            <input type="checkbox" checked={filterDetectedOnly} onChange={e => setFilterDetectedOnly(e.target.checked)} />
                            Findings only
                        </label>
                    </div>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Probe</th>
                                <th style={styles.th}>Category</th>
                                <th style={styles.th}>Technique</th>
                                <th style={styles.th}>Severity</th>
                                <th style={styles.th}>Detected</th>
                                <th style={styles.th}>Risk Score</th>
                                <th style={styles.th}>Latency</th>
                            </tr>
                        </thead>
                        <tbody>
                            {results.map(r => (
                                <tr key={r.id} style={{ background: r.detected ? '#fff3f3' : 'transparent' }}>
                                    <td style={styles.td} title={r.probe_name}>{r.probe_id}</td>
                                    <td style={styles.td}>{r.category}</td>
                                    <td style={styles.td}>{r.technique}</td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(severityColor[r.severity] || '#757575')}>{r.severity}</span>
                                    </td>
                                    <td style={styles.td}>
                                        <span style={styles.badge(r.detected ? '#d32f2f' : '#2e7d32')}>
                                            {r.detected ? 'VULNERABLE' : 'BLOCKED'}
                                        </span>
                                    </td>
                                    <td style={styles.td}>{r.risk_score.toFixed(2)}</td>
                                    <td style={styles.td}>{r.latency_ms.toFixed(0)}ms</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {results.length === 0 && <p style={{ color: '#666', textAlign: 'center', padding: 24 }}>No results match filters.</p>}
                </div>
            )}

            {/* Report Panel */}
            {report && (
                <div style={styles.card}>
                    <h2 style={styles.sectionTitle}>Findings Report</h2>
                    <div style={styles.grid}>
                        <div style={styles.statCard('#d32f2f')}>
                            <div style={styles.statValue}>{report.summary?.total_findings || 0}</div>
                            <div style={styles.statLabel}>Total Findings</div>
                        </div>
                        <div style={styles.statCard('#1a73e8')}>
                            <div style={styles.statValue}>{report.summary?.total_probes || 0}</div>
                            <div style={styles.statLabel}>Probes Run</div>
                        </div>
                        <div style={styles.statCard('#e65100')}>
                            <div style={styles.statValue}>{((report.summary?.detection_rate || 0) * 100).toFixed(1)}%</div>
                            <div style={styles.statLabel}>Detection Rate</div>
                        </div>
                    </div>
                    {report.summary?.by_severity && (
                        <div style={{ marginBottom: 16 }}>
                            <strong>By Severity: </strong>
                            {Object.entries(report.summary.by_severity).map(([sev, count]) => (
                                <span key={sev} style={{ ...styles.badge(severityColor[sev] || '#757575'), marginRight: 8 }}>
                                    {sev}: {count}
                                </span>
                            ))}
                        </div>
                    )}
                    {report.recommendations && report.recommendations.length > 0 && (
                        <div>
                            <h3 style={{ ...styles.sectionTitle, fontSize: 16 }}>Recommendations</h3>
                            {report.recommendations.map((rec, i) => (
                                <div key={i} style={{ ...styles.card, borderLeft: `4px solid ${severityColor[rec.priority] || '#1a73e8'}` }}>
                                    <strong>{rec.category}</strong> ({rec.priority}): {rec.recommendation}
                                </div>
                            ))}
                        </div>
                    )}
                    <div style={{ marginTop: 16, textAlign: 'right' }}>
                        <button style={styles.btn} onClick={() => {
                            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url; a.download = `red-team-report-${report.campaign_id}.json`;
                            a.click(); URL.revokeObjectURL(url);
                        }}>Download Report JSON</button>
                    </div>
                </div>
            )}

            {/* Create Campaign Modal */}
            {showCreate && (
                <div style={styles.modal} onClick={() => setShowCreate(false)}>
                    <div style={styles.modalContent} onClick={e => e.stopPropagation()}>
                        <h2 style={styles.sectionTitle}>Create Red Team Campaign</h2>
                        <div style={styles.formGroup}>
                            <label style={styles.label}>Campaign Name</label>
                            <input style={styles.input} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g., Production API Security Scan" />
                        </div>
                        <div style={styles.formGroup}>
                            <label style={styles.label}>Target URL</label>
                            <input style={styles.input} value={form.target_url} onChange={e => setForm({ ...form, target_url: e.target.value })} placeholder="https://api.example.com/v1/chat/completions" />
                        </div>
                        <div style={styles.formGroup}>
                            <label style={styles.label}>Description</label>
                            <input style={styles.input} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
                        </div>
                        <div style={styles.formGroup}>
                            <label style={styles.label}>Probe Categories</label>
                            {['injection', 'jailbreak', 'pii_extraction'].map(cat => (
                                <label key={cat} style={{ display: 'inline-flex', alignItems: 'center', marginRight: 16, fontSize: 14 }}>
                                    <input type="checkbox" checked={form.probe_categories.includes(cat)}
                                        onChange={e => {
                                            const cats = e.target.checked
                                                ? [...form.probe_categories, cat]
                                                : form.probe_categories.filter(c => c !== cat);
                                            setForm({ ...form, probe_categories: cats });
                                        }}
                                    />
                                    <span style={{ marginLeft: 4 }}>{cat.replace('_', ' ')}</span>
                                </label>
                            ))}
                        </div>
                        <div style={{ display: 'flex', gap: 16 }}>
                            <div style={{ ...styles.formGroup, flex: 1 }}>
                                <label style={styles.label}>Concurrency</label>
                                <input style={styles.input} type="number" value={form.concurrency} onChange={e => setForm({ ...form, concurrency: parseInt(e.target.value) || 10 })} />
                            </div>
                            <div style={{ ...styles.formGroup, flex: 1 }}>
                                <label style={styles.label}>Timeout (seconds)</label>
                                <input style={styles.input} type="number" value={form.timeout_seconds} onChange={e => setForm({ ...form, timeout_seconds: parseInt(e.target.value) || 30 })} />
                            </div>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                            <button style={{ ...styles.btn, background: '#757575' }} onClick={() => setShowCreate(false)}>Cancel</button>
                            <button style={styles.btn} onClick={handleCreate} disabled={!form.name || !form.target_url}>Create Campaign</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
