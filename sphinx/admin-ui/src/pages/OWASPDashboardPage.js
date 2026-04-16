import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    heading: { fontSize: 24, fontWeight: 700, marginBottom: 8, color: '#1a1a2e' },
    subtitle: { fontSize: 14, color: '#666', marginBottom: 24 },
    grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 20, marginBottom: 32 },
    card: {
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 4px rgba(0,0,0,0.08)',
    },
    cardLabel: { fontSize: 13, color: '#888', marginBottom: 4 },
    cardValue: { fontSize: 28, fontWeight: 700, color: '#1a1a2e' },
    section: { marginTop: 32 },
    sectionTitle: { fontSize: 18, fontWeight: 600, marginBottom: 12, color: '#333' },
    table: { width: '100%', borderCollapse: 'collapse', marginTop: 12 },
    th: { textAlign: 'left', padding: '10px 12px', borderBottom: '2px solid #eee', fontSize: 13, color: '#666', fontWeight: 600 },
    td: { padding: '10px 12px', borderBottom: '1px solid #f0f0f0', fontSize: 14 },
    badge: (color) => ({
        display: 'inline-block', padding: '4px 12px', borderRadius: 12,
        fontSize: 13, fontWeight: 600,
        background: color === 'green' ? '#e8f5e9' : color === 'yellow' ? '#fff8e1' : color === 'orange' ? '#fff3e0' : '#ffebee',
        color: color === 'green' ? '#2e7d32' : color === 'yellow' ? '#f9a825' : color === 'orange' ? '#ef6c00' : '#c62828',
    }),
    severityBadge: (sev) => ({
        display: 'inline-block', padding: '2px 8px', borderRadius: 8,
        fontSize: 12, fontWeight: 600,
        background: sev === 'HIGH' ? '#ffebee' : '#fff3e0',
        color: sev === 'HIGH' ? '#c62828' : '#ef6c00',
    }),
    radarContainer: {
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 4px rgba(0,0,0,0.08)', marginBottom: 32,
    },
    barContainer: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 },
    barLabel: { width: 180, fontSize: 13, color: '#555' },
    barTrack: { flex: 1, height: 20, background: '#f0f0f0', borderRadius: 4, overflow: 'hidden' },
    barFill: (pct) => ({
        width: `${Math.min(pct, 100)}%`, height: '100%', borderRadius: 4,
        background: pct >= 80 ? '#4caf50' : pct >= 60 ? '#ff9800' : '#f44336',
        transition: 'width 0.3s ease',
    }),
    barValue: { width: 50, fontSize: 13, fontWeight: 600, textAlign: 'right' },
    exportBtn: {
        padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
        fontWeight: 600, fontSize: 14, background: '#1a1a2e', color: '#fff', marginRight: 12,
    },
};

export default function OWASPDashboardPage() {
    const { apiFetch } = useAuth();
    const [dashboard, setDashboard] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const loadData = useCallback(async () => {
        try {
            setLoading(true);
            const res = await apiFetch('/v1/owasp/dashboard');
            const data = await res.json();
            setDashboard(data);
            setError(null);
        } catch (err) {
            setError('Failed to load OWASP compliance dashboard');
        } finally {
            setLoading(false);
        }
    }, [apiFetch]);

    useEffect(() => { loadData(); }, [loadData]);

    const handleExportJSON = async () => {
        try {
            const res = await apiFetch('/v1/owasp/export/json');
            const data = await res.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sphinx-owasp-compliance.json';
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            alert('Export failed');
        }
    };

    const handleExportPDF = async () => {
        try {
            const res = await apiFetch('/v1/owasp/export/pdf/text');
            const text = await res.text();
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sphinx-owasp-compliance-report.txt';
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            alert('Export failed');
        }
    };

    if (loading) return <div style={{ padding: 32 }}>Loading OWASP compliance data...</div>;
    if (error) return <div style={{ padding: 32, color: '#c62828' }}>{error}</div>;
    if (!dashboard) return null;

    const { radar_chart, shield_score, top_gaps, coverage_summary, gap_summary } = dashboard;

    return (
        <div style={{ maxWidth: 1200, margin: '0 auto', padding: 32 }}>
            <h1 style={styles.heading}>OWASP LLM Top 10 v2025 Compliance</h1>
            <p style={styles.subtitle}>
                Shield Score and coverage analysis across all 10 OWASP categories
            </p>

            {/* Shield Score + Summary Cards */}
            <div style={styles.grid}>
                <div style={{ ...styles.card, textAlign: 'center' }}>
                    <div style={styles.cardLabel}>Shield Score</div>
                    <div style={{ ...styles.cardValue, fontSize: 42 }}>{shield_score.score}</div>
                    <div style={styles.badge(shield_score.color)}>
                        Grade {shield_score.grade}
                    </div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Requirements Covered</div>
                    <div style={styles.cardValue}>
                        {gap_summary.covered_requirements}/{gap_summary.total_requirements}
                    </div>
                    <div style={{ fontSize: 13, color: '#666' }}>
                        {gap_summary.coverage_percentage}% coverage
                    </div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Gaps Identified</div>
                    <div style={{ ...styles.cardValue, color: gap_summary.gap_count > 0 ? '#ef6c00' : '#2e7d32' }}>
                        {gap_summary.gap_count}
                    </div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Scoring Time</div>
                    <div style={styles.cardValue}>{dashboard.scoring_time_ms.toFixed(1)}ms</div>
                </div>
            </div>

            {/* Radar Chart (bar chart representation) */}
            <div style={styles.radarContainer}>
                <h2 style={styles.sectionTitle}>Category Coverage</h2>
                {radar_chart.labels.map((label, i) => (
                    <div key={label} style={styles.barContainer}>
                        <div style={styles.barLabel}>{label} — {radar_chart.label_names[i]}</div>
                        <div style={styles.barTrack}>
                            <div style={styles.barFill(radar_chart.scores[i])} />
                        </div>
                        <div style={styles.barValue}>{radar_chart.scores[i]}%</div>
                    </div>
                ))}
            </div>

            {/* Top Gaps */}
            {top_gaps && top_gaps.length > 0 && (
                <div style={styles.section}>
                    <h2 style={styles.sectionTitle}>Top Coverage Gaps</h2>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Requirement</th>
                                <th style={styles.th}>Category</th>
                                <th style={styles.th}>Severity</th>
                                <th style={styles.th}>Description</th>
                                <th style={styles.th}>Remediation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {top_gaps.map((gap, i) => (
                                <tr key={i}>
                                    <td style={styles.td}>{gap.requirement_id}</td>
                                    <td style={styles.td}>{gap.category_id}</td>
                                    <td style={styles.td}>
                                        <span style={styles.severityBadge(gap.severity)}>
                                            {gap.severity}
                                        </span>
                                    </td>
                                    <td style={styles.td}>{gap.description}</td>
                                    <td style={{ ...styles.td, fontSize: 12, color: '#555' }}>
                                        {gap.remediation}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Export Buttons */}
            <div style={{ ...styles.section, display: 'flex', gap: 12 }}>
                <button style={styles.exportBtn} onClick={handleExportJSON}>
                    Export JSON
                </button>
                <button style={styles.exportBtn} onClick={handleExportPDF}>
                    Export Report (Text)
                </button>
                <button style={styles.exportBtn} onClick={loadData}>
                    Refresh
                </button>
            </div>
        </div>
    );
}
