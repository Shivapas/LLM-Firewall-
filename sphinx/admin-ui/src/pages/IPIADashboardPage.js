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
    cardValueSmall: { fontSize: 20, fontWeight: 600, color: '#1a1a2e' },
    section: { marginTop: 32 },
    sectionTitle: { fontSize: 18, fontWeight: 600, marginBottom: 12, color: '#333' },
    badge: (active) => ({
        display: 'inline-block', padding: '4px 12px', borderRadius: 12,
        fontSize: 13, fontWeight: 600,
        background: active ? '#e8f5e9' : '#ffebee',
        color: active ? '#2e7d32' : '#c62828',
    }),
    table: { width: '100%', borderCollapse: 'collapse', marginTop: 12 },
    th: { textAlign: 'left', padding: '10px 12px', borderBottom: '2px solid #eee', fontSize: 13, color: '#666', fontWeight: 600 },
    td: { padding: '10px 12px', borderBottom: '1px solid #f0f0f0', fontSize: 14 },
    toggleBtn: (enabled) => ({
        padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
        fontWeight: 600, fontSize: 14,
        background: enabled ? '#c62828' : '#2e7d32',
        color: '#fff',
    }),
    configRow: { display: 'flex', alignItems: 'center', gap: 16, marginBottom: 12 },
    input: { padding: '6px 12px', borderRadius: 6, border: '1px solid #ddd', fontSize: 14, width: 100 },
    saveBtn: {
        padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
        fontWeight: 600, fontSize: 14, background: '#1a1a2e', color: '#fff',
    },
};

export default function IPIADashboardPage() {
    const { apiFetch } = useAuth();
    const [metrics, setMetrics] = useState(null);
    const [config, setConfig] = useState(null);
    const [health, setHealth] = useState(null);
    const [threshold, setThreshold] = useState('');

    const loadData = useCallback(async () => {
        try {
            const [mRes, cRes, hRes] = await Promise.all([
                apiFetch('/v1/ipia/metrics'),
                apiFetch('/v1/ipia/config'),
                apiFetch('/v1/ipia/health'),
            ]);
            const mData = await mRes.json();
            const cData = await cRes.json();
            const hData = await hRes.json();
            setMetrics(mData);
            setConfig(cData);
            setHealth(hData);
            if (threshold === '') setThreshold(String(cData.default_threshold));
        } catch {
            // silently fail on load
        }
    }, [apiFetch, threshold]);

    useEffect(() => {
        loadData();
        const interval = setInterval(loadData, 30000);
        return () => clearInterval(interval);
    }, [loadData]);

    const toggleEnabled = async () => {
        try {
            await apiFetch('/v1/ipia/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ipia_enabled: !config?.ipia_enabled }),
            });
            loadData();
        } catch { /* ignore */ }
    };

    const saveThreshold = async () => {
        try {
            const val = parseFloat(threshold);
            if (isNaN(val) || val < 0 || val > 1) return;
            await apiFetch('/v1/ipia/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ default_threshold: val }),
            });
            loadData();
        } catch { /* ignore */ }
    };

    return (
        <div>
            <h1 style={styles.heading}>IPIA Detection Dashboard</h1>
            <div style={styles.subtitle}>
                Indirect Prompt Injection Analysis — Module E15 (Sprint 32)
            </div>

            {/* KPI Cards */}
            <div style={styles.grid}>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>24h Detections</div>
                    <div style={styles.cardValue}>
                        {metrics?.rolling_24h_detection_count ?? '-'}
                    </div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Total Scans</div>
                    <div style={styles.cardValue}>
                        {metrics?.total_scans ?? '-'}
                    </div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Detection Rate</div>
                    <div style={styles.cardValue}>
                        {metrics ? (metrics.detection_rate * 100).toFixed(2) + '%' : '-'}
                    </div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>IPIA Status</div>
                    <div style={styles.cardValue}>
                        <span style={styles.badge(config?.ipia_enabled)}>
                            {config?.ipia_enabled ? 'ENABLED' : 'DISABLED'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Health & Config */}
            <div style={styles.grid}>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Embedding Backend</div>
                    <div style={styles.cardValueSmall}>{health?.backend ?? '-'}</div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Embedding Dimension</div>
                    <div style={styles.cardValueSmall}>{health?.dimension ?? '-'}</div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Reference Patterns</div>
                    <div style={styles.cardValueSmall}>{health?.reference_count ?? '-'}</div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Default Threshold</div>
                    <div style={styles.cardValueSmall}>{config?.default_threshold ?? '-'}</div>
                </div>
            </div>

            {/* Configuration Controls */}
            <div style={styles.section}>
                <div style={styles.sectionTitle}>Configuration</div>
                <div style={styles.card}>
                    <div style={styles.configRow}>
                        <span style={{ fontWeight: 600, minWidth: 160 }}>Feature Flag:</span>
                        <button style={styles.toggleBtn(config?.ipia_enabled)} onClick={toggleEnabled}>
                            {config?.ipia_enabled ? 'Disable IPIA' : 'Enable IPIA'}
                        </button>
                    </div>
                    <div style={styles.configRow}>
                        <span style={{ fontWeight: 600, minWidth: 160 }}>Detection Threshold:</span>
                        <input
                            type="number"
                            min="0"
                            max="1"
                            step="0.05"
                            style={styles.input}
                            value={threshold}
                            onChange={(e) => setThreshold(e.target.value)}
                        />
                        <button style={styles.saveBtn} onClick={saveThreshold}>Save</button>
                        <span style={{ fontSize: 12, color: '#888' }}>
                            (0.0 = block all, 1.0 = pass all)
                        </span>
                    </div>
                </div>
            </div>

            {/* Top Blocked Categories */}
            <div style={styles.section}>
                <div style={styles.sectionTitle}>Top Blocked Categories (24h)</div>
                <div style={styles.card}>
                    {metrics?.top_blocked_categories?.length > 0 ? (
                        <table style={styles.table}>
                            <thead>
                                <tr>
                                    <th style={styles.th}>Category</th>
                                    <th style={styles.th}>Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                {metrics.top_blocked_categories.map((cat, i) => (
                                    <tr key={i}>
                                        <td style={styles.td}>{cat.category}</td>
                                        <td style={styles.td}>{cat.count}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <div style={{ color: '#888', padding: 12 }}>
                            No detections in the last 24 hours.
                        </div>
                    )}
                </div>
            </div>

            {/* Threat Event Emitter Status */}
            <div style={styles.section}>
                <div style={styles.sectionTitle}>TrustDetect Emitter Status</div>
                <div style={styles.grid}>
                    <div style={styles.card}>
                        <div style={styles.cardLabel}>Kafka Connected</div>
                        <span style={styles.badge(config?.emitter_connected)}>
                            {config?.emitter_connected ? 'Connected' : 'Disconnected'}
                        </span>
                    </div>
                    <div style={styles.card}>
                        <div style={styles.cardLabel}>Events Emitted</div>
                        <div style={styles.cardValueSmall}>
                            {config?.emitter_emitted_count ?? '-'}
                        </div>
                    </div>
                    <div style={styles.card}>
                        <div style={styles.cardLabel}>Fallback Queue</div>
                        <div style={styles.cardValueSmall}>
                            {config?.emitter_fallback_queue_size ?? '-'}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
