import React, { useEffect, useState, useCallback } from 'react';

const styles = {
    container: { maxWidth: 1100, margin: '0 auto' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 },
    title: { fontSize: 24, fontWeight: 700 },
    btn: {
        padding: '8px 18px', background: '#2196F3', color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', fontWeight: 600,
    },
    btnDanger: {
        padding: '6px 14px', background: '#e74c3c', color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 13,
    },
    btnSmall: {
        padding: '4px 10px', background: '#4CAF50', color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 12,
    },
    table: { width: '100%', borderCollapse: 'collapse', background: '#fff', borderRadius: 8, overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' },
    th: { padding: '12px 16px', textAlign: 'left', background: '#f0f0f0', fontWeight: 600, fontSize: 13 },
    td: { padding: '10px 16px', borderTop: '1px solid #eee', fontSize: 14 },
    badge: (level) => {
        const colors = { critical: '#e74c3c', high: '#e67e22', medium: '#f39c12', low: '#27ae60' };
        return {
            display: 'inline-block', padding: '2px 10px', borderRadius: 12,
            background: colors[level] || '#999', color: '#fff', fontWeight: 600, fontSize: 12,
        };
    },
    section: { marginTop: 32 },
    sectionTitle: { fontSize: 18, fontWeight: 600, marginBottom: 12 },
    card: { background: '#fff', borderRadius: 8, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.1)', marginBottom: 16 },
    alertRow: (ack) => ({ opacity: ack ? 0.5 : 1 }),
    capList: { listStyle: 'none', padding: 0, margin: 0 },
    capItem: { padding: '6px 0', borderBottom: '1px solid #f0f0f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
    form: { display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' },
    input: { padding: '8px 12px', border: '1px solid #ddd', borderRadius: 4, fontSize: 14 },
    empty: { textAlign: 'center', color: '#999', padding: 40 },
};

export default function MCPScannerPage() {
    const [servers, setServers] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [selectedServer, setSelectedServer] = useState(null);
    const [capabilities, setCapabilities] = useState([]);
    const [loading, setLoading] = useState(false);
    const [regName, setRegName] = useState('');
    const [regUrl, setRegUrl] = useState('');

    const fetchServers = useCallback(async () => {
        try {
            const res = await fetch('/admin/mcp/servers');
            if (res.ok) setServers(await res.json());
        } catch (e) { console.error('Failed to fetch MCP servers', e); }
    }, []);

    const fetchAlerts = useCallback(async () => {
        try {
            const res = await fetch('/admin/mcp/alerts');
            if (res.ok) setAlerts(await res.json());
        } catch (e) { console.error('Failed to fetch alerts', e); }
    }, []);

    useEffect(() => { fetchServers(); fetchAlerts(); }, [fetchServers, fetchAlerts]);

    const handleDiscover = async (serverName, url) => {
        setLoading(true);
        try {
            const res = await fetch('/admin/mcp/discover', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ server_name: serverName, url }),
            });
            if (res.ok) { await fetchServers(); await fetchAlerts(); }
        } catch (e) { console.error('Discovery failed', e); }
        setLoading(false);
    };

    const handleRegister = async (e) => {
        e.preventDefault();
        if (!regName || !regUrl) return;
        try {
            const res = await fetch('/admin/mcp/servers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ server_name: regName, url: regUrl }),
            });
            if (res.ok) { setRegName(''); setRegUrl(''); await fetchServers(); await fetchAlerts(); }
        } catch (e) { console.error('Registration failed', e); }
    };

    const handleAcknowledge = async (alertId) => {
        try {
            await fetch(`/admin/mcp/alerts/${alertId}/acknowledge`, { method: 'POST' });
            await fetchAlerts();
        } catch (e) { console.error('Acknowledge failed', e); }
    };

    const handleMarkReviewed = async (serverName) => {
        try {
            await fetch(`/admin/mcp/servers/${encodeURIComponent(serverName)}/review`, { method: 'POST' });
            await fetchServers();
        } catch (e) { console.error('Review failed', e); }
    };

    const handleSelectServer = async (serverName) => {
        setSelectedServer(serverName);
        try {
            const res = await fetch(`/admin/mcp/servers/${encodeURIComponent(serverName)}/capabilities`);
            if (res.ok) setCapabilities(await res.json());
        } catch (e) { console.error('Failed to fetch capabilities', e); }
    };

    const unackAlerts = alerts.filter(a => !a.is_acknowledged);

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <div>
                    <h1 style={styles.title}>MCP Server Scanner</h1>
                    <p style={{ color: '#666', margin: '4px 0 0' }}>
                        {servers.length} server{servers.length !== 1 ? 's' : ''} registered
                        {unackAlerts.length > 0 && <span style={{ color: '#e74c3c', marginLeft: 12, fontWeight: 600 }}>{unackAlerts.length} alert{unackAlerts.length !== 1 ? 's' : ''}</span>}
                    </p>
                </div>
            </div>

            {/* Register new server */}
            <div style={styles.card}>
                <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>Register MCP Server</h3>
                <form style={styles.form} onSubmit={handleRegister}>
                    <input style={styles.input} placeholder="Server name" value={regName} onChange={e => setRegName(e.target.value)} />
                    <input style={{ ...styles.input, flex: 1 }} placeholder="Server URL" value={regUrl} onChange={e => setRegUrl(e.target.value)} />
                    <button style={styles.btn} type="submit">Register</button>
                </form>
            </div>

            {/* Server inventory table */}
            {servers.length === 0 ? (
                <div style={styles.empty}>No MCP servers registered yet.</div>
            ) : (
                <table style={styles.table}>
                    <thead>
                        <tr>
                            <th style={styles.th}>Server Name</th>
                            <th style={styles.th}>URL</th>
                            <th style={styles.th}>Risk</th>
                            <th style={styles.th}>Agents</th>
                            <th style={styles.th}>Reviewed</th>
                            <th style={styles.th}>Last Seen</th>
                            <th style={styles.th}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {servers.map(s => (
                            <tr key={s.server_name} style={{ cursor: 'pointer' }} onClick={() => handleSelectServer(s.server_name)}>
                                <td style={styles.td}><strong>{s.server_name}</strong></td>
                                <td style={styles.td}>{s.url}</td>
                                <td style={styles.td}><span style={styles.badge(s.risk_level)}>{s.risk_level}</span></td>
                                <td style={styles.td}>{(s.connected_agents || []).length}</td>
                                <td style={styles.td}>{s.is_reviewed ? 'Yes' : 'No'}</td>
                                <td style={styles.td}>{s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : '-'}</td>
                                <td style={styles.td}>
                                    <button style={styles.btn} disabled={loading} onClick={e => { e.stopPropagation(); handleDiscover(s.server_name, s.url); }}>
                                        Scan
                                    </button>
                                    {!s.is_reviewed && (
                                        <button style={{ ...styles.btnSmall, marginLeft: 8 }} onClick={e => { e.stopPropagation(); handleMarkReviewed(s.server_name); }}>
                                            Mark Reviewed
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}

            {/* Capability detail panel */}
            {selectedServer && (
                <div style={styles.section}>
                    <h2 style={styles.sectionTitle}>Capabilities: {selectedServer}</h2>
                    <div style={styles.card}>
                        {capabilities.length === 0 ? (
                            <div style={styles.empty}>No capabilities discovered. Run a scan first.</div>
                        ) : (
                            <ul style={styles.capList}>
                                {capabilities.map((c, i) => (
                                    <li key={i} style={styles.capItem}>
                                        <div>
                                            <strong>{c.tool_name}</strong>
                                            <span style={{ color: '#888', marginLeft: 8, fontSize: 13 }}>{c.capability_category}</span>
                                            {c.description && <div style={{ fontSize: 12, color: '#666', marginTop: 2 }}>{c.description}</div>}
                                        </div>
                                        <span style={styles.badge(c.risk_level)}>{c.risk_level} ({c.risk_score})</span>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </div>
            )}

            {/* Alerts section */}
            <div style={styles.section}>
                <h2 style={styles.sectionTitle}>Risk Alerts</h2>
                {alerts.length === 0 ? (
                    <div style={styles.empty}>No alerts.</div>
                ) : (
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Type</th>
                                <th style={styles.th}>Server</th>
                                <th style={styles.th}>Tool</th>
                                <th style={styles.th}>Risk</th>
                                <th style={styles.th}>Message</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {alerts.map(a => (
                                <tr key={a.id} style={styles.alertRow(a.is_acknowledged)}>
                                    <td style={styles.td}>{a.alert_type}</td>
                                    <td style={styles.td}>{a.server_name}</td>
                                    <td style={styles.td}>{a.tool_name || '-'}</td>
                                    <td style={styles.td}><span style={styles.badge(a.risk_level)}>{a.risk_level}</span></td>
                                    <td style={styles.td}>{a.message}</td>
                                    <td style={styles.td}>{a.is_acknowledged ? 'Acknowledged' : 'Open'}</td>
                                    <td style={styles.td}>
                                        {!a.is_acknowledged && (
                                            <button style={styles.btnSmall} onClick={() => handleAcknowledge(a.id)}>Acknowledge</button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}
