import React, { useState, useEffect, useCallback } from 'react';

const styles = {
  container: { padding: '24px', maxWidth: '1400px', margin: '0 auto' },
  header: { fontSize: '24px', fontWeight: 'bold', marginBottom: '24px', color: '#1a1a2e' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '24px' },
  card: { background: '#fff', borderRadius: '8px', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', border: '1px solid #e2e8f0' },
  cardTitle: { fontSize: '14px', color: '#64748b', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.5px' },
  cardValue: { fontSize: '28px', fontWeight: 'bold', color: '#1a1a2e' },
  cardSubtext: { fontSize: '12px', color: '#94a3b8', marginTop: '4px' },
  sectionTitle: { fontSize: '18px', fontWeight: '600', marginBottom: '16px', color: '#1a1a2e', marginTop: '24px' },
  table: { width: '100%', borderCollapse: 'collapse', background: '#fff', borderRadius: '8px', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' },
  th: { padding: '12px 16px', textAlign: 'left', background: '#f8fafc', borderBottom: '2px solid #e2e8f0', fontSize: '13px', fontWeight: '600', color: '#475569' },
  td: { padding: '12px 16px', borderBottom: '1px solid #f1f5f9', fontSize: '14px', color: '#334155' },
  badge: (color) => ({ display: 'inline-block', padding: '2px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: '500', background: color === 'green' ? '#dcfce7' : color === 'red' ? '#fee2e2' : color === 'yellow' ? '#fef9c3' : '#e0e7ff', color: color === 'green' ? '#166534' : color === 'red' ? '#991b1b' : color === 'yellow' ? '#854d0e' : '#3730a3' }),
  btn: { padding: '8px 16px', borderRadius: '6px', border: 'none', cursor: 'pointer', fontSize: '14px', fontWeight: '500', background: '#3b82f6', color: '#fff', marginRight: '8px' },
  btnDanger: { padding: '8px 16px', borderRadius: '6px', border: 'none', cursor: 'pointer', fontSize: '14px', fontWeight: '500', background: '#ef4444', color: '#fff' },
  progressBar: { height: '8px', borderRadius: '4px', background: '#e2e8f0', overflow: 'hidden', marginTop: '8px' },
  progressFill: (pct) => ({ height: '100%', borderRadius: '4px', width: `${Math.min(pct, 100)}%`, background: pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#22c55e', transition: 'width 0.3s' }),
  error: { color: '#dc2626', background: '#fef2f2', padding: '12px', borderRadius: '6px', marginBottom: '16px' },
};

export default function MemoryStoreDashboardPage() {
  const [dashboard, setDashboard] = useState(null);
  const [anomalies, setAnomalies] = useState([]);
  const [integrityAlerts, setIntegrityAlerts] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchDashboard = useCallback(async () => {
    try {
      const res = await fetch('/admin/memory-firewall/dashboard');
      if (!res.ok) throw new Error('Failed to fetch dashboard');
      setDashboard(await res.json());
    } catch (e) {
      setError(e.message);
    }
  }, []);

  const fetchAnomalies = useCallback(async () => {
    try {
      const res = await fetch('/admin/memory-firewall/read-anomalies?limit=20');
      if (res.ok) setAnomalies(await res.json());
    } catch (_) {}
  }, []);

  const fetchIntegrityAlerts = useCallback(async () => {
    try {
      const res = await fetch('/admin/memory-firewall/integrity/alerts?limit=20');
      if (res.ok) setIntegrityAlerts(await res.json());
    } catch (_) {}
  }, []);

  useEffect(() => {
    Promise.all([fetchDashboard(), fetchAnomalies(), fetchIntegrityAlerts()])
      .finally(() => setLoading(false));
  }, [fetchDashboard, fetchAnomalies, fetchIntegrityAlerts]);

  const runIntegrityCheck = async () => {
    try {
      const res = await fetch('/admin/memory-firewall/integrity/verify', { method: 'POST' });
      if (!res.ok) throw new Error('Integrity check failed');
      await Promise.all([fetchDashboard(), fetchIntegrityAlerts()]);
    } catch (e) {
      setError(e.message);
    }
  };

  if (loading) return <div style={styles.container}>Loading memory store dashboard...</div>;

  const d = dashboard || {};
  const proxyStats = d.proxy_stats || {};
  const readStats = d.read_anomaly_stats || {};
  const lifecycleStats = d.lifecycle_stats || {};
  const integrityStats = d.integrity_stats || {};
  const isolationStats = d.isolation_stats || {};
  const writeAudit = d.write_audit || {};

  return (
    <div style={styles.container}>
      <h1 style={styles.header}>Memory Store Dashboard</h1>
      {error && <div style={styles.error}>{error}</div>}

      {/* Summary Cards */}
      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardTitle}>Total Writes</div>
          <div style={styles.cardValue}>{proxyStats.total_writes || 0}</div>
          <div style={styles.cardSubtext}>Intercepted by firewall</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>Blocked Writes</div>
          <div style={styles.cardValue}>{proxyStats.blocked || 0}</div>
          <div style={styles.cardSubtext}>Malicious content detected</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>Read Anomalies</div>
          <div style={styles.cardValue}>{d.read_anomaly_count || 0}</div>
          <div style={styles.cardSubtext}>Cross-agent: {readStats.cross_agent_reads || 0} | Stale: {readStats.stale_reads || 0}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>Total Evictions</div>
          <div style={styles.cardValue}>{lifecycleStats.total_evictions || 0}</div>
          <div style={styles.cardSubtext}>{lifecycleStats.total_tokens_evicted || 0} tokens evicted</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>Integrity Status</div>
          <div style={styles.cardValue}>
            {d.latest_integrity_check
              ? <span style={styles.badge(d.latest_integrity_check.chain_valid ? 'green' : 'red')}>
                  {d.latest_integrity_check.chain_valid ? 'Valid' : 'Tampered'}
                </span>
              : <span style={styles.badge('yellow')}>Not Checked</span>}
          </div>
          <div style={styles.cardSubtext}>{integrityStats.verification_runs || 0} verification runs</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}>Isolation Blocks</div>
          <div style={styles.cardValue}>{isolationStats.blocked || 0}</div>
          <div style={styles.cardSubtext}>{d.isolation_permission_count || 0} permissions configured</div>
        </div>
      </div>

      {/* Actions */}
      <div style={{ marginBottom: '24px' }}>
        <button style={styles.btn} onClick={runIntegrityCheck}>Run Integrity Verification</button>
        <button style={styles.btn} onClick={() => Promise.all([fetchDashboard(), fetchAnomalies(), fetchIntegrityAlerts()])}>Refresh</button>
      </div>

      {/* Per-Agent Memory Summary */}
      <h2 style={styles.sectionTitle}>Per-Agent Memory Usage</h2>
      {(d.agent_summaries || []).length > 0 ? (
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Agent ID</th>
              <th style={styles.th}>Tokens Used</th>
              <th style={styles.th}>Max Tokens</th>
              <th style={styles.th}>Utilization</th>
              <th style={styles.th}>Entries</th>
              <th style={styles.th}>Writes</th>
            </tr>
          </thead>
          <tbody>
            {(d.agent_summaries || []).map((a, i) => (
              <tr key={i}>
                <td style={styles.td}><strong>{a.agent_id}</strong></td>
                <td style={styles.td}>{a.memory_tokens.toLocaleString()}</td>
                <td style={styles.td}>{a.max_tokens.toLocaleString()}</td>
                <td style={styles.td}>
                  {a.utilization_pct}%
                  <div style={styles.progressBar}>
                    <div style={styles.progressFill(a.utilization_pct)} />
                  </div>
                </td>
                <td style={styles.td}>{a.entry_count}</td>
                <td style={styles.td}>{a.write_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={styles.card}>No agent memory data tracked yet.</div>
      )}

      {/* Read Anomalies */}
      <h2 style={styles.sectionTitle}>Recent Read Anomalies</h2>
      {anomalies.length > 0 ? (
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Time</th>
              <th style={styles.th}>Reader Agent</th>
              <th style={styles.th}>Content Key</th>
              <th style={styles.th}>Type</th>
              <th style={styles.th}>Severity</th>
              <th style={styles.th}>Details</th>
            </tr>
          </thead>
          <tbody>
            {anomalies.map((a, i) => (
              <tr key={i}>
                <td style={styles.td}>{new Date(a.timestamp).toLocaleString()}</td>
                <td style={styles.td}>{a.reader_agent_id}</td>
                <td style={styles.td}>{a.content_key}</td>
                <td style={styles.td}>
                  <span style={styles.badge(a.anomaly_type === 'cross_agent_read' ? 'red' : 'yellow')}>
                    {a.anomaly_type}
                  </span>
                </td>
                <td style={styles.td}>
                  <span style={styles.badge(a.severity === 'high' || a.severity === 'critical' ? 'red' : 'yellow')}>
                    {a.severity}
                  </span>
                </td>
                <td style={styles.td}>{a.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={styles.card}>No read anomalies detected.</div>
      )}

      {/* Integrity Alerts */}
      <h2 style={styles.sectionTitle}>Integrity Alerts</h2>
      {integrityAlerts.length > 0 ? (
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Time</th>
              <th style={styles.th}>Agent</th>
              <th style={styles.th}>Content Key</th>
              <th style={styles.th}>Failure Type</th>
              <th style={styles.th}>Details</th>
            </tr>
          </thead>
          <tbody>
            {integrityAlerts.map((a, i) => (
              <tr key={i}>
                <td style={styles.td}>{new Date(a.timestamp).toLocaleString()}</td>
                <td style={styles.td}>{a.agent_id}</td>
                <td style={styles.td}>{a.content_key}</td>
                <td style={styles.td}>
                  <span style={styles.badge('red')}>{a.failure_type}</span>
                </td>
                <td style={styles.td}>{a.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={styles.card}>No integrity alerts. Memory records are intact.</div>
      )}
    </div>
  );
}
