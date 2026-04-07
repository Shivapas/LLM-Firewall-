/**
 * Sprint 30 — Cascading Failure Circuit Breaker UI
 *
 * Admin UI: per-agent circuit breaker status (closed/open/half-open),
 * anomaly timeline, manual reset, downstream halt event log.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const STATUS_COLORS = {
  closed: '#22c55e',
  open: '#ef4444',
  half_open: '#f59e0b',
};

const STATUS_LABELS = {
  closed: 'Closed (Healthy)',
  open: 'Open (Blocked)',
  half_open: 'Half-Open (Probing)',
};

const styles = {
  page: { padding: '24px', maxWidth: '1200px', margin: '0 auto' },
  title: { fontSize: '24px', fontWeight: 700, marginBottom: '24px', color: '#1a1a2e' },
  summaryGrid: { display: 'flex', gap: '16px', marginBottom: '24px' },
  summaryCard: {
    flex: 1, padding: '16px', borderRadius: '8px',
    backgroundColor: '#fff', textAlign: 'center',
    boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
  },
  sectionTitle: { fontSize: '18px', fontWeight: 600, marginBottom: '12px', marginTop: '32px', color: '#1a1a2e' },
  card: {
    border: '2px solid #e0e0e0', borderRadius: '8px', padding: '16px',
    marginBottom: '12px', backgroundColor: '#fff',
  },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: '13px', background: '#fff', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' },
  th: { textAlign: 'left', padding: '10px 12px', borderBottom: '2px solid #e0e0e0', fontSize: '12px', color: '#666', fontWeight: 600, textTransform: 'uppercase' },
  td: { padding: '8px 12px', borderBottom: '1px solid #f0f0f0', fontSize: '13px', color: '#333' },
  badge: (color) => ({
    display: 'inline-block', padding: '2px 8px', borderRadius: '4px',
    backgroundColor: color, color: '#fff', fontSize: '12px',
  }),
  timelineItem: {
    borderLeft: '3px solid #ef4444', paddingLeft: '12px',
    marginBottom: '8px', fontSize: '13px',
  },
  resetBtn: {
    marginTop: '8px', padding: '4px 12px', backgroundColor: '#3b82f6',
    color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '12px',
  },
  empty: { color: '#999', textAlign: 'center', padding: '24px' },
};

function CircuitBreakerCard({ breaker, onReset }) {
  const status = breaker.state || 'closed';
  const color = STATUS_COLORS[status] || '#6b7280';

  return (
    <div style={{ ...styles.card, borderColor: color }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, color: '#1a1a2e' }}>
            {breaker.agent_id || breaker.provider_name || 'Unknown'}
          </h3>
          <span style={styles.badge(color)}>
            {STATUS_LABELS[status] || status}
          </span>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ color: '#666', fontSize: '12px' }}>
            Failures: {breaker.failure_count || 0}
          </div>
          <div style={{ color: '#666', fontSize: '12px' }}>
            Successes: {breaker.success_count || 0}
          </div>
          {status !== 'closed' && (
            <button onClick={() => onReset(breaker.agent_id || breaker.provider_name)} style={styles.resetBtn}>
              Manual Reset
            </button>
          )}
        </div>
      </div>
      {breaker.opened_at && (
        <div style={{ color: '#888', fontSize: '11px', marginTop: '8px' }}>
          Opened at: {new Date(breaker.opened_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

function AnomalyTimeline({ anomalies }) {
  if (!anomalies || anomalies.length === 0) {
    return <p style={styles.empty}>No anomalies detected.</p>;
  }

  return (
    <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
      {anomalies.map((a, i) => (
        <div key={i} style={styles.timelineItem}>
          <div style={{ color: '#1a1a2e' }}>
            <strong>{a.anomaly_type || a.event_type || 'anomaly'}</strong>
            {' — '}
            {a.agent_id || 'unknown agent'}
          </div>
          <div style={{ color: '#888', fontSize: '11px' }}>
            Deviation: {(a.deviation_score || 0).toFixed(2)} |
            Circuit: {a.circuit_breaker_state || 'N/A'} |
            {a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}
          </div>
        </div>
      ))}
    </div>
  );
}

function HaltEventLog({ events }) {
  if (!events || events.length === 0) {
    return <p style={styles.empty}>No downstream halt events.</p>;
  }

  return (
    <table style={styles.table}>
      <thead>
        <tr>
          <th style={styles.th}>Time</th>
          <th style={styles.th}>Agent</th>
          <th style={styles.th}>Type</th>
          <th style={styles.th}>State</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={i}>
            <td style={styles.td}>
              {e.timestamp ? new Date(e.timestamp).toLocaleString() : ''}
            </td>
            <td style={styles.td}>{e.agent_id}</td>
            <td style={styles.td}>{e.anomaly_type}</td>
            <td style={styles.td}>
              <span style={styles.badge(STATUS_COLORS[e.circuit_breaker_state] || '#6b7280')}>
                {e.circuit_breaker_state}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function CircuitBreakerDashboardPage() {
  const { apiFetch } = useAuth();
  const [breakers, setBreakers] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [haltEvents, setHaltEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [cbRes, anomalyRes, haltRes] = await Promise.all([
        apiFetch('/admin/circuit-breakers').then(r => r.ok ? r.json() : []).catch(() => []),
        apiFetch('/admin/anomalies?limit=50').then(r => r.ok ? r.json() : []).catch(() => []),
        apiFetch('/admin/halt-events?limit=50').then(r => r.ok ? r.json() : []).catch(() => []),
      ]);
      setBreakers(Array.isArray(cbRes) ? cbRes : cbRes.breakers || []);
      setAnomalies(Array.isArray(anomalyRes) ? anomalyRes : anomalyRes.anomalies || []);
      setHaltEvents(Array.isArray(haltRes) ? haltRes : haltRes.events || []);
    } catch (err) {
      console.error('Failed to fetch circuit breaker data:', err);
    } finally {
      setLoading(false);
    }
  }, [apiFetch]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleReset = async (agentId) => {
    try {
      await apiFetch(`/admin/agents/${agentId}/circuit-breaker`, {
        method: 'POST',
        body: JSON.stringify({ state: 'closed' }),
      });
      fetchData();
    } catch (err) {
      console.error('Failed to reset circuit breaker:', err);
    }
  };

  if (loading) {
    return <div style={styles.page}><p>Loading circuit breaker data...</p></div>;
  }

  return (
    <div style={styles.page}>
      <h1 style={styles.title}>Circuit Breaker Dashboard</h1>

      {/* Summary */}
      <div style={styles.summaryGrid}>
        {['closed', 'open', 'half_open'].map(state => {
          const count = breakers.filter(b => (b.state || 'closed') === state).length;
          return (
            <div key={state} style={styles.summaryCard}>
              <div style={{ fontSize: '28px', fontWeight: 'bold', color: STATUS_COLORS[state] }}>
                {count}
              </div>
              <div style={{ fontSize: '12px', color: '#666' }}>
                {STATUS_LABELS[state]}
              </div>
            </div>
          );
        })}
      </div>

      {/* Circuit Breakers */}
      <h2 style={styles.sectionTitle}>Per-Agent Circuit Breakers</h2>
      {breakers.length === 0 ? (
        <p style={styles.empty}>No circuit breakers registered.</p>
      ) : (
        breakers.map((b, i) => (
          <CircuitBreakerCard key={i} breaker={b} onReset={handleReset} />
        ))
      )}

      {/* Anomaly Timeline */}
      <h2 style={styles.sectionTitle}>Anomaly Timeline</h2>
      <AnomalyTimeline anomalies={anomalies} />

      {/* Halt Event Log */}
      <h2 style={styles.sectionTitle}>Downstream Halt Event Log</h2>
      <HaltEventLog events={haltEvents} />
    </div>
  );
}
