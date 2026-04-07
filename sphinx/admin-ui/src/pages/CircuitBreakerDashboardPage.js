/**
 * Sprint 30 — Cascading Failure Circuit Breaker UI
 *
 * Admin UI: per-agent circuit breaker status (closed/open/half-open),
 * anomaly timeline, manual reset, downstream halt event log.
 */

import React, { useState, useEffect, useCallback } from 'react';

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

function CircuitBreakerCard({ breaker, onReset }) {
  const status = breaker.state || 'closed';
  const color = STATUS_COLORS[status] || '#6b7280';

  return (
    <div style={{
      border: `2px solid ${color}`,
      borderRadius: '8px',
      padding: '16px',
      marginBottom: '12px',
      backgroundColor: '#1a1a2e',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, color: '#e0e0e0' }}>
            {breaker.agent_id || breaker.provider_name || 'Unknown'}
          </h3>
          <span style={{
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: '4px',
            backgroundColor: color,
            color: '#fff',
            fontSize: '12px',
            marginTop: '4px',
          }}>
            {STATUS_LABELS[status] || status}
          </span>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ color: '#9ca3af', fontSize: '12px' }}>
            Failures: {breaker.failure_count || 0}
          </div>
          <div style={{ color: '#9ca3af', fontSize: '12px' }}>
            Successes: {breaker.success_count || 0}
          </div>
          {status !== 'closed' && (
            <button
              onClick={() => onReset(breaker.agent_id || breaker.provider_name)}
              style={{
                marginTop: '8px',
                padding: '4px 12px',
                backgroundColor: '#3b82f6',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '12px',
              }}
            >
              Manual Reset
            </button>
          )}
        </div>
      </div>
      {breaker.opened_at && (
        <div style={{ color: '#9ca3af', fontSize: '11px', marginTop: '8px' }}>
          Opened at: {new Date(breaker.opened_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

function AnomalyTimeline({ anomalies }) {
  if (!anomalies || anomalies.length === 0) {
    return <p style={{ color: '#6b7280' }}>No anomalies detected.</p>;
  }

  return (
    <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
      {anomalies.map((a, i) => (
        <div key={i} style={{
          borderLeft: '3px solid #ef4444',
          paddingLeft: '12px',
          marginBottom: '8px',
          fontSize: '13px',
        }}>
          <div style={{ color: '#e0e0e0' }}>
            <strong>{a.anomaly_type || a.event_type || 'anomaly'}</strong>
            {' — '}
            {a.agent_id || 'unknown agent'}
          </div>
          <div style={{ color: '#9ca3af', fontSize: '11px' }}>
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
    return <p style={{ color: '#6b7280' }}>No downstream halt events.</p>;
  }

  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
      <thead>
        <tr style={{ borderBottom: '1px solid #374151' }}>
          <th style={{ textAlign: 'left', padding: '8px', color: '#9ca3af' }}>Time</th>
          <th style={{ textAlign: 'left', padding: '8px', color: '#9ca3af' }}>Agent</th>
          <th style={{ textAlign: 'left', padding: '8px', color: '#9ca3af' }}>Type</th>
          <th style={{ textAlign: 'left', padding: '8px', color: '#9ca3af' }}>State</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #1f2937' }}>
            <td style={{ padding: '6px 8px', color: '#e0e0e0' }}>
              {e.timestamp ? new Date(e.timestamp).toLocaleString() : ''}
            </td>
            <td style={{ padding: '6px 8px', color: '#e0e0e0' }}>{e.agent_id}</td>
            <td style={{ padding: '6px 8px', color: '#e0e0e0' }}>{e.anomaly_type}</td>
            <td style={{ padding: '6px 8px' }}>
              <span style={{
                color: STATUS_COLORS[e.circuit_breaker_state] || '#6b7280',
              }}>
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
  const [breakers, setBreakers] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [haltEvents, setHaltEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [cbRes, anomalyRes, haltRes] = await Promise.all([
        fetch('/api/v1/circuit-breakers').then(r => r.json()).catch(() => []),
        fetch('/api/v1/anomalies?limit=50').then(r => r.json()).catch(() => []),
        fetch('/api/v1/anomalies?limit=50').then(r => r.json()).catch(() => []),
      ]);
      setBreakers(Array.isArray(cbRes) ? cbRes : cbRes.breakers || []);
      setAnomalies(Array.isArray(anomalyRes) ? anomalyRes : anomalyRes.anomalies || []);
      setHaltEvents(Array.isArray(haltRes) ? haltRes : haltRes.events || []);
    } catch (err) {
      console.error('Failed to fetch circuit breaker data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleReset = async (agentId) => {
    try {
      await fetch(`/api/v1/agents/${agentId}/circuit-breaker`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: 'closed' }),
      });
      fetchData();
    } catch (err) {
      console.error('Failed to reset circuit breaker:', err);
    }
  };

  if (loading) {
    return <div style={{ color: '#e0e0e0', padding: '24px' }}>Loading circuit breaker data...</div>;
  }

  return (
    <div style={{ padding: '24px', color: '#e0e0e0', maxWidth: '1200px', margin: '0 auto' }}>
      <h1 style={{ fontSize: '24px', marginBottom: '24px' }}>
        Circuit Breaker Dashboard
      </h1>

      {/* Summary */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '24px' }}>
        {['closed', 'open', 'half_open'].map(state => {
          const count = breakers.filter(b => (b.state || 'closed') === state).length;
          return (
            <div key={state} style={{
              flex: 1,
              padding: '16px',
              borderRadius: '8px',
              backgroundColor: '#1a1a2e',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: '28px', fontWeight: 'bold', color: STATUS_COLORS[state] }}>
                {count}
              </div>
              <div style={{ fontSize: '12px', color: '#9ca3af' }}>
                {STATUS_LABELS[state]}
              </div>
            </div>
          );
        })}
      </div>

      {/* Circuit Breakers */}
      <h2 style={{ fontSize: '18px', marginBottom: '12px' }}>Per-Agent Circuit Breakers</h2>
      {breakers.length === 0 ? (
        <p style={{ color: '#6b7280' }}>No circuit breakers registered.</p>
      ) : (
        breakers.map((b, i) => (
          <CircuitBreakerCard key={i} breaker={b} onReset={handleReset} />
        ))
      )}

      {/* Anomaly Timeline */}
      <h2 style={{ fontSize: '18px', marginTop: '32px', marginBottom: '12px' }}>
        Anomaly Timeline
      </h2>
      <AnomalyTimeline anomalies={anomalies} />

      {/* Halt Event Log */}
      <h2 style={{ fontSize: '18px', marginTop: '32px', marginBottom: '12px' }}>
        Downstream Halt Event Log
      </h2>
      <HaltEventLog events={haltEvents} />
    </div>
  );
}
