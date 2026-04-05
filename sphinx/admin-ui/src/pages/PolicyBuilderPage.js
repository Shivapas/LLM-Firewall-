import React, { useState, useEffect, useCallback } from 'react';

const CATEGORIES = [
  'prompt_injection',
  'jailbreak',
  'data_extraction',
  'privilege_escalation',
  'model_manipulation',
  'insecure_output',
  'sensitive_disclosure',
  'denial_of_service',
];

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const ACTIONS = ['block', 'allow', 'rewrite', 'downgrade'];
const STAGES = ['input', 'output', 'rag'];

const API_BASE = process.env.REACT_APP_API_URL || '';

function PolicyBuilderPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [engineStatus, setEngineStatus] = useState(null);
  const [testText, setTestText] = useState('');
  const [testResult, setTestResult] = useState(null);

  const [form, setForm] = useState({
    name: '',
    description: '',
    category: 'prompt_injection',
    severity: 'medium',
    pattern: '',
    action: 'block',
    rewrite_template: '',
    tags: '',
    stage: 'input',
  });

  const fetchRules = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/admin/security-rules`);
      if (!res.ok) throw new Error('Failed to fetch rules');
      const data = await res.json();
      setRules(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchEngineStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/admin/threat-engine/status`);
      if (res.ok) {
        setEngineStatus(await res.json());
      }
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    fetchRules();
    fetchEngineStatus();
  }, [fetchRules, fetchEngineStatus]);

  const resetForm = () => {
    setForm({
      name: '',
      description: '',
      category: 'prompt_injection',
      severity: 'medium',
      pattern: '',
      action: 'block',
      rewrite_template: '',
      tags: '',
      stage: 'input',
    });
    setEditingRule(null);
    setShowForm(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const payload = {
      ...form,
      tags: form.tags ? form.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      rewrite_template: form.rewrite_template || null,
    };

    try {
      let res;
      if (editingRule) {
        res = await fetch(`${API_BASE}/admin/security-rules/${editingRule}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } else {
        res = await fetch(`${API_BASE}/admin/security-rules`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to save rule');
      }

      resetForm();
      fetchRules();
      fetchEngineStatus();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEdit = (rule) => {
    setForm({
      name: rule.name,
      description: rule.description,
      category: rule.category,
      severity: rule.severity,
      pattern: rule.pattern,
      action: rule.action,
      rewrite_template: rule.rewrite_template || '',
      tags: (rule.tags || []).join(', '),
      stage: rule.stage,
    });
    setEditingRule(rule.id);
    setShowForm(true);
  };

  const handleDelete = async (ruleId) => {
    if (!window.confirm('Delete this security rule?')) return;
    try {
      const res = await fetch(`${API_BASE}/admin/security-rules/${ruleId}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error('Failed to delete rule');
      fetchRules();
      fetchEngineStatus();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggleActive = async (rule) => {
    try {
      const res = await fetch(`${API_BASE}/admin/security-rules/${rule.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: !rule.is_active }),
      });
      if (!res.ok) throw new Error('Failed to toggle rule');
      fetchRules();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleTest = async () => {
    if (!testText.trim()) return;
    try {
      const res = await fetch(`${API_BASE}/admin/threat-engine/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: testText }),
      });
      if (res.ok) {
        setTestResult(await res.json());
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const severityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#dc3545';
      case 'high': return '#fd7e14';
      case 'medium': return '#ffc107';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  };

  const actionColor = (action) => {
    switch (action) {
      case 'block': return '#dc3545';
      case 'rewrite': return '#fd7e14';
      case 'downgrade': return '#ffc107';
      case 'allow': return '#28a745';
      default: return '#6c757d';
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <h1>Security Policy Builder</h1>
      <p style={{ color: '#666' }}>
        Create and manage security rules for the Tier 1 Threat Detection Engine.
        Rules use regex patterns to detect prompt injection, jailbreak attempts, and OWASP LLM Top 10 threats.
      </p>

      {/* Engine Status */}
      {engineStatus && (
        <div style={{
          background: '#f8f9fa', border: '1px solid #dee2e6', borderRadius: '8px',
          padding: '16px', marginBottom: '24px'
        }}>
          <h3 style={{ margin: '0 0 8px 0' }}>Threat Engine Status</h3>
          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
            <div><strong>Total Patterns:</strong> {engineStatus.total_patterns}</div>
            <div><strong>Categories:</strong> {engineStatus.categories?.length || 0}</div>
            {engineStatus.severity_counts && Object.entries(engineStatus.severity_counts).map(([sev, count]) => (
              <div key={sev}>
                <span style={{
                  background: severityColor(sev), color: '#fff',
                  padding: '2px 8px', borderRadius: '4px', fontSize: '12px'
                }}>
                  {sev}: {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div style={{ background: '#f8d7da', color: '#721c24', padding: '12px', borderRadius: '4px', marginBottom: '16px' }}>
          {error}
          <button onClick={() => setError(null)} style={{ float: 'right', border: 'none', background: 'none', cursor: 'pointer' }}>x</button>
        </div>
      )}

      {/* Test Scanner */}
      <div style={{
        background: '#f0f7ff', border: '1px solid #b6d4fe', borderRadius: '8px',
        padding: '16px', marginBottom: '24px'
      }}>
        <h3 style={{ margin: '0 0 8px 0' }}>Test Scanner</h3>
        <div style={{ display: 'flex', gap: '8px' }}>
          <textarea
            value={testText}
            onChange={(e) => setTestText(e.target.value)}
            placeholder="Enter text to scan for threats..."
            style={{ flex: 1, minHeight: '60px', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
          />
          <button
            onClick={handleTest}
            style={{
              padding: '8px 16px', background: '#0d6efd', color: '#fff',
              border: 'none', borderRadius: '4px', cursor: 'pointer', alignSelf: 'flex-start'
            }}
          >
            Scan
          </button>
        </div>
        {testResult && (
          <div style={{ marginTop: '12px', fontFamily: 'monospace', fontSize: '13px' }}>
            <div>
              <strong>Risk Level:</strong>{' '}
              <span style={{ color: severityColor(testResult.threat_score?.risk_level) }}>
                {testResult.threat_score?.risk_level}
              </span>
              {' | '}
              <strong>Score:</strong> {testResult.threat_score?.score}
              {' | '}
              <strong>Action:</strong>{' '}
              <span style={{ color: actionColor(testResult.action?.action) }}>
                {testResult.action?.action}
              </span>
              {' | '}
              <strong>Scan Time:</strong> {testResult.threat_score?.scan_time_ms?.toFixed(2)} ms
            </div>
            {testResult.threat_score?.matches?.length > 0 && (
              <div style={{ marginTop: '8px' }}>
                <strong>Matches:</strong>
                <ul style={{ margin: '4px 0', paddingLeft: '20px' }}>
                  {testResult.threat_score.matches.map((m, i) => (
                    <li key={i}>
                      <span style={{ color: severityColor(m.severity) }}>[{m.severity}]</span>{' '}
                      {m.pattern_name} ({m.category})
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Actions Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h2 style={{ margin: 0 }}>Custom Security Rules</h2>
        <button
          onClick={() => { resetForm(); setShowForm(!showForm); }}
          style={{
            padding: '8px 16px', background: '#198754', color: '#fff',
            border: 'none', borderRadius: '4px', cursor: 'pointer'
          }}
        >
          {showForm ? 'Cancel' : '+ New Rule'}
        </button>
      </div>

      {/* Create/Edit Form */}
      {showForm && (
        <form onSubmit={handleSubmit} style={{
          background: '#fff', border: '1px solid #dee2e6', borderRadius: '8px',
          padding: '20px', marginBottom: '24px'
        }}>
          <h3>{editingRule ? 'Edit Rule' : 'Create New Rule'}</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Name</label>
              <input
                required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Category</label>
              <select
                value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              >
                {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Severity</label>
              <select
                value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              >
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Action</label>
              <select
                value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              >
                {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Stage</label>
              <select
                value={form.stage} onChange={(e) => setForm({ ...form, stage: e.target.value })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              >
                {STAGES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Tags (comma-separated)</label>
              <input
                value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })}
                placeholder="owasp-llm01, custom"
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              />
            </div>
          </div>
          <div style={{ marginTop: '12px' }}>
            <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Description</label>
            <input
              value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
              style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
            />
          </div>
          <div style={{ marginTop: '12px' }}>
            <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>
              Regex Pattern <span style={{ color: '#dc3545' }}>*</span>
            </label>
            <input
              required value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })}
              placeholder="(?i)ignore\s+previous\s+instructions"
              style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc', fontFamily: 'monospace' }}
            />
          </div>
          {form.action === 'rewrite' && (
            <div style={{ marginTop: '12px' }}>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Rewrite Template</label>
              <input
                value={form.rewrite_template} onChange={(e) => setForm({ ...form, rewrite_template: e.target.value })}
                placeholder="[Content removed: policy violation]"
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }}
              />
            </div>
          )}
          <button
            type="submit"
            style={{
              marginTop: '16px', padding: '8px 24px', background: '#0d6efd', color: '#fff',
              border: 'none', borderRadius: '4px', cursor: 'pointer'
            }}
          >
            {editingRule ? 'Update Rule' : 'Create Rule'}
          </button>
        </form>
      )}

      {/* Rules Table */}
      {loading ? (
        <p>Loading rules...</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>
              <th style={{ padding: '8px' }}>Name</th>
              <th style={{ padding: '8px' }}>Category</th>
              <th style={{ padding: '8px' }}>Severity</th>
              <th style={{ padding: '8px' }}>Action</th>
              <th style={{ padding: '8px' }}>Stage</th>
              <th style={{ padding: '8px' }}>Active</th>
              <th style={{ padding: '8px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '24px', textAlign: 'center', color: '#666' }}>
                  No custom security rules. Click "+ New Rule" to create one.
                </td>
              </tr>
            ) : (
              rules.map((rule) => (
                <tr key={rule.id} style={{ borderBottom: '1px solid #dee2e6' }}>
                  <td style={{ padding: '8px' }}>
                    <strong>{rule.name}</strong>
                    <div style={{ fontSize: '12px', color: '#666' }}>{rule.description}</div>
                  </td>
                  <td style={{ padding: '8px' }}>{rule.category}</td>
                  <td style={{ padding: '8px' }}>
                    <span style={{
                      background: severityColor(rule.severity), color: '#fff',
                      padding: '2px 8px', borderRadius: '4px', fontSize: '12px'
                    }}>
                      {rule.severity}
                    </span>
                  </td>
                  <td style={{ padding: '8px' }}>
                    <span style={{
                      background: actionColor(rule.action), color: '#fff',
                      padding: '2px 8px', borderRadius: '4px', fontSize: '12px'
                    }}>
                      {rule.action}
                    </span>
                  </td>
                  <td style={{ padding: '8px' }}>{rule.stage}</td>
                  <td style={{ padding: '8px' }}>
                    <button
                      onClick={() => handleToggleActive(rule)}
                      style={{
                        background: rule.is_active ? '#198754' : '#6c757d', color: '#fff',
                        border: 'none', borderRadius: '4px', padding: '2px 8px', cursor: 'pointer',
                        fontSize: '12px'
                      }}
                    >
                      {rule.is_active ? 'ON' : 'OFF'}
                    </button>
                  </td>
                  <td style={{ padding: '8px' }}>
                    <button
                      onClick={() => handleEdit(rule)}
                      style={{
                        marginRight: '4px', padding: '4px 8px', background: '#0d6efd',
                        color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '12px'
                      }}
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(rule.id)}
                      style={{
                        padding: '4px 8px', background: '#dc3545', color: '#fff',
                        border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '12px'
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default PolicyBuilderPage;
