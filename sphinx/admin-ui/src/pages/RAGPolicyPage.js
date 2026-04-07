import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const TOGGLE_FIELDS = [
  { key: 'query_stage_enabled', label: 'Query Stage', group: 'Stages' },
  { key: 'retrieval_stage_enabled', label: 'Retrieval Stage', group: 'Stages' },
  { key: 'generator_stage_enabled', label: 'Generator Stage', group: 'Stages' },
  { key: 'query_threat_detection', label: 'Threat Detection', group: 'Query Stage' },
  { key: 'query_pii_redaction', label: 'PII Redaction', group: 'Query Stage' },
  { key: 'query_intent_classification', label: 'Intent Classification', group: 'Query Stage' },
  { key: 'block_high_risk_intents', label: 'Block High-Risk Intents', group: 'Query Stage' },
  { key: 'scan_retrieved_chunks', label: 'Scan Retrieved Chunks', group: 'Retrieval Stage' },
  { key: 'generator_pii_redaction', label: 'PII Redaction', group: 'Generator Stage' },
  { key: 'generator_threat_detection', label: 'Threat Detection', group: 'Generator Stage' },
];

const DEFAULT_FORM = {
  name: '',
  description: '',
  query_stage_enabled: true,
  retrieval_stage_enabled: true,
  generator_stage_enabled: true,
  query_threat_detection: true,
  query_pii_redaction: true,
  query_intent_classification: true,
  block_high_risk_intents: false,
  max_chunks: 10,
  max_tokens_per_chunk: 512,
  scan_retrieved_chunks: true,
  generator_pii_redaction: true,
  generator_threat_detection: true,
  tenant_id: '*',
};

function RAGPolicyPage() {
  const { apiFetch } = useAuth();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState({ ...DEFAULT_FORM });

  // Test panel state
  const [testQuery, setTestQuery] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testMode, setTestMode] = useState('classify');

  const fetchPolicies = useCallback(async () => {
    try {
      setLoading(true);
      const res = await apiFetch(`/admin/rag-policies`);
      if (!res.ok) throw new Error('Failed to fetch RAG policies');
      setPolicies(await res.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);

  const resetForm = () => {
    setForm({ ...DEFAULT_FORM });
    setEditingId(null);
    setShowForm(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const url = editingId
        ? `/admin/rag-policies/${editingId}`
        : `/admin/rag-policies`;
      const method = editingId ? 'PATCH' : 'POST';
      const res = await apiFetch(url, {
        method,

        body: JSON.stringify(form),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to save RAG policy');
      }
      resetForm();
      fetchPolicies();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEdit = (policy) => {
    setForm({
      name: policy.name,
      description: policy.description,
      query_stage_enabled: policy.query_stage_enabled,
      retrieval_stage_enabled: policy.retrieval_stage_enabled,
      generator_stage_enabled: policy.generator_stage_enabled,
      query_threat_detection: policy.query_threat_detection,
      query_pii_redaction: policy.query_pii_redaction,
      query_intent_classification: policy.query_intent_classification,
      block_high_risk_intents: policy.block_high_risk_intents,
      max_chunks: policy.max_chunks,
      max_tokens_per_chunk: policy.max_tokens_per_chunk,
      scan_retrieved_chunks: policy.scan_retrieved_chunks,
      generator_pii_redaction: policy.generator_pii_redaction,
      generator_threat_detection: policy.generator_threat_detection,
      tenant_id: policy.tenant_id,
    });
    setEditingId(policy.id);
    setShowForm(true);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this RAG policy?')) return;
    try {
      const res = await apiFetch(`/admin/rag-policies/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to delete');
      fetchPolicies();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggle = async (policy) => {
    try {
      const res = await apiFetch(`/admin/rag-policies/${policy.id}`, {
        method: 'PATCH',

        body: JSON.stringify({ is_active: !policy.is_active }),
      });
      if (!res.ok) throw new Error('Failed to toggle');
      fetchPolicies();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleTest = async () => {
    if (!testQuery.trim()) return;
    setTestResult(null);
    try {
      let url, payload;
      if (testMode === 'classify') {
        url = `/admin/rag-pipeline/classify`;
        payload = { body: { messages: [{ role: 'user', content: testQuery }], rag_config: {} } };
      } else if (testMode === 'intent') {
        url = `/admin/rag-pipeline/classify-intent`;
        payload = { query: testQuery };
      } else if (testMode === 'scan') {
        url = `/admin/rag-pipeline/scan-query`;
        payload = { query: testQuery };
      } else {
        url = `/admin/rag-pipeline/process`;
        payload = { body: { messages: [{ role: 'user', content: testQuery }], rag_config: {} } };
      }
      const res = await apiFetch(url, {
        method: 'POST',

        body: JSON.stringify(payload),
      });
      if (res.ok) setTestResult(await res.json());
    } catch (err) {
      setError(err.message);
    }
  };

  const riskColor = (level) => {
    switch (level) {
      case 'high': return '#dc3545';
      case 'medium': return '#ffc107';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <h1>RAG Pipeline Policies</h1>
      <p style={{ color: '#666' }}>
        Configure per-stage security policies for RAG pipelines. Control threat detection,
        PII redaction, and intent classification at the Query, Retrieval, and Generator stages.
      </p>

      {error && (
        <div style={{ background: '#f8d7da', color: '#721c24', padding: '12px', borderRadius: '4px', marginBottom: '16px' }}>
          {error}
          <button onClick={() => setError(null)} style={{ float: 'right', border: 'none', background: 'none', cursor: 'pointer' }}>x</button>
        </div>
      )}

      {/* Test Panel */}
      <div style={{
        background: '#f0f7ff', border: '1px solid #b6d4fe', borderRadius: '8px',
        padding: '16px', marginBottom: '24px'
      }}>
        <h3 style={{ margin: '0 0 8px 0' }}>RAG Pipeline Tester</h3>
        <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
          {['classify', 'intent', 'scan', 'full'].map((m) => (
            <button
              key={m}
              onClick={() => setTestMode(m)}
              style={{
                padding: '4px 12px', border: '1px solid #0d6efd', borderRadius: '4px',
                background: testMode === m ? '#0d6efd' : '#fff',
                color: testMode === m ? '#fff' : '#0d6efd', cursor: 'pointer', fontSize: '13px',
              }}
            >
              {m === 'classify' ? 'Classify Request' : m === 'intent' ? 'Intent' : m === 'scan' ? 'Query Scan' : 'Full Pipeline'}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <textarea
            value={testQuery}
            onChange={(e) => setTestQuery(e.target.value)}
            placeholder="Enter a RAG query to test..."
            style={{ flex: 1, minHeight: '60px', padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
          />
          <button
            onClick={handleTest}
            style={{
              padding: '8px 16px', background: '#0d6efd', color: '#fff',
              border: 'none', borderRadius: '4px', cursor: 'pointer', alignSelf: 'flex-start'
            }}
          >
            Test
          </button>
        </div>
        {testResult && (
          <pre style={{
            marginTop: '12px', background: '#fff', padding: '12px', borderRadius: '4px',
            border: '1px solid #dee2e6', fontSize: '13px', overflow: 'auto', maxHeight: '300px'
          }}>
            {JSON.stringify(testResult, null, 2)}
          </pre>
        )}
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h2 style={{ margin: 0 }}>Policy Configurations</h2>
        <button
          onClick={() => { resetForm(); setShowForm(!showForm); }}
          style={{
            padding: '8px 16px', background: '#198754', color: '#fff',
            border: 'none', borderRadius: '4px', cursor: 'pointer'
          }}
        >
          {showForm ? 'Cancel' : '+ New RAG Policy'}
        </button>
      </div>

      {/* Form */}
      {showForm && (
        <form onSubmit={handleSubmit} style={{
          background: '#fff', border: '1px solid #dee2e6', borderRadius: '8px',
          padding: '20px', marginBottom: '24px'
        }}>
          <h3>{editingId ? 'Edit RAG Policy' : 'Create RAG Policy'}</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Name *</label>
              <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }} />
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Tenant ID</label>
              <input value={form.tenant_id} onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
                placeholder="* (global)"
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }} />
            </div>
          </div>
          <div style={{ marginTop: '12px' }}>
            <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Description</label>
            <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
              style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }} />
          </div>

          {/* Toggle Groups */}
          {['Stages', 'Query Stage', 'Retrieval Stage', 'Generator Stage'].map((group) => (
            <div key={group} style={{ marginTop: '16px' }}>
              <h4 style={{ margin: '0 0 8px 0', color: '#495057' }}>{group}</h4>
              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                {TOGGLE_FIELDS.filter((f) => f.group === group).map((f) => (
                  <label key={f.key} style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={form[f.key]} onChange={(e) => setForm({ ...form, [f.key]: e.target.checked })} />
                    {f.label}
                  </label>
                ))}
              </div>
            </div>
          ))}

          {/* Numeric fields */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '16px' }}>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Max Chunks</label>
              <input type="number" min={1} max={100} value={form.max_chunks}
                onChange={(e) => setForm({ ...form, max_chunks: parseInt(e.target.value) || 10 })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }} />
            </div>
            <div>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '4px' }}>Max Tokens per Chunk</label>
              <input type="number" min={64} max={4096} value={form.max_tokens_per_chunk}
                onChange={(e) => setForm({ ...form, max_tokens_per_chunk: parseInt(e.target.value) || 512 })}
                style={{ width: '100%', padding: '6px', borderRadius: '4px', border: '1px solid #ccc' }} />
            </div>
          </div>

          <button type="submit" style={{
            marginTop: '16px', padding: '8px 24px', background: '#0d6efd', color: '#fff',
            border: 'none', borderRadius: '4px', cursor: 'pointer'
          }}>
            {editingId ? 'Update Policy' : 'Create Policy'}
          </button>
        </form>
      )}

      {/* Policies Table */}
      {loading ? <p>Loading...</p> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>
              <th style={{ padding: '8px' }}>Name</th>
              <th style={{ padding: '8px' }}>Tenant</th>
              <th style={{ padding: '8px' }}>Query</th>
              <th style={{ padding: '8px' }}>Retrieval</th>
              <th style={{ padding: '8px' }}>Generator</th>
              <th style={{ padding: '8px' }}>Active</th>
              <th style={{ padding: '8px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {policies.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '24px', textAlign: 'center', color: '#666' }}>
                  No RAG policies configured. Click "+ New RAG Policy" to create one.
                </td>
              </tr>
            ) : policies.map((p) => (
              <tr key={p.id} style={{ borderBottom: '1px solid #dee2e6' }}>
                <td style={{ padding: '8px' }}>
                  <strong>{p.name}</strong>
                  <div style={{ fontSize: '12px', color: '#666' }}>{p.description}</div>
                </td>
                <td style={{ padding: '8px', fontFamily: 'monospace', fontSize: '13px' }}>{p.tenant_id}</td>
                <td style={{ padding: '8px' }}>
                  <StageIndicator enabled={p.query_stage_enabled}
                    details={[
                      p.query_threat_detection && 'Threat',
                      p.query_pii_redaction && 'PII',
                      p.query_intent_classification && 'Intent',
                    ].filter(Boolean)} />
                </td>
                <td style={{ padding: '8px' }}>
                  <StageIndicator enabled={p.retrieval_stage_enabled}
                    details={[
                      p.scan_retrieved_chunks && 'Chunk Scan',
                      `Max ${p.max_chunks} chunks`,
                    ].filter(Boolean)} />
                </td>
                <td style={{ padding: '8px' }}>
                  <StageIndicator enabled={p.generator_stage_enabled}
                    details={[
                      p.generator_threat_detection && 'Threat',
                      p.generator_pii_redaction && 'PII',
                    ].filter(Boolean)} />
                </td>
                <td style={{ padding: '8px' }}>
                  <button onClick={() => handleToggle(p)} style={{
                    background: p.is_active ? '#198754' : '#6c757d', color: '#fff',
                    border: 'none', borderRadius: '4px', padding: '2px 8px', cursor: 'pointer', fontSize: '12px'
                  }}>
                    {p.is_active ? 'ON' : 'OFF'}
                  </button>
                </td>
                <td style={{ padding: '8px' }}>
                  <button onClick={() => handleEdit(p)} style={{
                    marginRight: '4px', padding: '4px 8px', background: '#0d6efd',
                    color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '12px'
                  }}>Edit</button>
                  <button onClick={() => handleDelete(p.id)} style={{
                    padding: '4px 8px', background: '#dc3545', color: '#fff',
                    border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '12px'
                  }}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function StageIndicator({ enabled, details }) {
  return (
    <div>
      <span style={{
        display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%',
        background: enabled ? '#198754' : '#dc3545', marginRight: '6px'
      }} />
      <span style={{ fontSize: '13px' }}>{enabled ? 'Enabled' : 'Disabled'}</span>
      {enabled && details.length > 0 && (
        <div style={{ fontSize: '11px', color: '#666', marginTop: '2px' }}>
          {details.join(', ')}
        </div>
      )}
    </div>
  );
}

export default RAGPolicyPage;
