import React, { useState, useEffect, useCallback } from 'react';

const CONDITION_TYPES = ['sensitivity', 'budget', 'compliance_tag', 'kill_switch', 'composite'];
const ACTIONS = ['route', 'downgrade', 'block'];
const API_BASE = process.env.REACT_APP_API_URL || '';

function RoutingRulesPage() {
  const [rules, setRules] = useState([]);
  const [tiers, setTiers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [showTierForm, setShowTierForm] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [policyStatus, setPolicyStatus] = useState(null);
  const [activeTab, setActiveTab] = useState('rules');

  const [ruleForm, setRuleForm] = useState({
    name: '',
    description: '',
    priority: 100,
    condition_type: 'sensitivity',
    condition_json: '{"tags": ["PII", "PHI"], "operator": "any"}',
    target_model: '',
    target_provider: '',
    action: 'route',
    tenant_id: '*',
    is_active: true,
  });

  const [tierForm, setTierForm] = useState({
    model_name: '',
    tier_name: 'standard',
    token_budget: 1000000,
    downgrade_model: '',
    budget_window_seconds: 3600,
    tenant_id: '*',
  });

  const fetchRules = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/admin/routing-rules`);
      if (!res.ok) throw new Error('Failed to fetch routing rules');
      const data = await res.json();
      setRules(data.rules || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchTiers = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/admin/budget-tiers`);
      if (!res.ok) throw new Error('Failed to fetch budget tiers');
      const data = await res.json();
      setTiers(data.tiers || []);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/admin/routing-policy/status`);
      if (res.ok) {
        setPolicyStatus(await res.json());
      }
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    fetchRules();
    fetchTiers();
    fetchStatus();
  }, [fetchRules, fetchTiers, fetchStatus]);

  const resetRuleForm = () => {
    setRuleForm({
      name: '',
      description: '',
      priority: 100,
      condition_type: 'sensitivity',
      condition_json: '{"tags": ["PII", "PHI"], "operator": "any"}',
      target_model: '',
      target_provider: '',
      action: 'route',
      tenant_id: '*',
      is_active: true,
    });
    setEditingRule(null);
  };

  const handleCreateRule = async (e) => {
    e.preventDefault();
    try {
      const method = editingRule ? 'PUT' : 'POST';
      const url = editingRule
        ? `${API_BASE}/admin/routing-rules/${editingRule.id}`
        : `${API_BASE}/admin/routing-rules`;
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ruleForm),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Failed to save rule');
      }
      resetRuleForm();
      setShowRuleForm(false);
      fetchRules();
      fetchStatus();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleEditRule = (rule) => {
    setRuleForm({
      name: rule.name,
      description: rule.description || '',
      priority: rule.priority,
      condition_type: rule.condition_type,
      condition_json: rule.condition_json,
      target_model: rule.target_model,
      target_provider: rule.target_provider || '',
      action: rule.action,
      tenant_id: rule.tenant_id || '*',
      is_active: rule.is_active,
    });
    setEditingRule(rule);
    setShowRuleForm(true);
  };

  const handleDeleteRule = async (ruleId) => {
    if (!window.confirm('Delete this routing rule?')) return;
    try {
      const res = await fetch(`${API_BASE}/admin/routing-rules/${ruleId}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error('Failed to delete rule');
      fetchRules();
      fetchStatus();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleCreateTier = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_BASE}/admin/budget-tiers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(tierForm),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Failed to create tier');
      }
      setTierForm({
        model_name: '',
        tier_name: 'standard',
        token_budget: 1000000,
        downgrade_model: '',
        budget_window_seconds: 3600,
        tenant_id: '*',
      });
      setShowTierForm(false);
      fetchTiers();
      fetchStatus();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDeleteTier = async (tierId) => {
    if (!window.confirm('Delete this budget tier?')) return;
    try {
      const res = await fetch(`${API_BASE}/admin/budget-tiers/${tierId}`, {
        method: 'DELETE',
      });
      if (!res.ok) throw new Error('Failed to delete tier');
      fetchTiers();
      fetchStatus();
    } catch (err) {
      setError(err.message);
    }
  };

  const conditionPresets = {
    sensitivity: '{"tags": ["PII", "PHI"], "operator": "any"}',
    budget: '{"budget_exceeded": true}',
    compliance_tag: '{"tags": ["REGULATED", "CONFIDENTIAL"], "operator": "any"}',
    kill_switch: '{}',
    composite: '{"operator": "and", "conditions": [{"type": "sensitivity", "condition": {"tags": ["PII"], "operator": "any"}}, {"type": "budget", "condition": {"budget_exceeded": true}}]}',
  };

  if (loading) return <div style={styles.loading}>Loading routing rules...</div>;

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>Routing Rules & Budget Tiers</h1>

      {error && (
        <div style={styles.error}>
          {error}
          <button onClick={() => setError(null)} style={styles.dismissBtn}>Dismiss</button>
        </div>
      )}

      {policyStatus && (
        <div style={styles.statusBar}>
          <span><strong>Rules loaded:</strong> {policyStatus.routing_rules_loaded}</span>
          <span><strong>Budget tiers:</strong> {policyStatus.budget_tiers_loaded}</span>
          <span><strong>Private model:</strong> {policyStatus.private_model}</span>
          <span><strong>Public model:</strong> {policyStatus.public_model}</span>
        </div>
      )}

      <div style={styles.tabs}>
        <button
          style={activeTab === 'rules' ? styles.activeTab : styles.tab}
          onClick={() => setActiveTab('rules')}
        >
          Routing Rules ({rules.length})
        </button>
        <button
          style={activeTab === 'tiers' ? styles.activeTab : styles.tab}
          onClick={() => setActiveTab('tiers')}
        >
          Budget Tiers ({tiers.length})
        </button>
      </div>

      {activeTab === 'rules' && (
        <div>
          <button
            style={styles.addBtn}
            onClick={() => { resetRuleForm(); setShowRuleForm(!showRuleForm); }}
          >
            {showRuleForm ? 'Cancel' : '+ Add Routing Rule'}
          </button>

          {showRuleForm && (
            <form onSubmit={handleCreateRule} style={styles.form}>
              <h3>{editingRule ? 'Edit Rule' : 'New Routing Rule'}</h3>
              <div style={styles.formGrid}>
                <label style={styles.label}>
                  Name
                  <input
                    style={styles.input}
                    value={ruleForm.name}
                    onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                    required
                  />
                </label>
                <label style={styles.label}>
                  Priority (lower = higher)
                  <input
                    style={styles.input}
                    type="number"
                    value={ruleForm.priority}
                    onChange={(e) => setRuleForm({ ...ruleForm, priority: parseInt(e.target.value) || 0 })}
                  />
                </label>
                <label style={styles.label}>
                  Condition Type
                  <select
                    style={styles.input}
                    value={ruleForm.condition_type}
                    onChange={(e) => {
                      const ct = e.target.value;
                      setRuleForm({
                        ...ruleForm,
                        condition_type: ct,
                        condition_json: conditionPresets[ct] || '{}',
                      });
                    }}
                  >
                    {CONDITION_TYPES.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </label>
                <label style={styles.label}>
                  Action
                  <select
                    style={styles.input}
                    value={ruleForm.action}
                    onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value })}
                  >
                    {ACTIONS.map((a) => (
                      <option key={a} value={a}>{a}</option>
                    ))}
                  </select>
                </label>
                <label style={styles.label}>
                  Target Model
                  <input
                    style={styles.input}
                    value={ruleForm.target_model}
                    onChange={(e) => setRuleForm({ ...ruleForm, target_model: e.target.value })}
                    placeholder="e.g. llama-3.1-70b"
                  />
                </label>
                <label style={styles.label}>
                  Target Provider
                  <input
                    style={styles.input}
                    value={ruleForm.target_provider}
                    onChange={(e) => setRuleForm({ ...ruleForm, target_provider: e.target.value })}
                    placeholder="e.g. llama, openai"
                  />
                </label>
                <label style={styles.label}>
                  Tenant ID
                  <input
                    style={styles.input}
                    value={ruleForm.tenant_id}
                    onChange={(e) => setRuleForm({ ...ruleForm, tenant_id: e.target.value })}
                    placeholder="* for global"
                  />
                </label>
                <label style={styles.label}>
                  Active
                  <input
                    type="checkbox"
                    checked={ruleForm.is_active}
                    onChange={(e) => setRuleForm({ ...ruleForm, is_active: e.target.checked })}
                  />
                </label>
              </div>
              <label style={styles.label}>
                Description
                <input
                  style={styles.input}
                  value={ruleForm.description}
                  onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })}
                />
              </label>
              <label style={styles.label}>
                Condition JSON
                <textarea
                  style={styles.textarea}
                  value={ruleForm.condition_json}
                  onChange={(e) => setRuleForm({ ...ruleForm, condition_json: e.target.value })}
                  rows={4}
                />
              </label>
              <button type="submit" style={styles.submitBtn}>
                {editingRule ? 'Update Rule' : 'Create Rule'}
              </button>
            </form>
          )}

          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Priority</th>
                <th style={styles.th}>Name</th>
                <th style={styles.th}>Condition</th>
                <th style={styles.th}>Action</th>
                <th style={styles.th}>Target Model</th>
                <th style={styles.th}>Tenant</th>
                <th style={styles.th}>Active</th>
                <th style={styles.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} style={rule.is_active ? {} : styles.inactiveRow}>
                  <td style={styles.td}>{rule.priority}</td>
                  <td style={styles.td}>
                    <strong>{rule.name}</strong>
                    {rule.description && <div style={styles.desc}>{rule.description}</div>}
                  </td>
                  <td style={styles.td}>
                    <span style={styles.badge}>{rule.condition_type}</span>
                    <code style={styles.code}>{rule.condition_json}</code>
                  </td>
                  <td style={styles.td}>
                    <span style={{
                      ...styles.badge,
                      background: rule.action === 'block' ? '#e74c3c' :
                        rule.action === 'downgrade' ? '#f39c12' : '#27ae60',
                    }}>
                      {rule.action}
                    </span>
                  </td>
                  <td style={styles.td}>{rule.target_model || '-'}</td>
                  <td style={styles.td}>{rule.tenant_id}</td>
                  <td style={styles.td}>{rule.is_active ? 'Yes' : 'No'}</td>
                  <td style={styles.td}>
                    <button style={styles.editBtn} onClick={() => handleEditRule(rule)}>Edit</button>
                    <button style={styles.deleteBtn} onClick={() => handleDeleteRule(rule.id)}>Delete</button>
                  </td>
                </tr>
              ))}
              {rules.length === 0 && (
                <tr>
                  <td colSpan={8} style={styles.empty}>No routing rules configured. Add one to get started.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'tiers' && (
        <div>
          <button
            style={styles.addBtn}
            onClick={() => setShowTierForm(!showTierForm)}
          >
            {showTierForm ? 'Cancel' : '+ Add Budget Tier'}
          </button>

          {showTierForm && (
            <form onSubmit={handleCreateTier} style={styles.form}>
              <h3>New Budget Tier</h3>
              <div style={styles.formGrid}>
                <label style={styles.label}>
                  Model Name
                  <input
                    style={styles.input}
                    value={tierForm.model_name}
                    onChange={(e) => setTierForm({ ...tierForm, model_name: e.target.value })}
                    placeholder="e.g. gpt-4o"
                    required
                  />
                </label>
                <label style={styles.label}>
                  Tier Name
                  <input
                    style={styles.input}
                    value={tierForm.tier_name}
                    onChange={(e) => setTierForm({ ...tierForm, tier_name: e.target.value })}
                  />
                </label>
                <label style={styles.label}>
                  Token Budget
                  <input
                    style={styles.input}
                    type="number"
                    value={tierForm.token_budget}
                    onChange={(e) => setTierForm({ ...tierForm, token_budget: parseInt(e.target.value) || 0 })}
                  />
                </label>
                <label style={styles.label}>
                  Downgrade Model
                  <input
                    style={styles.input}
                    value={tierForm.downgrade_model}
                    onChange={(e) => setTierForm({ ...tierForm, downgrade_model: e.target.value })}
                    placeholder="e.g. gpt-3.5-turbo"
                  />
                </label>
                <label style={styles.label}>
                  Budget Window (seconds)
                  <input
                    style={styles.input}
                    type="number"
                    value={tierForm.budget_window_seconds}
                    onChange={(e) => setTierForm({ ...tierForm, budget_window_seconds: parseInt(e.target.value) || 3600 })}
                  />
                </label>
                <label style={styles.label}>
                  Tenant ID
                  <input
                    style={styles.input}
                    value={tierForm.tenant_id}
                    onChange={(e) => setTierForm({ ...tierForm, tenant_id: e.target.value })}
                    placeholder="* for global"
                  />
                </label>
              </div>
              <button type="submit" style={styles.submitBtn}>Create Tier</button>
            </form>
          )}

          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Model</th>
                <th style={styles.th}>Tier</th>
                <th style={styles.th}>Token Budget</th>
                <th style={styles.th}>Downgrade To</th>
                <th style={styles.th}>Window</th>
                <th style={styles.th}>Tenant</th>
                <th style={styles.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tiers.map((tier) => (
                <tr key={tier.id}>
                  <td style={styles.td}><strong>{tier.model_name}</strong></td>
                  <td style={styles.td}>{tier.tier_name}</td>
                  <td style={styles.td}>{tier.token_budget.toLocaleString()}</td>
                  <td style={styles.td}>{tier.downgrade_model || '-'}</td>
                  <td style={styles.td}>{tier.budget_window_seconds}s</td>
                  <td style={styles.td}>{tier.tenant_id}</td>
                  <td style={styles.td}>
                    <button style={styles.deleteBtn} onClick={() => handleDeleteTier(tier.id)}>Delete</button>
                  </td>
                </tr>
              ))}
              {tiers.length === 0 && (
                <tr>
                  <td colSpan={7} style={styles.empty}>No budget tiers configured.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: { padding: '24px', maxWidth: '1200px', margin: '0 auto' },
  title: { fontSize: '24px', marginBottom: '16px', color: '#1a1a2e' },
  loading: { padding: '40px', textAlign: 'center', color: '#666' },
  error: {
    padding: '12px 16px', background: '#ffeaea', color: '#c0392b', borderRadius: '6px',
    marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
  },
  dismissBtn: { background: 'none', border: 'none', color: '#c0392b', cursor: 'pointer', fontWeight: 'bold' },
  statusBar: {
    display: 'flex', gap: '24px', padding: '12px 16px', background: '#f0f4ff',
    borderRadius: '6px', marginBottom: '16px', fontSize: '14px', flexWrap: 'wrap',
  },
  tabs: { display: 'flex', gap: '4px', marginBottom: '16px' },
  tab: {
    padding: '8px 20px', border: '1px solid #ddd', background: '#f9f9f9',
    borderRadius: '6px 6px 0 0', cursor: 'pointer', fontSize: '14px',
  },
  activeTab: {
    padding: '8px 20px', border: '1px solid #3498db', background: '#3498db',
    color: '#fff', borderRadius: '6px 6px 0 0', cursor: 'pointer', fontSize: '14px',
  },
  addBtn: {
    padding: '8px 16px', background: '#27ae60', color: '#fff', border: 'none',
    borderRadius: '6px', cursor: 'pointer', marginBottom: '16px', fontSize: '14px',
  },
  form: {
    padding: '20px', background: '#f9f9f9', borderRadius: '8px',
    marginBottom: '20px', border: '1px solid #ddd',
  },
  formGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' },
  label: { display: 'flex', flexDirection: 'column', fontSize: '13px', color: '#555', gap: '4px' },
  input: {
    padding: '8px 10px', border: '1px solid #ccc', borderRadius: '4px',
    fontSize: '14px', width: '100%', boxSizing: 'border-box',
  },
  textarea: {
    padding: '8px 10px', border: '1px solid #ccc', borderRadius: '4px',
    fontSize: '13px', fontFamily: 'monospace', width: '100%', boxSizing: 'border-box',
  },
  submitBtn: {
    padding: '10px 24px', background: '#3498db', color: '#fff', border: 'none',
    borderRadius: '6px', cursor: 'pointer', fontSize: '14px', marginTop: '8px',
  },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: '14px' },
  th: {
    textAlign: 'left', padding: '10px 12px', borderBottom: '2px solid #ddd',
    background: '#f5f5f5', color: '#333', fontSize: '13px',
  },
  td: { padding: '10px 12px', borderBottom: '1px solid #eee', verticalAlign: 'top' },
  inactiveRow: { opacity: 0.5, background: '#fafafa' },
  badge: {
    display: 'inline-block', padding: '2px 8px', borderRadius: '10px',
    fontSize: '12px', background: '#3498db', color: '#fff', marginRight: '4px',
  },
  code: {
    display: 'block', marginTop: '4px', fontSize: '11px', background: '#f0f0f0',
    padding: '4px 6px', borderRadius: '3px', wordBreak: 'break-all', maxWidth: '300px',
  },
  desc: { fontSize: '12px', color: '#888', marginTop: '2px' },
  editBtn: {
    padding: '4px 10px', background: '#f39c12', color: '#fff', border: 'none',
    borderRadius: '4px', cursor: 'pointer', marginRight: '4px', fontSize: '12px',
  },
  deleteBtn: {
    padding: '4px 10px', background: '#e74c3c', color: '#fff', border: 'none',
    borderRadius: '4px', cursor: 'pointer', fontSize: '12px',
  },
  empty: { textAlign: 'center', padding: '24px', color: '#999' },
};

export default RoutingRulesPage;
