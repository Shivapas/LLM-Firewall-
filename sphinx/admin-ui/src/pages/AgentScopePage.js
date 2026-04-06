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
    badge: (active) => ({
        display: 'inline-block', padding: '2px 10px', borderRadius: 12,
        background: active ? '#27ae60' : '#e74c3c', color: '#fff', fontWeight: 600, fontSize: 12,
    }),
    section: { marginTop: 32 },
    sectionTitle: { fontSize: 18, fontWeight: 600, marginBottom: 12 },
    card: { background: '#fff', borderRadius: 8, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.1)', marginBottom: 16 },
    form: { display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'flex-end' },
    input: { padding: '8px 12px', border: '1px solid #ddd', borderRadius: 4, fontSize: 14 },
    label: { fontSize: 13, fontWeight: 600, marginBottom: 4, display: 'block' },
    fieldGroup: { display: 'flex', flexDirection: 'column' },
    tagList: { display: 'flex', gap: 4, flexWrap: 'wrap' },
    tag: { display: 'inline-block', padding: '2px 8px', borderRadius: 4, background: '#e3f2fd', color: '#1565c0', fontSize: 12 },
    empty: { textAlign: 'center', color: '#999', padding: 40 },
    violationRow: { fontSize: 13, borderTop: '1px solid #f0f0f0', padding: '8px 0' },
};

export default function AgentScopePage() {
    const [agents, setAgents] = useState([]);
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [violations, setViolations] = useState([]);
    const [violationCounts, setViolationCounts] = useState({});
    const [loading, setLoading] = useState(false);

    // Form state
    const [formAgentId, setFormAgentId] = useState('');
    const [formDisplayName, setFormDisplayName] = useState('');
    const [formDescription, setFormDescription] = useState('');
    const [formServers, setFormServers] = useState('');
    const [formTools, setFormTools] = useState('');
    const [formScope, setFormScope] = useState('');
    const [formRedactFields, setFormRedactFields] = useState('');

    const fetchAgents = useCallback(async () => {
        try {
            const res = await fetch('/admin/agents');
            if (res.ok) setAgents(await res.json());
        } catch (e) { console.error('Failed to fetch agents', e); }
    }, []);

    useEffect(() => { fetchAgents(); }, [fetchAgents]);

    const createAgent = async () => {
        if (!formAgentId) return;
        setLoading(true);
        try {
            const res = await fetch('/admin/agents', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    agent_id: formAgentId,
                    display_name: formDisplayName || formAgentId,
                    description: formDescription,
                    allowed_mcp_servers: formServers ? formServers.split(',').map(s => s.trim()) : [],
                    allowed_tools: formTools ? formTools.split(',').map(s => s.trim()) : [],
                    context_scope: formScope ? formScope.split(',').map(s => s.trim()) : [],
                    redact_fields: formRedactFields ? formRedactFields.split(',').map(s => s.trim()) : [],
                }),
            });
            if (res.ok) {
                setFormAgentId(''); setFormDisplayName(''); setFormDescription('');
                setFormServers(''); setFormTools(''); setFormScope(''); setFormRedactFields('');
                fetchAgents();
            }
        } catch (e) { console.error('Failed to create agent', e); }
        setLoading(false);
    };

    const deleteAgent = async (agentId) => {
        if (!window.confirm(`Delete agent "${agentId}"?`)) return;
        try {
            await fetch(`/admin/agents/${agentId}`, { method: 'DELETE' });
            if (selectedAgent === agentId) { setSelectedAgent(null); setViolations([]); }
            fetchAgents();
        } catch (e) { console.error('Failed to delete agent', e); }
    };

    const toggleActive = async (agent) => {
        try {
            await fetch(`/admin/agents/${agent.agent_id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active: !agent.is_active }),
            });
            fetchAgents();
        } catch (e) { console.error('Failed to toggle agent', e); }
    };

    const selectAgent = async (agentId) => {
        setSelectedAgent(agentId);
        try {
            const [vRes, cRes] = await Promise.all([
                fetch(`/admin/agents/${agentId}/violations?limit=50`),
                fetch(`/admin/agents/${agentId}/violation-counts`),
            ]);
            if (vRes.ok) setViolations(await vRes.json());
            if (cRes.ok) setViolationCounts(await cRes.json());
        } catch (e) { console.error('Failed to fetch violations', e); }
    };

    const splitTags = (arr) => (arr || []).length > 0
        ? arr.map((t, i) => <span key={i} style={styles.tag}>{t}</span>)
        : <span style={{ color: '#999', fontSize: 12 }}>none</span>;

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <div style={styles.title}>Agent Service Accounts</div>
            </div>

            {/* Create Form */}
            <div style={styles.card}>
                <div style={styles.sectionTitle}>Create Agent Account</div>
                <div style={styles.form}>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Agent ID</label>
                        <input style={styles.input} placeholder="agent-id" value={formAgentId} onChange={e => setFormAgentId(e.target.value)} />
                    </div>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Display Name</label>
                        <input style={styles.input} placeholder="Display Name" value={formDisplayName} onChange={e => setFormDisplayName(e.target.value)} />
                    </div>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Description</label>
                        <input style={styles.input} placeholder="Description" value={formDescription} onChange={e => setFormDescription(e.target.value)} />
                    </div>
                </div>
                <div style={styles.form}>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Allowed MCP Servers (comma-separated)</label>
                        <input style={{ ...styles.input, width: 250 }} placeholder="server-a, server-b" value={formServers} onChange={e => setFormServers(e.target.value)} />
                    </div>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Allowed Tools (comma-separated)</label>
                        <input style={{ ...styles.input, width: 250 }} placeholder="read_file, search" value={formTools} onChange={e => setFormTools(e.target.value)} />
                    </div>
                </div>
                <div style={styles.form}>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Context Scope (comma-separated tags)</label>
                        <input style={{ ...styles.input, width: 250 }} placeholder="finance, public" value={formScope} onChange={e => setFormScope(e.target.value)} />
                    </div>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>Redact Fields (comma-separated)</label>
                        <input style={{ ...styles.input, width: 250 }} placeholder="ssn, email, credit_card" value={formRedactFields} onChange={e => setFormRedactFields(e.target.value)} />
                    </div>
                    <div style={styles.fieldGroup}>
                        <label style={styles.label}>&nbsp;</label>
                        <button style={styles.btn} onClick={createAgent} disabled={loading}>Create Agent</button>
                    </div>
                </div>
            </div>

            {/* Agents Table */}
            {agents.length === 0 ? (
                <div style={styles.empty}>No agent service accounts configured.</div>
            ) : (
                <table style={styles.table}>
                    <thead>
                        <tr>
                            <th style={styles.th}>Agent ID</th>
                            <th style={styles.th}>Display Name</th>
                            <th style={styles.th}>MCP Servers</th>
                            <th style={styles.th}>Tools</th>
                            <th style={styles.th}>Context Scope</th>
                            <th style={styles.th}>Redact Fields</th>
                            <th style={styles.th}>Status</th>
                            <th style={styles.th}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {agents.map((a) => (
                            <tr key={a.agent_id} style={{ cursor: 'pointer', background: selectedAgent === a.agent_id ? '#e3f2fd' : 'transparent' }}
                                onClick={() => selectAgent(a.agent_id)}>
                                <td style={styles.td}><strong>{a.agent_id}</strong></td>
                                <td style={styles.td}>{a.display_name}</td>
                                <td style={styles.td}><div style={styles.tagList}>{splitTags(a.allowed_mcp_servers)}</div></td>
                                <td style={styles.td}><div style={styles.tagList}>{splitTags(a.allowed_tools)}</div></td>
                                <td style={styles.td}><div style={styles.tagList}>{splitTags(a.context_scope)}</div></td>
                                <td style={styles.td}><div style={styles.tagList}>{splitTags(a.redact_fields)}</div></td>
                                <td style={styles.td}><span style={styles.badge(a.is_active)}>{a.is_active ? 'Active' : 'Inactive'}</span></td>
                                <td style={styles.td}>
                                    <button style={styles.btnSmall} onClick={(e) => { e.stopPropagation(); toggleActive(a); }}>
                                        {a.is_active ? 'Disable' : 'Enable'}
                                    </button>{' '}
                                    <button style={styles.btnDanger} onClick={(e) => { e.stopPropagation(); deleteAgent(a.agent_id); }}>Delete</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}

            {/* Violations Detail */}
            {selectedAgent && (
                <div style={styles.section}>
                    <div style={styles.sectionTitle}>Violations for: {selectedAgent}</div>
                    <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
                        {Object.entries(violationCounts).map(([type, count]) => (
                            <div key={type} style={{ ...styles.card, minWidth: 140, textAlign: 'center' }}>
                                <div style={{ fontSize: 24, fontWeight: 700, color: '#e74c3c' }}>{count}</div>
                                <div style={{ fontSize: 12, color: '#666' }}>{type}</div>
                            </div>
                        ))}
                        {Object.keys(violationCounts).length === 0 && (
                            <div style={{ color: '#999', fontSize: 14 }}>No violations recorded.</div>
                        )}
                    </div>
                    {violations.length > 0 && (
                        <table style={styles.table}>
                            <thead>
                                <tr>
                                    <th style={styles.th}>Type</th>
                                    <th style={styles.th}>Tool</th>
                                    <th style={styles.th}>MCP Server</th>
                                    <th style={styles.th}>Resource</th>
                                    <th style={styles.th}>Detail</th>
                                    <th style={styles.th}>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {violations.map((v) => (
                                    <tr key={v.id}>
                                        <td style={styles.td}><span style={styles.badge(false)}>{v.violation_type}</span></td>
                                        <td style={styles.td}>{v.tool_name || '-'}</td>
                                        <td style={styles.td}>{v.mcp_server || '-'}</td>
                                        <td style={styles.td}>{v.resource_id || '-'}</td>
                                        <td style={styles.td}>{v.detail}</td>
                                        <td style={styles.td}>{v.created_at ? new Date(v.created_at).toLocaleString() : '-'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            )}
        </div>
    );
}
