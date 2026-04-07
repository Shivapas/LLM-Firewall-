import React, { useState, useCallback } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    page: { maxWidth: 800, margin: '0 auto' },
    title: { fontSize: 24, fontWeight: 700, color: '#1a1a2e', marginBottom: 8 },
    subtitle: { fontSize: 14, color: '#666', marginBottom: 24 },
    card: {
        background: '#fff', borderRadius: 8, padding: 24, marginBottom: 16,
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    },
    progress: {
        height: 8, background: '#e0e0e0', borderRadius: 4, marginBottom: 24, overflow: 'hidden',
    },
    progressFill: (pct) => ({
        height: '100%', width: `${pct}%`, background: pct >= 100 ? '#2e7d32' : '#1a73e8',
        borderRadius: 4, transition: 'width 0.3s ease',
    }),
    step: (completed, current) => ({
        display: 'flex', alignItems: 'flex-start', padding: 20, marginBottom: 12,
        borderRadius: 8, border: `2px solid ${completed ? '#2e7d32' : current ? '#1a73e8' : '#e0e0e0'}`,
        background: completed ? '#e8f5e920' : current ? '#e3f2fd20' : '#fff',
    }),
    stepNumber: (completed, current) => ({
        width: 32, height: 32, borderRadius: '50%', display: 'flex', alignItems: 'center',
        justifyContent: 'center', fontWeight: 700, fontSize: 14, marginRight: 16, flexShrink: 0,
        background: completed ? '#2e7d32' : current ? '#1a73e8' : '#e0e0e0',
        color: '#fff',
    }),
    stepTitle: { fontSize: 16, fontWeight: 600, color: '#1a1a2e', marginBottom: 4 },
    stepDesc: { fontSize: 13, color: '#666' },
    btn: (variant) => ({
        padding: '10px 20px', border: 'none', borderRadius: 6, cursor: 'pointer',
        fontWeight: 600, fontSize: 14, marginRight: 8,
        ...(variant === 'primary' ? { background: '#1a73e8', color: '#fff' } : {}),
        ...(variant === 'secondary' ? { background: '#e0e0e0', color: '#333' } : {}),
        ...(variant === 'success' ? { background: '#2e7d32', color: '#fff' } : {}),
    }),
    input: {
        padding: '8px 12px', borderRadius: 6, border: '1px solid #ddd',
        fontSize: 14, width: 200, marginRight: 8,
    },
    completeBanner: {
        background: '#e8f5e9', border: '2px solid #2e7d32', borderRadius: 8, padding: 24,
        textAlign: 'center', marginBottom: 24,
    },
};

export default function OnboardingPage() {
    const { apiFetch } = useAuth();
    const [tenantId, setTenantId] = useState('');
    const [status, setStatus] = useState(null);

    const fetchStatus = useCallback(async () => {
        if (!tenantId) return;
        try {
            const res = await apiFetch(`/admin/onboarding/${tenantId}`);
            setStatus(await res.json());
        } catch (e) { console.error(e); }
    }, [tenantId]);

    const autoDetect = async () => {
        if (!tenantId) return;
        try {
            const res = await apiFetch(`/admin/onboarding/${tenantId}/auto-detect`, { method: 'POST' });
            setStatus(await res.json());
        } catch (e) { console.error(e); }
    };

    const completeStep = async (stepKey) => {
        if (!tenantId) return;
        try {
            const res = await apiFetch(`/admin/onboarding/${tenantId}/complete-step`, {
                method: 'POST',
                body: JSON.stringify({ step_key: stepKey }),
            });
            setStatus(await res.json());
        } catch (e) { console.error(e); }
    };

    const resetProgress = async () => {
        if (!tenantId) return;
        try {
            const res = await apiFetch(`/admin/onboarding/${tenantId}/reset`, { method: 'POST' });
            setStatus(await res.json());
        } catch (e) { console.error(e); }
    };

    return (
        <div style={styles.page}>
            <h1 style={styles.title}>Onboarding Wizard</h1>
            <p style={styles.subtitle}>Step-by-step guide to get your first request through the Sphinx gateway.</p>

            <div style={styles.card}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                    <input style={styles.input} placeholder="Enter tenant ID" value={tenantId} onChange={e => setTenantId(e.target.value)} />
                    <button style={styles.btn('primary')} onClick={fetchStatus}>Load</button>
                    <button style={styles.btn('secondary')} onClick={autoDetect}>Auto-Detect</button>
                </div>
            </div>

            {status && (
                <>
                    {/* Progress bar */}
                    <div style={styles.progress}>
                        <div style={styles.progressFill(status.progress_percentage)} />
                    </div>
                    <p style={{ fontSize: 14, color: '#666', marginBottom: 20 }}>
                        {status.progress_percentage}% complete ({status.steps?.filter(s => s.completed).length}/{status.total_steps} steps)
                    </p>

                    {/* Completion banner */}
                    {status.completed && (
                        <div style={styles.completeBanner}>
                            <div style={{ fontSize: 28, marginBottom: 8 }}>All steps complete!</div>
                            <p style={{ color: '#2e7d32' }}>Your gateway is configured and processing requests.</p>
                        </div>
                    )}

                    {/* Steps */}
                    {(status.steps || []).map((step, i) => (
                        <div key={step.key} style={styles.step(step.completed, i === status.current_step && !status.completed)}>
                            <div style={styles.stepNumber(step.completed, i === status.current_step)}>
                                {step.completed ? '\u2713' : i + 1}
                            </div>
                            <div style={{ flex: 1 }}>
                                <div style={styles.stepTitle}>{step.title}</div>
                                <div style={styles.stepDesc}>{step.description}</div>
                            </div>
                            {!step.completed && (
                                <button style={styles.btn('primary')} onClick={() => completeStep(step.key)}>
                                    Mark Complete
                                </button>
                            )}
                        </div>
                    ))}

                    <div style={{ marginTop: 24 }}>
                        <button style={styles.btn('secondary')} onClick={resetProgress}>Reset Progress</button>
                    </div>
                </>
            )}
        </div>
    );
}
