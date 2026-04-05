import React, { useEffect, useState } from 'react';
import { useAuth } from '../components/AuthContext';

const styles = {
    heading: { fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1a2e' },
    grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 20, marginBottom: 32 },
    card: {
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 4px rgba(0,0,0,0.08)',
    },
    cardLabel: { fontSize: 13, color: '#888', marginBottom: 4 },
    cardValue: { fontSize: 28, fontWeight: 700, color: '#1a1a2e' },
    section: { marginTop: 32 },
    sectionTitle: { fontSize: 18, fontWeight: 600, marginBottom: 12, color: '#333' },
    status: (ok) => ({
        display: 'inline-block', padding: '4px 12px', borderRadius: 12,
        fontSize: 13, fontWeight: 600,
        background: ok ? '#e8f5e9' : '#ffebee',
        color: ok ? '#2e7d32' : '#c62828',
    }),
};

export default function DashboardPage() {
    const { apiFetch } = useAuth();
    const [health, setHealth] = useState(null);
    const [keys, setKeys] = useState([]);
    const [policyStatus, setPolicyStatus] = useState(null);

    useEffect(() => {
        const load = async () => {
            try {
                const [hRes, kRes, pRes] = await Promise.all([
                    fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/ready`),
                    apiFetch('/admin/keys'),
                    apiFetch('/admin/policies/cache/status'),
                ]);
                setHealth(await hRes.json());
                setKeys(await kRes.json());
                setPolicyStatus(await pRes.json());
            } catch {
                // silently fail on dashboard load
            }
        };
        load();
    }, [apiFetch]);

    const activeKeys = keys.filter(k => k.is_active).length;

    return (
        <div>
            <h1 style={styles.heading}>Dashboard</h1>
            <div style={styles.grid}>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Total API Keys</div>
                    <div style={styles.cardValue}>{keys.length}</div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Active Keys</div>
                    <div style={styles.cardValue}>{activeKeys}</div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Cached Policies</div>
                    <div style={styles.cardValue}>{policyStatus?.cached_policies ?? '-'}</div>
                </div>
                <div style={styles.card}>
                    <div style={styles.cardLabel}>Gateway Status</div>
                    <div style={styles.cardValue}>
                        <span style={styles.status(health?.status === 'ready')}>
                            {health?.status === 'ready' ? 'Healthy' : 'Checking...'}
                        </span>
                    </div>
                </div>
            </div>

            {health && (
                <div style={styles.section}>
                    <div style={styles.sectionTitle}>Service Health</div>
                    <div style={styles.grid}>
                        <div style={styles.card}>
                            <div style={styles.cardLabel}>PostgreSQL</div>
                            <span style={styles.status(health.checks?.postgres)}>
                                {health.checks?.postgres ? 'Connected' : 'Down'}
                            </span>
                        </div>
                        <div style={styles.card}>
                            <div style={styles.cardLabel}>Redis</div>
                            <span style={styles.status(health.checks?.redis)}>
                                {health.checks?.redis ? 'Connected' : 'Down'}
                            </span>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
