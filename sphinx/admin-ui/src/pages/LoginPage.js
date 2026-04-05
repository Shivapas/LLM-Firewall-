import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';

const styles = {
    wrapper: {
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        minHeight: '100vh', background: '#1a1a2e',
    },
    card: {
        background: '#fff', borderRadius: 8, padding: 40, width: 380,
        boxShadow: '0 4px 24px rgba(0,0,0,0.2)',
    },
    title: { fontSize: 24, fontWeight: 700, marginBottom: 8, color: '#1a1a2e' },
    subtitle: { fontSize: 14, color: '#888', marginBottom: 24 },
    label: { display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6, color: '#333' },
    input: {
        width: '100%', padding: '10px 12px', border: '1px solid #ddd', borderRadius: 4,
        fontSize: 14, marginBottom: 16,
    },
    button: {
        width: '100%', padding: '12px', background: '#4fc3f7', color: '#fff',
        border: 'none', borderRadius: 4, fontSize: 15, fontWeight: 600, cursor: 'pointer',
    },
    error: { color: '#e74c3c', fontSize: 13, marginBottom: 12 },
};

export default function LoginPage() {
    const [token, setToken] = useState('');
    const [error, setError] = useState('');
    const { login } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!token.trim()) {
            setError('API token is required');
            return;
        }
        login(token.trim());
        navigate('/');
    };

    return (
        <div style={styles.wrapper}>
            <form style={styles.card} onSubmit={handleSubmit}>
                <div style={styles.title}>Sphinx Admin</div>
                <div style={styles.subtitle}>Enter your admin API key to continue</div>
                {error && <div style={styles.error}>{error}</div>}
                <label style={styles.label}>Admin API Key</label>
                <input
                    style={styles.input}
                    type="password"
                    placeholder="spx-..."
                    value={token}
                    onChange={(e) => { setToken(e.target.value); setError(''); }}
                />
                <button type="submit" style={styles.button}>Sign In</button>
            </form>
        </div>
    );
}
