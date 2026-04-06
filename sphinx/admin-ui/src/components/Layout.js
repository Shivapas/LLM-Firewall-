import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';

const styles = {
    container: { display: 'flex', minHeight: '100vh' },
    sidebar: {
        width: 220, background: '#1a1a2e', color: '#eee', padding: '24px 0',
        display: 'flex', flexDirection: 'column',
    },
    brand: { fontSize: 20, fontWeight: 700, padding: '0 20px 24px', borderBottom: '1px solid #333' },
    nav: { flex: 1, padding: '16px 0' },
    navLink: (active) => ({
        display: 'block', padding: '10px 20px', color: active ? '#4fc3f7' : '#ccc',
        textDecoration: 'none', background: active ? '#16213e' : 'transparent',
        fontWeight: active ? 600 : 400,
    }),
    main: { flex: 1, background: '#f5f5f5', padding: 32 },
    logoutBtn: {
        margin: '16px 20px', padding: '8px 16px', background: '#e74c3c', color: '#fff',
        border: 'none', borderRadius: 4, cursor: 'pointer',
    },
};

export default function Layout() {
    const { logout } = useAuth();
    const location = useLocation();

    return (
        <div style={styles.container}>
            <aside style={styles.sidebar}>
                <div style={styles.brand}>Sphinx Admin</div>
                <nav style={styles.nav}>
                    <Link to="/" style={styles.navLink(location.pathname === '/')}>Dashboard</Link>
                    <Link to="/keys" style={styles.navLink(location.pathname === '/keys')}>API Keys</Link>
                    <Link to="/policies" style={styles.navLink(location.pathname === '/policies')}>Security Policies</Link>
                    <Link to="/rag-policies" style={styles.navLink(location.pathname === '/rag-policies')}>RAG Policies</Link>
                    <Link to="/policy-versions" style={styles.navLink(location.pathname === '/policy-versions')}>Policy Versions</Link>
                    <Link to="/vector-db" style={styles.navLink(location.pathname === '/vector-db')}>Vector DB</Link>
                    <Link to="/vector-dashboard" style={styles.navLink(location.pathname === '/vector-dashboard')}>Vector Dashboard</Link>
                    <Link to="/routing-rules" style={styles.navLink(location.pathname === '/routing-rules')}>Routing Rules</Link>
                    <Link to="/kill-switches" style={styles.navLink(location.pathname === '/kill-switches')}>Kill-Switches</Link>
                    <Link to="/multi-model" style={styles.navLink(location.pathname === '/multi-model')}>Multi-Model</Link>
                    <Link to="/mcp-scanner" style={styles.navLink(location.pathname === '/mcp-scanner')}>MCP Scanner</Link>
                    <Link to="/agent-scope" style={styles.navLink(location.pathname === '/agent-scope')}>Agent Scope</Link>
                </nav>
                <button style={styles.logoutBtn} onClick={logout}>Logout</button>
            </aside>
            <main style={styles.main}>
                <Outlet />
            </main>
        </div>
    );
}
