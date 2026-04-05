import React, { createContext, useContext, useState, useCallback } from 'react';

const AuthContext = createContext(null);

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export function AuthProvider({ children }) {
    const [token, setToken] = useState(() => localStorage.getItem('sphinx_token'));

    const login = useCallback((adminToken) => {
        localStorage.setItem('sphinx_token', adminToken);
        setToken(adminToken);
    }, []);

    const logout = useCallback(() => {
        localStorage.removeItem('sphinx_token');
        setToken(null);
    }, []);

    const isAuthenticated = !!token;

    const apiFetch = useCallback(async (path, options = {}) => {
        const res = await fetch(`${API_URL}${path}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...options.headers,
            },
        });
        if (res.status === 401) {
            logout();
            throw new Error('Unauthorized');
        }
        return res;
    }, [token, logout]);

    return (
        <AuthContext.Provider value={{ token, login, logout, isAuthenticated, apiFetch }}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth() {
    const ctx = useContext(AuthContext);
    if (!ctx) throw new Error('useAuth must be used within AuthProvider');
    return ctx;
}
