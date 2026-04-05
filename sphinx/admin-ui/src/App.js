import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import ApiKeysPage from './pages/ApiKeysPage';
import PolicyBuilderPage from './pages/PolicyBuilderPage';
import RAGPolicyPage from './pages/RAGPolicyPage';
import PolicyVersionPage from './pages/PolicyVersionPage';
import VectorDBPage from './pages/VectorDBPage';
import { AuthProvider, useAuth } from './components/AuthContext';

function ProtectedRoute({ children }) {
    const { isAuthenticated } = useAuth();
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }
    return children;
}

export default function App() {
    return (
        <AuthProvider>
            <BrowserRouter>
                <Routes>
                    <Route path="/login" element={<LoginPage />} />
                    <Route
                        path="/"
                        element={
                            <ProtectedRoute>
                                <Layout />
                            </ProtectedRoute>
                        }
                    >
                        <Route index element={<DashboardPage />} />
                        <Route path="keys" element={<ApiKeysPage />} />
                        <Route path="policies" element={<PolicyBuilderPage />} />
                        <Route path="rag-policies" element={<RAGPolicyPage />} />
                        <Route path="policy-versions" element={<PolicyVersionPage />} />
                        <Route path="vector-db" element={<VectorDBPage />} />
                    </Route>
                </Routes>
            </BrowserRouter>
        </AuthProvider>
    );
}
