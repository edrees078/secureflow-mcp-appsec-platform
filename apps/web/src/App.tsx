import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './auth/AuthContext.js';
import { ProtectedRoute } from './auth/ProtectedRoute.js';
import { LoginPage } from './pages/LoginPage.js';
import { WorkspacePage } from './pages/WorkspacePage.js';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/" element={<WorkspacePage />} />
        <Route path="/workspace" element={<WorkspacePage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
