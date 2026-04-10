import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./App.css";

import Dashboard from "./pages/Dashboard";
import ConnectionTracking from "./pages/ConnectionTracking";
import PolicyEngine from "./pages/PolicyEngine";
import Settings from "./pages/Settings";
import LoginPage from "./pages/LoginPage";
import Dns from "./pages/Dns";
import Ips from "./pages/Ips";
import ProtectedRoute from "./router/ProtectedRoute";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* LOGIN */}
        <Route path="/login" element={<LoginPage />} />

        {/* PROTECTED ROUTES */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/dashboard/dns"
          element={
            <ProtectedRoute>
              <Dns />
            </ProtectedRoute>
          }
        />

        <Route
          path="/dashboard/ips"
          element={
            <ProtectedRoute>
              <Ips />
            </ProtectedRoute>
          }
        />

        <Route
          path="/connections"
          element={
            <ProtectedRoute>
              <ConnectionTracking />
            </ProtectedRoute>
          }
        />

        <Route
          path="/rules"
          element={
            <ProtectedRoute>
              <PolicyEngine />
            </ProtectedRoute>
          }
        />

        <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <Settings />
            </ProtectedRoute>
          }
        />

        {/* DEFAULT REDIRECT */}
        <Route path="*" element={<LoginPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
