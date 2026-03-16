import { BrowserRouter, Routes, Route } from "react-router-dom"
import "./App.css"

import Dashboard from "./pages/Dashboard"
import ConnectionTracking from "./pages/ConnectionTracking"
import PolicyEngine from "./pages/PolicyEngine"
import Settings from "./pages/Settings"
import LoginPage from "./pages/LoginPage"

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Login */}
        <Route path="/" element={<LoginPage />} />

        {/* Main UI */}
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/connections" element={<ConnectionTracking />} />
        <Route path="/rules" element={<PolicyEngine />} />
        <Route path="/settings" element={<Settings />} />

        {/* fallback */}
        <Route path="*" element={<LoginPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App