import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { Provider } from "react-redux";
import { store } from "./app/store.ts";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import LoginPage from "./pages/LoginPage.tsx";
import ResetPasswordPage from "./pages/ResetPasswordPage.tsx";
import Dashboard from "./pages/Dashboard.tsx";
import Dns from "./pages/Dns.tsx";
import Ips from "./pages/Ips.tsx";
import ConnectionTracking from "./pages/ConnectionTracking.tsx";
import PolicyEngine from "./pages/PolicyEngine.tsx";
import Settings from "./pages/Settings.tsx";
import Zones from "./pages/Zones.tsx";
import NatRules from "./pages/NatRules.tsx";
import { Layout } from "./components/layout/layout.tsx";
import { Metrics } from "./components/metrics/Metrics.tsx";
import { ProtectedRoute } from "./components/protectedRoute/protectedRoute.tsx";
import { protectedRouteLoader } from "./loaders/protectedRouteLoader.ts";

const router = createBrowserRouter([
  {
    path: "",
    element: <Layout />,
    children: [
      {
        path: "/login",
        element: <LoginPage />,
      },
      {
        path: "/reset-password",
        element: <ResetPasswordPage />,
      },
      {
        path: "/dashboard",
        element: (
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        ),
        loader: protectedRouteLoader,
        children: [
          {
            path: "metrics",
            element: <Metrics />,
          },
          {
            path: "dns",
            element: <Dns />,
          },
          {
            path: "ips",
            element: <Ips />,
          },
          {
            path: "connections",
            element: <ConnectionTracking />,
          },
          {
            path: "rules",
            element: <PolicyEngine />,
          },
          {
            path: "zones",
            element: <Zones />,
          },
          {
            path: "nat-rules",
            element: <NatRules />,
          },
          {
            path: "settings",
            element: <Settings />,
          },
        ],
      },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Provider store={store}>
      <RouterProvider router={router} />
    </Provider>
  </StrictMode>,
);
