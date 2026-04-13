import { Navigate, Outlet, useLocation } from "react-router-dom";

export function Layout() {
  const location = useLocation();

  return (
    <>
      <Outlet />
      {location.pathname === "/" ? <Navigate to="/login" /> : ""}
    </>
  );
}
