import { Outlet, useLocation, useNavigate } from "react-router-dom";
import Navbar from "../components/navbar/Navbar";
import { useEffect } from "react";

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (location.pathname === "/dashboard") navigate("/dashboard/metrics");
  }, [location.pathname]);

  return (
    <>
      <Navbar />
      <Outlet />
    </>
  );
}
