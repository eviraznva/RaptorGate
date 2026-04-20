import { Outlet, useLocation, useNavigate } from "react-router-dom";
import Navbar from "../components/navbar/Navbar";
import { useEffect } from "react";
import { RecoveryTokenModal } from "../components/recoveryTokenModal/RecoveryTokenModal";
import { useAppDispatch, useAppSelector } from "../app/hooks";
import { clearRecoveryToken, setIsFirstLogin } from "../features/userSlice";

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const user = useAppSelector((state) => state.user);
  console.log(user);

  const handleConfirm = function () {
    dispatch(clearRecoveryToken());
    dispatch(setIsFirstLogin(false));
  };

  useEffect(() => {
    if (location.pathname === "/dashboard") navigate("/dashboard/metrics");
  }, [location.pathname]);

  return (
    <>
      <Navbar />
      {user.showRecoveryToken && (
        <RecoveryTokenModal
          token={user.recoveryToken!}
          onConfirm={handleConfirm}
        />
      )}
      <Outlet />
    </>
  );
}
