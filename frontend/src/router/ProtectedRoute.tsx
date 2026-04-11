import { Navigate } from "react-router-dom";
import { useAppSelector } from "../app/hooks";

export default function ProtectedRoute({ children }: any) {
  const userData = useAppSelector((state) => state.user);

  if (userData.accessToken) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

