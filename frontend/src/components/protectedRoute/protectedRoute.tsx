import { useEffect, type PropsWithChildren } from "react";
import { useAppSelector } from "../../app/hooks";
import { useNavigate } from "react-router-dom";

type ProtectedRouteProps = PropsWithChildren;

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const user = useAppSelector((state) => state.user);
  const navigate = useNavigate();

  useEffect(() => {
    if (user.accessToken === "") {
      navigate("/login");
    }
  }, [navigate, user]);

  return children;
}
