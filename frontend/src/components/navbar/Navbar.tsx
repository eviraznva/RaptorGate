import { useLocation, useNavigate } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { Icon } from "@iconify/react";
import { useLogoutMutation } from "../../services/auth";
import { useEffect } from "react";
import { clearUser } from "../../features/userSlice";

const navItems = [
  { name: "Metrics", path: "/dashboard/metrics" },
  { name: "DNS", path: "/dashboard/dns" },
  { name: "IPS", path: "/dashboard/ips" },
  { name: "Policy Engine", path: "/dashboard/rules" },
  { name: "Connections", path: "/dashboard/connections" },
  { name: "Settings", path: "/dashboard/settings" },
];

export default function Navbar() {
  const dispatch = useAppDispatch();
  const user = useAppSelector((state) => state.user);
  const navigate = useNavigate();
  const location = useLocation();
  const [logout, { isLoading, isError, isSuccess }] = useLogoutMutation();

  const handleLogout = async function () {
    try {
      await logout({
        accessToken: user.accessToken,
      });
    } catch (err) {}
  };

  useEffect(() => {
    if (isSuccess) {
      dispatch(clearUser());
      navigate("/login", { replace: true });
    }
  }, [isSuccess]);

  return (
    <nav className="bg-[#161616] border-b border-[#262626] px-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1">
          {navItems.map((item, i) => (
            <div key={item.name} className="flex items-center">
              <button
                onClick={() => {
                  navigate(item.path);
                }}
                className={`px-4 py-4 text-sm transition-colors ${
                  location.pathname === item.path
                    ? "text-[#06b6d4] border-b-2 border-[#06b6d4]"
                    : "text-[#8a8a8a] hover:text-[#f5f5f5]"
                }`}
              >
                {item.name}
              </button>
              {i < navItems.length - 1 && (
                <span className="text-[#262626] mx-1">│</span>
              )}
            </div>
          ))}
        </div>
        <div className="flex items-center gap-2 text-sm text-[#8a8a8a]">
          <span>{user.username}</span>
          <span className="text-[#06b6d4]">│</span>
          <button className="hover:text-[#f5f5f5]">
            <Icon icon="lucide:settings cursor-pointer" />
          </button>
          <button className="hover:text-[#f5f5f5] relative">
            <Icon icon="lucide:bell" className="cursor-pointer" />
            <span className="absolute -top-1 -right-1 w-2 h-2 bg-[#f43f5e] rounded-full" />
          </button>
          <button
            onClick={handleLogout}
            className="hover:text-[#f5f5f5] cursor-pointer flex felx-row"
          >
            <p className="text-base px-2">Log out</p>
            <Icon
              icon="lucide:log-out"
              width={24}
              height={24}
              className="cursor-pointer px-1"
            />
          </button>
        </div>
      </div>
    </nav>
  );
}
