import { useLocation, useNavigate } from "react-router-dom"

const navItems = [
  { name: "Login", path: "/" },
  { name: "Dashboard", path: "/dashboard" },
  { name: "Policy Engine", path: "/rules" },
  { name: "Connections", path: "/connections" },
  { name: "Settings", path: "/settings" },
]

export default function Navbar() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <div className="bg-[#e5e7eb] text-black px-6 py-2 flex gap-6 text-sm">
      <span className="text-gray-500">RaptorGate:</span>

      {navItems.map((item) => (
        <button
          key={item.name}
          onClick={() => navigate(item.path)}
          className={`pb-1 transition ${
            location.pathname === item.path
              ? "border-b-2 border-[#06b6d4]"
              : "hover:text-gray-600"
          }`}
        >
          {item.name}
        </button>
      ))}
    </div>
  )
}