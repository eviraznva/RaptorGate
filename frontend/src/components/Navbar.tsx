import { useState } from "react"

const navItems = [
  "Login",
  "Dashboard",
  "Policy Engine",
  "Connections",
  "Settings",
]

export default function Navbar() {
  const [active, setActive] = useState("Login")

  return (
    <div className="bg-[#e5e7eb] text-black px-6 py-2 flex gap-6 text-sm">
      <span className="text-gray-500">SCREEN:</span>

      {navItems.map((item) => (
        <button
          key={item}
          onClick={() => setActive(item)}
          className={`pb-1 transition ${
            active === item
              ? "border-b-2 border-[#06b6d4]"
              : "hover:text-gray-600"
          }`}
        >
          {item}
        </button>
      ))}
    </div>
  )
}