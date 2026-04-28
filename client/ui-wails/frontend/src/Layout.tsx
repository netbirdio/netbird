import { NavLink, Outlet } from "react-router-dom";
import { Activity, Bug, Network, Settings as SettingsIcon, Share2, Users } from "lucide-react";
import { cn } from "./lib/cn";

const nav = [
  { to: "/", label: "Status", icon: Activity, end: true },
  { to: "/peers", label: "Peers", icon: Share2 },
  { to: "/networks", label: "Networks", icon: Network },
  { to: "/profiles", label: "Profiles", icon: Users },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
  { to: "/debug", label: "Debug", icon: Bug },
];

export default function Layout() {
  return (
    <div className="flex h-full">
      <aside className="w-48 shrink-0 border-r border-nb-gray-200 bg-nb-gray-50 dark:border-nb-gray-800 dark:bg-nb-gray-940">
        <div className="px-4 py-5 text-lg font-semibold text-netbird">NetBird</div>
        <nav className="px-2">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                  isActive
                    ? "bg-netbird/10 text-netbird"
                    : "text-nb-gray-700 hover:bg-nb-gray-100 dark:text-nb-gray-300 dark:hover:bg-nb-gray-900",
                )
              }
            >
              <Icon className="h-4 w-4" strokeWidth={1.5} />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
