"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";

const NAV_ITEMS = [
  { href: "/dashboard", icon: "📊", label: "Dashboard" },
  { href: "/dashboard/inbounds", icon: "🔌", label: "Inbounds" },
  { href: "/dashboard/config", icon: "⚙️", label: "Server Config" },
  { href: "/dashboard/logs", icon: "📝", label: "Logs" },
  { href: "/dashboard/settings", icon: "🔒", label: "Settings" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) window.location.href = "/login";
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      {/* Sidebar */}
      <aside style={{
        width: collapsed ? 64 : 240,
        background: "var(--bg-secondary)",
        borderRight: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        transition: "width 0.3s",
        flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{
          padding: "20px 16px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 14, fontWeight: 700, color: "white", flexShrink: 0,
          }}>
            SP
          </div>
          {!collapsed && (
            <span style={{ fontWeight: 600, fontSize: 16 }}>Spoof Panel</span>
          )}
        </div>

        {/* Nav */}
        <nav style={{ padding: "12px 8px", flex: 1 }}>
          {NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href || 
              (item.href !== "/dashboard" && pathname?.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`sidebar-item ${isActive ? "active" : ""}`}
                style={{ marginBottom: 4 }}
              >
                <span style={{ fontSize: 18 }}>{item.icon}</span>
                {!collapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Bottom */}
        <div style={{ padding: "12px 8px", borderTop: "1px solid var(--border)" }}>
          <button
            className="sidebar-item"
            onClick={() => setCollapsed(!collapsed)}
            style={{ width: "100%", border: "none", cursor: "pointer", background: "none" }}
          >
            <span style={{ fontSize: 18 }}>{collapsed ? "→" : "←"}</span>
            {!collapsed && <span>Collapse</span>}
          </button>
          <button
            className="sidebar-item"
            onClick={handleLogout}
            style={{ width: "100%", border: "none", cursor: "pointer", background: "none", color: "var(--danger)" }}
          >
            <span style={{ fontSize: 18 }}>🚪</span>
            {!collapsed && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main */}
      <main style={{ flex: 1, padding: "32px", overflowY: "auto" }}>
        {children}
      </main>
    </div>
  );
}
