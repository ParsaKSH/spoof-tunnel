"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";

const NAV_ITEMS = [
  { href: "/dashboard", icon: "📊", label: "Dashboard" },
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
    <div style={{ display: "flex", minHeight: "100vh", flexDirection: "column" }}>
      {/* Top Bar */}
      <header style={{
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border)",
        padding: "10px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 12, fontWeight: 700, color: "white",
          }}>
            SP
          </div>
          <span style={{ fontWeight: 600, fontSize: 16 }}>Spoof Tunnel v3.0.0</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <a
            href="https://github.com/ParsaKSH/spoof-tunnel"
            target="_blank"
            rel="noopener noreferrer"
            className="btn"
            style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "6px 14px", fontSize: 13, textDecoration: "none",
              background: "var(--bg-tertiary)", border: "1px solid var(--border)",
              borderRadius: 8, color: "var(--text-primary)", cursor: "pointer",
            }}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
            </svg>
            GitHub
          </a>
          <a
            href="https://nowpayments.io/donation/ParsaKSH"
            target="_blank"
            rel="noopener noreferrer"
            className="btn"
            style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "6px 14px", fontSize: 13, textDecoration: "none",
              background: "linear-gradient(135deg, #f59e0b, #ef4444)",
              border: "none", borderRadius: 8, color: "white", cursor: "pointer",
              fontWeight: 600,
            }}
          >
            ❤️ Donate
          </a>
        </div>
      </header>

      <div style={{ display: "flex", flex: 1 }}>
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

      {/* Footer */}
      <footer style={{
        background: "var(--bg-secondary)",
        borderTop: "1px solid var(--border)",
        padding: "12px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        fontSize: 12,
        color: "var(--text-secondary)",
        flexShrink: 0,
      }}>
        <span>Spoof Tunnel v3.0.0 — Rust Transport Engine</span>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <a
            href="https://github.com/ParsaKSH/spoof-tunnel"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--text-secondary)", textDecoration: "none" }}
          >
            GitHub
          </a>
          <a
            href="https://nowpayments.io/donation/ParsaKSH"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--text-secondary)", textDecoration: "none" }}
          >
            ❤️ Donate
          </a>
          <span>© {new Date().getFullYear()} ParsaKSH</span>
        </div>
      </footer>
    </div>
  );
}
