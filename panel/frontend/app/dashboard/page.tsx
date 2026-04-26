"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface DashData {
  tunnel_status: string;
  tunnel_error: string;
  uptime: number;
}

interface SysData {
  hostname: string;
  os: string;
  arch: string;
  cpus: number;
  goroutines: number;
  memory_mb: number;
  go_version: string;
}

function formatUptime(seconds: number): string {
  if (seconds <= 0) return "—";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function DashboardPage() {
  const [dash, setDash] = useState<DashData | null>(null);
  const [sys, setSys] = useState<SysData | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    try {
      const [d, s] = await Promise.all([api.dashboard(), api.system()]);
      setDash(d);
      setSys(s);
    } catch {}
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleAction = async (action: "start" | "stop" | "restart") => {
    setLoading(true);
    try {
      if (action === "start") await api.tunnelStart();
      else if (action === "stop") await api.tunnelStop();
      else await api.tunnelRestart();
      setTimeout(fetchData, 1000);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  const status = dash?.tunnel_status || "stopped";

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 32 }}>Dashboard</h1>

      {/* Status Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 20, marginBottom: 32 }}>
        {/* Tunnel Status */}
        <div className="glass-card" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div className={`status-dot ${status}`} />
            <span style={{ color: "var(--text-secondary)", fontSize: 13, textTransform: "uppercase", fontWeight: 600 }}>
              Tunnel Status
            </span>
          </div>
          <span style={{ fontSize: 28, fontWeight: 700, textTransform: "capitalize" }}>{status}</span>
          {dash?.tunnel_error && (
            <span style={{ fontSize: 12, color: "var(--danger)" }}>{dash.tunnel_error}</span>
          )}
        </div>

        {/* Uptime */}
        <div className="glass-card">
          <span style={{ color: "var(--text-secondary)", fontSize: 13, textTransform: "uppercase", fontWeight: 600, display: "block", marginBottom: 12 }}>
            ⏱ Uptime
          </span>
          <span style={{ fontSize: 28, fontWeight: 700 }}>{formatUptime(dash?.uptime || 0)}</span>
        </div>

        {/* Goroutines */}
        <div className="glass-card">
          <span style={{ color: "var(--text-secondary)", fontSize: 13, textTransform: "uppercase", fontWeight: 600, display: "block", marginBottom: 12 }}>
            ⚡ Goroutines
          </span>
          <span style={{ fontSize: 28, fontWeight: 700 }}>{sys?.goroutines || 0}</span>
        </div>

        {/* Memory */}
        <div className="glass-card">
          <span style={{ color: "var(--text-secondary)", fontSize: 13, textTransform: "uppercase", fontWeight: 600, display: "block", marginBottom: 12 }}>
            💾 Memory
          </span>
          <span style={{ fontSize: 28, fontWeight: 700 }}>{sys?.memory_mb || 0} MB</span>
        </div>
      </div>

      {/* Controls */}
      <div className="glass-card" style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>Tunnel Control</h2>
        <div style={{ display: "flex", gap: 12 }}>
          <button
            className="btn btn-success"
            onClick={() => handleAction("start")}
            disabled={loading || status === "running"}
          >
            ▶ Start
          </button>
          <button
            className="btn btn-danger"
            onClick={() => handleAction("stop")}
            disabled={loading || status === "stopped"}
          >
            ⏹ Stop
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => handleAction("restart")}
            disabled={loading}
          >
            🔄 Restart
          </button>
        </div>
      </div>

      {/* System Info */}
      {sys && (
        <div className="glass-card">
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>System Info</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
            {[
              ["Hostname", sys.hostname],
              ["OS / Arch", `${sys.os} / ${sys.arch}`],
              ["CPUs", sys.cpus],
              ["Goroutines", sys.goroutines],
              ["Go Version", sys.go_version],
            ].map(([label, value]) => (
              <div key={String(label)} style={{ borderLeft: "3px solid var(--accent)", paddingLeft: 12 }}>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>{label}</div>
                <div style={{ fontWeight: 600 }}>{String(value)}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
