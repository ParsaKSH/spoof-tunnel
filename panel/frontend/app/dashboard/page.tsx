"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

interface DashInstance {
  id: number;
  name: string;
  mode: string;
  status: string;
  uptime: number;
  error?: string;
}

interface DashData {
  instances: DashInstance[];
  total: number;
  running_count: number;
  stopped_count: number;
  error_count: number;
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

  const handleAction = async (id: number, action: "start" | "stop") => {
    try {
      if (action === "start") await api.instanceStart(id);
      else await api.instanceStop(id);
      setTimeout(fetchData, 800);
    } catch (err: any) {
      alert(err.message);
    }
  };

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 32 }}>Dashboard</h1>

      {/* Summary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 20, marginBottom: 32 }}>
        <div className="glass-card" style={{ textAlign: "center" }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600, marginBottom: 10 }}>Total Tunnels</div>
          <div style={{ fontSize: 36, fontWeight: 700 }}>{dash?.total || 0}</div>
        </div>
        <div className="glass-card" style={{ textAlign: "center" }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600, marginBottom: 10 }}>🟢 Running</div>
          <div style={{ fontSize: 36, fontWeight: 700, color: "var(--success)" }}>{dash?.running_count || 0}</div>
        </div>
        <div className="glass-card" style={{ textAlign: "center" }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600, marginBottom: 10 }}>🔴 Stopped</div>
          <div style={{ fontSize: 36, fontWeight: 700, color: "var(--text-secondary)" }}>{dash?.stopped_count || 0}</div>
        </div>
        <div className="glass-card" style={{ textAlign: "center" }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600, marginBottom: 10 }}>💾 Memory</div>
          <div style={{ fontSize: 36, fontWeight: 700 }}>{sys?.memory_mb || 0} <span style={{ fontSize: 16 }}>MB</span></div>
        </div>
      </div>

      {/* Tunnel Instances */}
      {dash && dash.instances && dash.instances.length > 0 && (
        <div className="glass-card" style={{ marginBottom: 32 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600 }}>Tunnel Instances</h2>
            <Link href="/dashboard/tunnels" className="btn btn-ghost" style={{ textDecoration: "none", fontSize: 13 }}>
              Manage All →
            </Link>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Mode</th>
                <th>Uptime</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {dash.instances.map(inst => (
                <tr key={inst.id}>
                  <td><div className={`status-dot ${inst.status}`} /></td>
                  <td>
                    <Link href={`/dashboard/tunnels/edit?id=${inst.id}`} style={{ color: "var(--text-primary)", textDecoration: "none", fontWeight: 500 }}>
                      {inst.name}
                    </Link>
                  </td>
                  <td>
                    <span style={{
                      padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600,
                      background: inst.mode === "local" ? "#6366f120" : "#22c55e20",
                      color: inst.mode === "local" ? "#818cf8" : "#22c55e",
                    }}>{inst.mode.toUpperCase()}</span>
                  </td>
                  <td style={{ fontSize: 13 }}>{formatUptime(inst.uptime)}</td>
                  <td>
                    {inst.status !== "running" ? (
                      <button className="btn btn-success" style={{ padding: "4px 12px", fontSize: 12 }}
                        onClick={() => handleAction(inst.id, "start")}>▶</button>
                    ) : (
                      <button className="btn btn-danger" style={{ padding: "4px 12px", fontSize: 12 }}
                        onClick={() => handleAction(inst.id, "stop")}>⏹</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty state */}
      {dash && (!dash.instances || dash.instances.length === 0) && (
        <div className="glass-card" style={{ textAlign: "center", padding: 48, marginBottom: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>🔗</div>
          <p style={{ color: "var(--text-secondary)", marginBottom: 16 }}>No tunnel instances yet.</p>
          <Link href="/dashboard/tunnels" className="btn btn-primary" style={{ textDecoration: "none" }}>
            + Create Tunnel
          </Link>
        </div>
      )}

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
