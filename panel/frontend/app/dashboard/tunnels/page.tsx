"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

interface Instance {
  id: number;
  name: string;
  mode: string;
  status: string;
  uptime: number;
  status_error?: string;
  send_transport: string;
  recv_transport: string;
  remote_addr?: string;
  client_ip?: string;
}

function formatUptime(seconds: number): string {
  if (seconds <= 0) return "—";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function TunnelsPage() {
  const [instances, setInstances] = useState<Instance[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newMode, setNewMode] = useState("local");
  const [actionLoading, setActionLoading] = useState<number | null>(null);

  const fetchInstances = async () => {
    try {
      const data = await api.listInstances();
      setInstances(data);
    } catch { }
    setLoading(false);
  };

  useEffect(() => {
    fetchInstances();
    const interval = setInterval(fetchInstances, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleCreate = async () => {
    if (!newName.trim()) return;
    try {
      await api.createInstance({ name: newName, mode: newMode });
      setShowCreate(false);
      setNewName("");
      fetchInstances();
    } catch (e: any) {
      alert(e.message);
    }
  };

  const handleAction = async (id: number, action: "start" | "stop" | "restart") => {
    setActionLoading(id);
    try {
      if (action === "start") await api.instanceStart(id);
      else if (action === "stop") await api.instanceStop(id);
      else await api.instanceRestart(id);
      setTimeout(fetchInstances, 800);
    } catch (e: any) {
      alert(e.message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete tunnel "${name}"? This cannot be undone.`)) return;
    try {
      await api.deleteInstance(id);
      fetchInstances();
    } catch (e: any) {
      alert(e.message);
    }
  };

  if (loading) return <div style={{ color: "var(--text-secondary)" }}>Loading...</div>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>🔗 Tunnels</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          + New Tunnel
        </button>
      </div>

      {/* Create Modal */}
      {showCreate && (
        <div className="modal-overlay" onClick={() => setShowCreate(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 20 }}>Create Tunnel</h2>
            <div style={{ marginBottom: 14 }}>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 4 }}>Name</label>
              <input className="input" value={newName} onChange={e => setNewName(e.target.value)} placeholder="e.g. DE Server" autoFocus />
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 4 }}>Mode</label>
              <select className="input" value={newMode} onChange={e => setNewMode(e.target.value)}>
                <option value="local">Local (Client)</option>
                <option value="remote">Remote (Server)</option>
              </select>
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="btn btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreate}>Create</button>
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {instances.length === 0 && (
        <div className="glass-card" style={{ textAlign: "center", padding: 64 }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🔗</div>
          <h3 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>No Tunnels Yet</h3>
          <p style={{ color: "var(--text-secondary)", marginBottom: 20 }}>Create your first tunnel instance to get started.</p>
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ Create Tunnel</button>
        </div>
      )}

      {/* Instance Cards */}
      <div style={{ display: "grid", gap: 16 }}>
        {instances.map(inst => (
          <div key={inst.id} className="glass-card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 24px" }}>
            {/* Left */}
            <div style={{ display: "flex", alignItems: "center", gap: 16, flex: 1 }}>
              <div className={`status-dot ${inst.status}`} />
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <Link href={`/dashboard/tunnels/edit?id=${inst.id}`} style={{ fontSize: 16, fontWeight: 600, color: "var(--text-primary)", textDecoration: "none" }}>
                    {inst.name}
                  </Link>
                  <span style={{
                    padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600,
                    background: inst.mode === "local" ? "#6366f120" : "#22c55e20",
                    color: inst.mode === "local" ? "#818cf8" : "#22c55e",
                  }}>
                    {inst.mode.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", display: "flex", gap: 12 }}>
                  <span>Send: {inst.send_transport}</span>
                  <span>Recv: {inst.recv_transport}</span>
                  {inst.remote_addr && <span>Remote: {inst.remote_addr}</span>}
                  {inst.client_ip && <span>Client: {inst.client_ip}</span>}
                  {inst.status === "running" && <span style={{ color: "var(--success)" }}>⏱ {formatUptime(inst.uptime)}</span>}
                </div>
                {inst.status_error && (
                  <div style={{ fontSize: 12, color: "var(--danger)", marginTop: 4 }}>{inst.status_error}</div>
                )}
              </div>
            </div>

            {/* Right */}
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {inst.status !== "running" ? (
                <button className="btn btn-success" style={{ padding: "6px 14px", fontSize: 13 }}
                  onClick={() => handleAction(inst.id, "start")} disabled={actionLoading === inst.id}>
                  ▶ Start
                </button>
              ) : (
                <>
                  <button className="btn btn-danger" style={{ padding: "6px 14px", fontSize: 13 }}
                    onClick={() => handleAction(inst.id, "stop")} disabled={actionLoading === inst.id}>
                    ⏹ Stop
                  </button>
                  <button className="btn btn-ghost" style={{ padding: "6px 14px", fontSize: 13 }}
                    onClick={() => handleAction(inst.id, "restart")} disabled={actionLoading === inst.id}>
                    🔄
                  </button>
                </>
              )}
              <Link href={`/dashboard/tunnels/edit?id=${inst.id}`} className="btn btn-ghost" style={{ padding: "6px 14px", fontSize: 13, textDecoration: "none" }}>
                ⚙️ Config
              </Link>
              <button className="btn btn-ghost" style={{ padding: "6px 14px", fontSize: 13, color: "var(--danger)" }}
                onClick={() => handleDelete(inst.id, inst.name)}>
                🗑
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
