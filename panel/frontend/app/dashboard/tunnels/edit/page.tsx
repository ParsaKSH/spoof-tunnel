"use client";
import { useEffect, useState, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { api } from "@/lib/api";

const TRANSPORT_OPTIONS = [
  { value: "tcp", label: "TCP (SYN)" },
  { value: "udp", label: "UDP" },
  { value: "icmp", label: "ICMP" },
  { value: "icmpv6", label: "ICMPv6" },
];

function EditContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const id = Number(searchParams.get("id"));

  const [config, setConfig] = useState<any>(null);
  const [status, setStatus] = useState("stopped");
  const [uptime, setUptime] = useState(0);
  const [statusError, setStatusError] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [spoofIPs, setSpoofIPs] = useState("");
  const [spoofCount, setSpoofCount] = useState(0);
  const [savingIPs, setSavingIPs] = useState(false);
  const [activeTab, setActiveTab] = useState<"config" | "spoofips" | "logs">("config");
  const [logs, setLogs] = useState<string[]>([]);

  const fetchData = async () => {
    if (!id) return;
    try {
      const data = await api.getInstance(id);
      setConfig(data.instance);
      setStatus(data.status);
      setUptime(data.uptime);
      setStatusError(data.error || "");
    } catch {
      router.push("/dashboard/tunnels");
    }
  };

  const fetchSpoofIPs = async () => {
    if (!id) return;
    try {
      const data = await api.getInstanceSpoofIPs(id);
      setSpoofIPs(data.content);
      setSpoofCount(data.count);
    } catch { }
  };

  useEffect(() => {
    fetchData();
    fetchSpoofIPs();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, [id]);

  // WebSocket logs
  useEffect(() => {
    if (activeTab !== "logs" || !id) return;
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const token = localStorage.getItem("token");
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/api/instances/${id}/logs?token=${token}`);
    ws.onmessage = (e) => {
      setLogs(prev => [...prev.slice(-499), e.data]);
    };
    return () => ws.close();
  }, [id, activeTab]);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateInstance(id, config);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveSpoofIPs = async () => {
    setSavingIPs(true);
    try {
      const result = await api.setInstanceSpoofIPs(id, spoofIPs);
      setSpoofCount(result.count);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSavingIPs(false);
    }
  };

  const handleAction = async (action: "start" | "stop" | "restart") => {
    try {
      if (action === "start") await api.instanceStart(id);
      else if (action === "stop") await api.instanceStop(id);
      else await api.instanceRestart(id);
      setTimeout(fetchData, 800);
    } catch (err: any) {
      alert(err.message);
    }
  };

  const update = (key: string, value: any) => setConfig({ ...config, [key]: value });

  if (!config) return <div style={{ color: "var(--text-secondary)" }}>Loading...</div>;

  const isLocal = config.mode === "local";

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button className="btn btn-ghost" onClick={() => router.push("/dashboard/tunnels")} style={{ padding: "6px 12px" }}>←</button>
          <div className={`status-dot ${status}`} />
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>{config.name}</h1>
          <span style={{
            padding: "3px 10px", borderRadius: 4, fontSize: 12, fontWeight: 600,
            background: isLocal ? "#6366f120" : "#22c55e20",
            color: isLocal ? "#818cf8" : "#22c55e",
          }}>
            {config.mode?.toUpperCase()}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {status !== "running" ? (
            <button className="btn btn-success" onClick={() => handleAction("start")}>▶ Start</button>
          ) : (
            <>
              <button className="btn btn-danger" onClick={() => handleAction("stop")}>⏹ Stop</button>
              <button className="btn btn-ghost" onClick={() => handleAction("restart")}>🔄 Restart</button>
            </>
          )}
        </div>
      </div>

      {statusError && (
        <div style={{ background: "#ef444420", border: "1px solid var(--danger)", borderRadius: 8, padding: "10px 14px", marginBottom: 16, color: "var(--danger)", fontSize: 13 }}>
          {statusError}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, marginBottom: 24 }}>
        {(["config", "spoofips", "logs"] as const).map(t => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            style={{
              padding: "10px 24px",
              background: activeTab === t ? "var(--accent)" : "var(--bg-card)",
              color: activeTab === t ? "white" : "var(--text-secondary)",
              border: `1px solid ${activeTab === t ? "var(--accent)" : "var(--border)"}`,
              borderRadius: t === "config" ? "8px 0 0 8px" : t === "logs" ? "0 8px 8px 0" : "0",
              cursor: "pointer", fontWeight: 600, fontSize: 13,
            }}
          >
            {t === "config" ? "⚙️ Config" : t === "spoofips" ? "📋 Spoof IPs" : "📝 Logs"}
          </button>
        ))}
      </div>

      {/* Config Tab */}
      {activeTab === "config" && (
        <>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 12, alignItems: "center", marginBottom: 20 }}>
            {saved && <span style={{ color: "var(--success)", fontSize: 14 }}>✓ Saved!</span>}
            <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? "Saving..." : "Save Config"}
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
            {/* General */}
            <div className="glass-card">
              <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>General</h2>
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Name</label>
                  <input className="input" value={config.name || ""} onChange={e => update("name", e.target.value)} />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Mode</label>
                  <select className="input" value={config.mode} onChange={e => update("mode", e.target.value)}>
                    <option value="local">Local (Client)</option>
                    <option value="remote">Remote (Server)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Transport */}
            <div className="glass-card">
              <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Transport</h2>
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Send Transport</label>
                  <select className="input" value={config.send_transport} onChange={e => update("send_transport", e.target.value)}>
                    {TRANSPORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Recv Transport</label>
                  <select className="input" value={config.recv_transport} onChange={e => update("recv_transport", e.target.value)}>
                    {TRANSPORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>
            </div>

            {/* Local Mode */}
            {isLocal && (
              <div className="glass-card">
                <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Local Mode</h2>
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  <div>
                    <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Listen Address (UDP)</label>
                    <input className="input" value={config.listen_addr || ""} onChange={e => update("listen_addr", e.target.value)} placeholder="127.0.0.1:5000" />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Remote Server IP</label>
                    <input className="input" value={config.remote_addr || ""} onChange={e => update("remote_addr", e.target.value)} placeholder="Server IP" />
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <div>
                      <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Remote Port</label>
                      <input className="input" type="number" value={config.remote_port} onChange={e => update("remote_port", parseInt(e.target.value) || 0)} />
                    </div>
                    <div>
                      <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Recv Port</label>
                      <input className="input" type="number" value={config.recv_port} onChange={e => update("recv_port", parseInt(e.target.value) || 0)} />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Remote Mode */}
            {!isLocal && (
              <div className="glass-card">
                <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Remote Mode</h2>
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  <div>
                    <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Listen Port</label>
                    <input className="input" type="number" value={config.listen_port} onChange={e => update("listen_port", parseInt(e.target.value) || 0)} />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Forward Address</label>
                    <input className="input" value={config.forward_addr || ""} onChange={e => update("forward_addr", e.target.value)} placeholder="127.0.0.1:51820" />
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <div>
                      <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Client IP</label>
                      <input className="input" value={config.client_ip || ""} onChange={e => update("client_ip", e.target.value)} />
                    </div>
                    <div>
                      <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Client Port</label>
                      <input className="input" type="number" value={config.client_port} onChange={e => update("client_port", parseInt(e.target.value) || 0)} />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Spoof */}
            <div className="glass-card">
              <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Spoof Settings</h2>
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Spoof IP</label>
                  <input className="input" value={config.spoof_ip || ""} onChange={e => update("spoof_ip", e.target.value)} placeholder="Spoofed source IP" />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Spoof Port</label>
                  <input className="input" type="number" value={config.spoof_port} onChange={e => update("spoof_port", parseInt(e.target.value) || 0)} />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Peer Spoof IP (expected source)</label>
                  <input className="input" value={config.peer_spoof_ip || ""} onChange={e => update("peer_spoof_ip", e.target.value)} placeholder="Optional" />
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Spoof IPs Tab */}
      {activeTab === "spoofips" && (
        <div className="glass-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: "var(--accent)" }}>
              Spoof IP List <span style={{ fontSize: 13, color: "var(--text-secondary)", fontWeight: 400 }}>({spoofCount} IPs)</span>
            </h2>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {saved && <span style={{ color: "var(--success)", fontSize: 13 }}>✓ Saved!</span>}
              <button className="btn btn-primary" onClick={handleSaveSpoofIPs} disabled={savingIPs} style={{ fontSize: 13 }}>
                {savingIPs ? "Saving..." : "Save IPs"}
              </button>
            </div>
          </div>
          <p style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 14 }}>
            One IP per line. Supports single IPs, CIDR ranges, and dash ranges. These IPs are used by the tunnel as spoofed source addresses (round-robin).
          </p>
          <textarea
            className="input"
            value={spoofIPs}
            onChange={e => { setSpoofIPs(e.target.value); setSpoofCount(e.target.value.trim() ? e.target.value.trim().split("\n").filter(l => l.trim()).length : 0); }}
            placeholder={"1.2.3.4\n10.0.0.0/24\n172.16.0.1-172.16.0.50"}
            rows={16}
            style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, resize: "vertical" }}
          />
        </div>
      )}

      {/* Logs Tab */}
      {activeTab === "logs" && (
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, color: "var(--accent)" }}>Live Logs</h2>
          <div className="log-viewer">
            {logs.length === 0 && (
              <div style={{ color: "var(--text-secondary)", textAlign: "center", padding: 32 }}>
                {status === "running" ? "Waiting for logs..." : "Start the tunnel to see logs."}
              </div>
            )}
            {logs.map((line, i) => (
              <div key={i} className={line.includes("error") || line.includes("ERROR") ? "log-error" : line.includes("warn") ? "log-warn" : ""}>
                {line}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function EditPage() {
  return (
    <Suspense fallback={<div style={{ color: "var(--text-secondary)" }}>Loading...</div>}>
      <EditContent />
    </Suspense>
  );
}
