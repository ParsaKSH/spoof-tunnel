"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

const TRANSPORT_OPTIONS = [
  { value: "tcp", label: "TCP (SYN)" },
  { value: "udp", label: "UDP" },
  { value: "icmp", label: "ICMP" },
  { value: "icmpv6", label: "ICMPv6" },
];

export default function ConfigPage() {
  const [config, setConfig] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getConfig().then(setConfig).catch(() => {});
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateConfig(config);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSaving(false);
    }
  };

  const update = (key: string, value: any) => setConfig({ ...config, [key]: value });

  if (!config) return <div style={{ color: "var(--text-secondary)" }}>Loading...</div>;

  const isLocal = config.mode === "local";

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>Server Configuration</h1>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {saved && <span style={{ color: "var(--success)", fontSize: 14 }}>✓ Saved!</span>}
          <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? "Saving..." : "Save Config"}
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        {/* General */}
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>General</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Mode</label>
              <select className="input" value={config.mode} onChange={(e) => update("mode", e.target.value)}>
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
              <select className="input" value={config.send_transport} onChange={(e) => update("send_transport", e.target.value)}>
                {TRANSPORT_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Recv Transport</label>
              <select className="input" value={config.recv_transport} onChange={(e) => update("recv_transport", e.target.value)}>
                {TRANSPORT_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Local Mode Settings */}
        {isLocal && (
          <div className="glass-card">
            <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Local Mode</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Listen Address (UDP)</label>
                <input className="input" value={config.listen_addr || ""} onChange={(e) => update("listen_addr", e.target.value)} placeholder="127.0.0.1:5000" />
              </div>
              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Remote Server IP</label>
                <input className="input" value={config.remote_addr || ""} onChange={(e) => update("remote_addr", e.target.value)} placeholder="Server IP" />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Remote Port</label>
                  <input className="input" type="number" value={config.remote_port} onChange={(e) => update("remote_port", parseInt(e.target.value) || 0)} />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Recv Port</label>
                  <input className="input" type="number" value={config.recv_port} onChange={(e) => update("recv_port", parseInt(e.target.value) || 0)} />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Remote Mode Settings */}
        {!isLocal && (
          <div className="glass-card">
            <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Remote Mode</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Listen Port</label>
                <input className="input" type="number" value={config.listen_port} onChange={(e) => update("listen_port", parseInt(e.target.value) || 0)} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Forward Address</label>
                <input className="input" value={config.forward_addr || ""} onChange={(e) => update("forward_addr", e.target.value)} placeholder="127.0.0.1:51820" />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Client IP</label>
                  <input className="input" value={config.client_ip || ""} onChange={(e) => update("client_ip", e.target.value)} />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Client Port</label>
                  <input className="input" type="number" value={config.client_port} onChange={(e) => update("client_port", parseInt(e.target.value) || 0)} />
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
              <input className="input" value={config.spoof_ip || ""} onChange={(e) => update("spoof_ip", e.target.value)} placeholder="Spoofed source IP" />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Spoof Port</label>
              <input className="input" type="number" value={config.spoof_port} onChange={(e) => update("spoof_port", parseInt(e.target.value) || 0)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Peer Spoof IP (expected source)</label>
              <input className="input" value={config.peer_spoof_ip || ""} onChange={(e) => update("peer_spoof_ip", e.target.value)} placeholder="Optional" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
