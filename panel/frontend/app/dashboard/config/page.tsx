"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

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
                <option value="client">Client</option>
                <option value="server">Server</option>
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Transport</label>
              <select className="input" value={config.transport_type} onChange={(e) => update("transport_type", e.target.value)}>
                <option value="syn_udp">SYN + UDP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="raw">RAW</option>
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Log Level</label>
              <select className="input" value={config.log_level} onChange={(e) => update("log_level", e.target.value)}>
                <option value="debug">Debug</option>
                <option value="info">Info</option>
                <option value="warn">Warn</option>
                <option value="error">Error</option>
              </select>
            </div>
          </div>
        </div>

        {/* Network */}
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Network</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Server Address</label>
              <input className="input" value={config.server_address || ""} onChange={(e) => update("server_address", e.target.value)} placeholder="Server IP" />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Server Port</label>
              <input className="input" type="number" value={config.server_port} onChange={(e) => update("server_port", parseInt(e.target.value) || 0)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Listen Port (server mode)</label>
              <input className="input" type="number" value={config.listen_port} onChange={(e) => update("listen_port", parseInt(e.target.value) || 0)} />
            </div>
          </div>
        </div>

        {/* Spoof */}
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Spoof IPs</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Source IP (our spoof)</label>
              <input className="input" value={config.spoof_source_ip || ""} onChange={(e) => update("spoof_source_ip", e.target.value)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Peer Spoof IP (expected)</label>
              <input className="input" value={config.spoof_peer_ip || ""} onChange={(e) => update("spoof_peer_ip", e.target.value)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Client Real IP (server mode)</label>
              <input className="input" value={config.client_real_ip || ""} onChange={(e) => update("client_real_ip", e.target.value)} />
            </div>
          </div>
        </div>

        {/* Crypto */}
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Crypto Keys</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Private Key</label>
              <input className="input" value={config.private_key || ""} onChange={(e) => update("private_key", e.target.value)} style={{ fontFamily: "monospace", fontSize: 12 }} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Peer Public Key</label>
              <input className="input" value={config.peer_public_key || ""} onChange={(e) => update("peer_public_key", e.target.value)} style={{ fontFamily: "monospace", fontSize: 12 }} />
            </div>
          </div>
        </div>

        {/* Performance */}
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Performance</h2>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>MTU</label>
              <input className="input" type="number" value={config.mtu} onChange={(e) => update("mtu", parseInt(e.target.value) || 0)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Buffer Size</label>
              <input className="input" type="number" value={config.buffer_size} onChange={(e) => update("buffer_size", parseInt(e.target.value) || 0)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Session Timeout</label>
              <input className="input" type="number" value={config.session_timeout} onChange={(e) => update("session_timeout", parseInt(e.target.value) || 0)} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Workers</label>
              <input className="input" type="number" value={config.workers} onChange={(e) => update("workers", parseInt(e.target.value) || 0)} />
            </div>
          </div>
        </div>

        {/* Relay */}
        <div className="glass-card">
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 20, color: "var(--accent)" }}>Relay (Server Mode)</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Relay Forward Address</label>
              <input className="input" value={config.relay_forward || ""} onChange={(e) => update("relay_forward", e.target.value)} placeholder="127.0.0.1:51822" />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Relay Port (direct bypass)</label>
              <input className="input" type="number" value={config.relay_port || 0} onChange={(e) => update("relay_port", parseInt(e.target.value) || 0)} placeholder="8091" />
            </div>
            <div style={{ display: "flex", gap: 24 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                <label className="toggle">
                  <input type="checkbox" checked={config.reliability_enabled} onChange={(e) => update("reliability_enabled", e.target.checked)} />
                  <div className="slider" />
                </label>
                <span style={{ fontSize: 13 }}>Reliability</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                <label className="toggle">
                  <input type="checkbox" checked={config.fec_enabled} onChange={(e) => update("fec_enabled", e.target.checked)} />
                  <div className="slider" />
                </label>
                <span style={{ fontSize: 13 }}>FEC</span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
