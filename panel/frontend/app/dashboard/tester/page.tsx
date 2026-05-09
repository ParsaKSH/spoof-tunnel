"use client";
import { useState, useEffect, useRef } from "react";
import { api } from "@/lib/api";

type TesterResult = {
  ip: string;
  received: number;
  sent: number;
  loss_pct: number;
  passed: boolean;
};

type TesterState = {
  status: string;
  mode: string;
  error?: string;
  progress: number;
  total_ips: number;
  passed_count: number;
  recv_count: number;
  results: TesterResult[];
};

export default function TesterPage() {
  const [tab, setTab] = useState<"receiver" | "sender">("receiver");
  const [state, setState] = useState<TesterState>({ status: "idle", mode: "", progress: 0, total_ips: 0, passed_count: 0, recv_count: 0, results: [] });
  const [ipList, setIpList] = useState("");
  const [copied, setCopied] = useState(false);
  const [protocol, setProtocol] = useState("icmp");
  const [dstIP, setDstIP] = useState("");
  const [dstPort, setDstPort] = useState(80);
  const [timeout, setTimeout_] = useState(30);
  const [packetCount, setPacketCount] = useState(10);
  const [maxLoss, setMaxLoss] = useState(20);
  const [concurrency, setConcurrency] = useState(100);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const pollRef = useRef<NodeJS.Timeout | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Poll status while running
  useEffect(() => {
    if (state.status === "running") {
      pollRef.current = setInterval(async () => {
        try {
          const s = await api.testerStatus();
          setState({ ...s, results: s.results || [] });
          if (s.status !== "running" && pollRef.current) {
            clearInterval(pollRef.current);
          }
        } catch { }
      }, 2000);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [state.status]);

  const handleStart = async () => {
    if (!ipList.trim()) { setError("Enter source IPs"); return; }
    if (tab === "sender" && !dstIP.trim()) { setError("Enter destination IP"); return; }
    setError("");
    setLoading(true);
    try {
      await api.testerStart({
        mode: tab,
        protocol,
        ip_list: ipList,
        dst_ip: dstIP,
        dst_port: dstPort,
        timeout: timeout,
        packet_count: packetCount,
        max_packet_loss: maxLoss,
        concurrency,
      });
      setState({ status: "running", mode: tab, progress: 0, total_ips: 0, passed_count: 0, recv_count: 0, results: [] });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    try {
      await api.testerStop();
      setState(prev => ({ ...prev, status: "idle" }));
    } catch { }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const result = await api.testerUpload(file);
      setIpList(result.content);
    } catch (err: any) {
      setError(err.message);
    }
    e.target.value = "";
  };

  const copyToClipboard = (text: string) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
  };

  const handleCopyPassedIPs = () => {
    const ips = results.filter(r => r.passed).map(r => r.ip).join("\n");
    copyToClipboard(ips);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPassedIPs = () => {
    const ips = results.filter(r => r.passed).map(r => r.ip).join("\n") + "\n";
    const blob = new Blob([ips], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "spoof-ips.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  const results = state.results || [];
  const passedCount = state.passed_count || results.filter(r => r.passed).length;
  const totalIPs = state.total_ips || results.length;
  const receivedCount = results.length;

  const lossColor = (pct: number) => {
    if (pct <= 10) return "var(--success)";
    if (pct <= 30) return "var(--warning)";
    return "var(--danger)";
  };

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>🔬 Spoof Tester</h1>
      <p style={{ color: "var(--text-secondary)", marginBottom: 24, fontSize: 14 }}>
        Test which spoofed IPs can reach a destination. Run <strong>receiver</strong> on the remote server, then <strong>sender</strong> on the local side.
      </p>

      {/* Tab Selector */}
      <div style={{ display: "flex", gap: 0, marginBottom: 24 }}>
        {(["receiver", "sender"] as const).map(t => (
          <button
            key={t}
            onClick={() => { setTab(t); setError(""); }}
            style={{
              padding: "10px 28px",
              background: tab === t ? "var(--accent)" : "var(--bg-card)",
              color: tab === t ? "white" : "var(--text-secondary)",
              border: `1px solid ${tab === t ? "var(--accent)" : "var(--border)"}`,
              borderRadius: t === "receiver" ? "8px 0 0 8px" : "0 8px 8px 0",
              cursor: "pointer",
              fontWeight: 600,
              fontSize: 14,
              transition: "all 0.2s",
            }}
          >
            {t === "receiver" ? "📡 Receiver" : "📤 Sender"}
          </button>
        ))}
      </div>

      <div className="responsive-grid" style={{ gap: 24 }}>
        {/* Left: Config */}
        <div className="glass-card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
            {tab === "receiver" ? "Receiver Config" : "Sender Config"}
          </h3>

          {/* Protocol */}
          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>Protocol</label>
            <select className="input" value={protocol} onChange={e => setProtocol(e.target.value)}>
              <option value="icmp">ICMP</option>
              <option value="tcp">TCP</option>
            </select>
          </div>

          {/* Sender: Destination IP */}
          {tab === "sender" && (
            <>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>Destination IP (Receiver Server)</label>
                <input className="input" value={dstIP} onChange={e => setDstIP(e.target.value)} placeholder="e.g. 1.2.3.4" />
              </div>
              {protocol === "tcp" && (
                <div style={{ marginBottom: 14 }}>
                  <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>Destination Port</label>
                  <input className="input" type="number" value={dstPort} onChange={e => setDstPort(+e.target.value)} />
                </div>
              )}
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>Concurrency</label>
                <input className="input" type="number" value={concurrency} onChange={e => setConcurrency(+e.target.value)} min={1} max={1000} />
              </div>
            </>
          )}

          {/* Receiver: Timeout */}
          {tab === "receiver" && (
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>Timeout (seconds)</label>
              <input className="input" type="number" value={timeout} onChange={e => setTimeout_(+e.target.value)} min={5} max={300} />
            </div>
          )}

          {/* Shared: Packet Count */}
          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>Packets Per IP</label>
            <input className="input" type="number" value={packetCount} onChange={e => setPacketCount(+e.target.value)} min={1} max={100} />
          </div>

          {/* Receiver: Max Loss */}
          {tab === "receiver" && (
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 13, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>
                Max Packet Loss: <strong style={{ color: "var(--text-primary)" }}>{maxLoss}%</strong>
              </label>
              <input type="range" min={0} max={100} value={maxLoss} onChange={e => setMaxLoss(+e.target.value)}
                style={{ width: "100%", accentColor: "var(--accent)" }} />
            </div>
          )}

          {/* Source IP List */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <label style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                Source IPs (one per line, CIDR, ranges)
              </label>
              <button className="btn btn-ghost" style={{ padding: "4px 10px", fontSize: 12 }} onClick={() => fileInputRef.current?.click()}>
                📁 Upload File
              </button>
              <input type="file" ref={fileInputRef} onChange={handleFileUpload} style={{ display: "none" }} accept=".txt,.csv,.list" />
            </div>
            <textarea
              className="input"
              value={ipList}
              onChange={e => setIpList(e.target.value)}
              placeholder={"192.168.1.1\n10.0.0.0/24\n172.16.0.1-172.16.0.50"}
              rows={8}
              style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, resize: "vertical" }}
            />
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4 }}>
              {ipList.trim() ? `${ipList.trim().split("\n").filter(l => l.trim()).length} lines` : "No IPs entered"}
            </div>
          </div>

          {error && (
            <div style={{ background: "#ef444420", border: "1px solid var(--danger)", borderRadius: 8, padding: "8px 12px", marginBottom: 14, color: "var(--danger)", fontSize: 13 }}>
              {error}
            </div>
          )}

          {/* Buttons */}
          <div style={{ display: "flex", gap: 8 }}>
            {state.status !== "running" ? (
              <button className="btn btn-primary" onClick={handleStart} disabled={loading} style={{ flex: 1 }}>
                {loading ? "Starting..." : `▶ Start ${tab === "receiver" ? "Receiver" : "Sender"}`}
              </button>
            ) : (
              <button className="btn btn-danger" onClick={handleStop} style={{ flex: 1 }}>
                ⏹ Stop
              </button>
            )}
          </div>
        </div>

        {/* Right: Status + Results */}
        <div className="glass-card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Status & Results</h3>

          {/* Status */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
            <div className={`status-dot ${state.status === "running" ? "running" : state.status === "done" ? "running" : "stopped"}`} />
            <span style={{ fontSize: 14, fontWeight: 500, textTransform: "uppercase" }}>
              {state.status} {state.mode ? `(${state.mode})` : ""}
            </span>
          </div>

          {/* Progress */}
          {state.status === "running" && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Progress</span>
                <span style={{ fontSize: 12, color: "var(--accent)" }}>{state.progress}%</span>
              </div>
              <div style={{ height: 6, background: "var(--bg-secondary)", borderRadius: 3, overflow: "hidden" }}>
                <div style={{
                  width: `${state.progress}%`,
                  height: "100%",
                  background: "linear-gradient(90deg, var(--accent), #8b5cf6)",
                  borderRadius: 3,
                  transition: "width 0.5s",
                }} />
              </div>
            </div>
          )}

          {/* Error */}
          {state.error && (
            <div style={{ background: "#ef444420", border: "1px solid var(--danger)", borderRadius: 8, padding: "8px 12px", marginBottom: 16, color: "var(--danger)", fontSize: 13 }}>
              {state.error}
            </div>
          )}

          {/* Results Summary */}
          {(results.length > 0 || state.recv_count > 0) && (
            <>
              {/* Live indicator */}
              {state.status === "running" && state.mode === "receiver" && (
                <div style={{
                  display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
                  padding: "8px 14px", borderRadius: 8,
                  background: "#22c55e10", border: "1px solid #22c55e30",
                }}>
                  <span style={{
                    display: "inline-block", width: 8, height: 8, borderRadius: "50%",
                    background: "#22c55e", animation: "pulse 1.5s infinite",
                  }} />
                  <span style={{ fontSize: 13, fontWeight: 600, color: "var(--success)" }}>LIVE</span>
                  <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                    Receiving packets... {state.recv_count} IPs detected so far
                  </span>
                </div>
              )}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 16 }}>
                <div style={{ background: "var(--bg-secondary)", borderRadius: 8, padding: "12px", textAlign: "center" }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)" }}>{totalIPs.toLocaleString()}</div>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>Total IPs</div>
                </div>
                <div style={{ background: "#22c55e15", borderRadius: 8, padding: "12px", textAlign: "center" }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: "var(--success)" }}>{passedCount}</div>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>Passed</div>
                </div>
                <div style={{ background: "#3b82f615", borderRadius: 8, padding: "12px", textAlign: "center" }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: "#3b82f6" }}>{receivedCount}</div>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>Received</div>
                </div>
              </div>

              {/* Action buttons */}
              <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
                <button
                  className="btn btn-ghost"
                  onClick={handleCopyPassedIPs}
                  style={{
                    fontSize: 12,
                    transition: "all 0.3s",
                    background: copied ? "var(--success)" : undefined,
                    color: copied ? "white" : undefined,
                    borderColor: copied ? "var(--success)" : undefined,
                  }}
                >
                  {copied ? "✓ Copied!" : "📋 Copy Passed IPs"}
                </button>
                <button className="btn btn-ghost" onClick={handleDownloadPassedIPs} style={{ fontSize: 12 }}>
                  📥 Download spoof-ips.txt
                </button>
              </div>

              {/* Results Table */}
              <div style={{ maxHeight: 360, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 8 }}>
                <table className="table" style={{ fontSize: 13 }}>
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Received</th>
                      <th>Loss</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((r, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace" }}>{r.ip}</td>
                        <td>{r.received}/{r.sent}</td>
                        <td style={{ color: lossColor(r.loss_pct), fontWeight: 600 }}>
                          {r.loss_pct.toFixed(1)}%
                        </td>
                        <td>
                          <span style={{
                            display: "inline-block",
                            padding: "2px 8px",
                            borderRadius: 4,
                            fontSize: 11,
                            fontWeight: 600,
                            background: r.passed ? "#22c55e20" : "#ef444420",
                            color: r.passed ? "var(--success)" : "var(--danger)",
                          }}>
                            {r.passed ? "PASS" : "FAIL"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {results.length === 0 && state.status === "idle" && (
            <div style={{ textAlign: "center", padding: 48, color: "var(--text-secondary)" }}>
              <div style={{ fontSize: 48, marginBottom: 12 }}>🔬</div>
              <p>Start a test to see results here.</p>
              <p style={{ fontSize: 12, marginTop: 8 }}>
                Run <strong>receiver</strong> on remote, then <strong>sender</strong> on local.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
