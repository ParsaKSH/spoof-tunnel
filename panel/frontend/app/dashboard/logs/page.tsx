"use client";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

export default function LogsPage() {
  const [logs, setLogs] = useState<string[]>([]);
  const [connected, setConnected] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const logEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/api/tunnel/logs?token=${token}`;

    const connect = () => {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000);
      };
      ws.onmessage = (e) => {
        setLogs((prev) => {
          const next = [...prev, e.data];
          if (next.length > 500) return next.slice(-500);
          return next;
        });
      };
    };

    connect();
    return () => wsRef.current?.close();
  }, []);

  useEffect(() => {
    if (autoScroll) logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs, autoScroll]);

  const classifyLine = (line: string) => {
    if (line.includes("ERROR") || line.includes("error") || line.includes("FATAL")) return "log-error";
    if (line.includes("WARN") || line.includes("warn")) return "log-warn";
    if (line.includes("[") && line.includes("]")) return "log-info";
    return "";
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>
          Logs
          <span style={{ 
            marginLeft: 12, fontSize: 12, padding: "4px 10px", borderRadius: 6,
            background: connected ? "#22c55e20" : "#ef444420",
            color: connected ? "#22c55e" : "#ef4444",
          }}>
            {connected ? "● Connected" : "○ Disconnected"}
          </span>
        </h1>
        <div style={{ display: "flex", gap: 12 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "var(--text-secondary)" }}>
            <label className="toggle">
              <input type="checkbox" checked={autoScroll} onChange={() => setAutoScroll(!autoScroll)} />
              <div className="slider" />
            </label>
            Auto-scroll
          </label>
          <button className="btn btn-ghost" onClick={() => setLogs([])}>Clear</button>
        </div>
      </div>

      <div className="log-viewer">
        {logs.length === 0 && (
          <div style={{ color: "var(--text-secondary)", textAlign: "center", paddingTop: 40 }}>
            No logs yet. Start the tunnel to see output.
          </div>
        )}
        {logs.map((line, i) => (
          <div key={i} className={classifyLine(line)}>{line}</div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
