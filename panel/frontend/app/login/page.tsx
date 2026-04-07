"use client";
import { useState } from "react";
import { api, setToken } from "@/lib/api";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await api.login(username, password);
      setToken(data.token);
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "radial-gradient(ellipse at top, #1a1a2e 0%, #0a0a0f 70%)",
    }}>
      <div style={{
        background: "rgba(22, 22, 31, 0.9)",
        backdropFilter: "blur(20px)",
        border: "1px solid var(--border)",
        borderRadius: "20px",
        padding: "48px",
        width: "420px",
        boxShadow: "0 25px 50px -12px rgba(0,0,0,0.5)",
      }}>
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: "32px" }}>
          <div style={{
            width: 56, height: 56, borderRadius: 16,
            background: "linear-gradient(135deg, #6366f1, #8b5cf6)",
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            fontSize: 24, fontWeight: 700, color: "white", marginBottom: 16,
          }}>
            SP
          </div>
          <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 4 }}>Spoof Panel</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: 14 }}>Sign in to your account</p>
        </div>

        {error && (
          <div style={{
            background: "#ef444420", border: "1px solid #ef4444",
            borderRadius: 8, padding: "10px 14px", marginBottom: 20,
            color: "#ef4444", fontSize: 13,
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: 20 }}>
            <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>
              Username
            </label>
            <input
              className="input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoFocus
              required
            />
          </div>

          <div style={{ marginBottom: 28 }}>
            <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>
              Password
            </label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
            />
          </div>

          <button
            className="btn btn-primary"
            type="submit"
            disabled={loading}
            style={{ width: "100%", justifyContent: "center", padding: "12px", fontSize: 15 }}
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
