"use client";
import { useState } from "react";
import { api, setToken } from "@/lib/api";

export default function SettingsPage() {
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (newPass !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (newPass.length < 6) {
      setError("Password must be at least 6 characters");
      return;
    }

    setLoading(true);
    try {
      const data = await api.changePassword(oldPass, newPass);
      if (data.token) setToken(data.token);
      setSuccess("Password changed successfully!");
      setOldPass("");
      setNewPass("");
      setConfirm("");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 32 }}>Settings</h1>

      <div className="glass-card" style={{ maxWidth: 480 }}>
        <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 24 }}>Change Password</h2>

        {error && (
          <div style={{ background: "#ef444420", border: "1px solid #ef4444", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#ef4444", fontSize: 13 }}>
            {error}
          </div>
        )}
        {success && (
          <div style={{ background: "#22c55e20", border: "1px solid #22c55e", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#22c55e", fontSize: 13 }}>
            {success}
          </div>
        )}

        <form onSubmit={handleChangePassword} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Current Password</label>
            <input className="input" type="password" value={oldPass} onChange={(e) => setOldPass(e.target.value)} required />
          </div>
          <div>
            <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>New Password</label>
            <input className="input" type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} required />
          </div>
          <div>
            <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Confirm New Password</label>
            <input className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
          </div>
          <button className="btn btn-primary" type="submit" disabled={loading} style={{ marginTop: 8 }}>
            {loading ? "Changing..." : "Change Password"}
          </button>
        </form>
      </div>
    </div>
  );
}
