"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface Inbound {
  id: number;
  type: string;
  listen: string;
  target: string;
  remote_port: number;
  enabled: boolean;
  remark: string;
}

export default function InboundsPage() {
  const [inbounds, setInbounds] = useState<Inbound[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<Inbound | null>(null);
  const [form, setForm] = useState({ type: "socks", listen: "", target: "", remote_port: 0, remark: "", enabled: true });

  const fetchInbounds = async () => {
    try {
      const data = await api.listInbounds();
      setInbounds(data || []);
    } catch {}
  };

  useEffect(() => { fetchInbounds(); }, []);

  const openCreate = () => {
    setEditing(null);
    setForm({ type: "socks", listen: "127.0.0.1:1080", target: "", remote_port: 0, remark: "", enabled: true });
    setShowModal(true);
  };

  const openEdit = (inb: Inbound) => {
    setEditing(inb);
    setForm({ type: inb.type, listen: inb.listen, target: inb.target, remote_port: inb.remote_port, remark: inb.remark, enabled: inb.enabled });
    setShowModal(true);
  };

  const handleSave = async () => {
    try {
      if (editing) {
        await api.updateInbound(editing.id, form);
      } else {
        await api.createInbound(form);
      }
      setShowModal(false);
      fetchInbounds();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this inbound?")) return;
    try {
      await api.deleteInbound(id);
      fetchInbounds();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleToggle = async (inb: Inbound) => {
    try {
      await api.updateInbound(inb.id, { ...inb, enabled: !inb.enabled });
      fetchInbounds();
    } catch {}
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
        <h1 style={{ fontSize: 28, fontWeight: 700 }}>Inbounds</h1>
        <button className="btn btn-primary" onClick={openCreate}>+ Add Inbound</button>
      </div>

      <div className="glass-card" style={{ padding: 0, overflow: "hidden" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Type</th>
              <th>Listen</th>
              <th>Target</th>
              <th>Remark</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {inbounds.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text-secondary)", padding: 40 }}>No inbounds configured. Click &quot;Add Inbound&quot; to create one.</td></tr>
            )}
            {inbounds.map((inb) => (
              <tr key={inb.id}>
                <td>
                  <label className="toggle">
                    <input type="checkbox" checked={inb.enabled} onChange={() => handleToggle(inb)} />
                    <div className="slider" />
                  </label>
                </td>
                <td>
                  <span className={`badge badge-${inb.type}`}>{inb.type}</span>
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 13 }}>{inb.listen}</td>
                <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                  {inb.type === "forward" && inb.target}
                  {inb.type === "relay" && inb.remote_port > 0 && `direct:${inb.remote_port}`}
                  {inb.type === "relay" && !inb.remote_port && "tunneled"}
                  {inb.type === "socks" && "—"}
                </td>
                <td style={{ color: "var(--text-secondary)" }}>{inb.remark || "—"}</td>
                <td>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button className="btn btn-ghost" style={{ padding: "6px 12px", fontSize: 12 }} onClick={() => openEdit(inb)}>Edit</button>
                    <button className="btn btn-danger" style={{ padding: "6px 12px", fontSize: 12 }} onClick={() => handleDelete(inb.id)}>Delete</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 24 }}>
              {editing ? "Edit Inbound" : "New Inbound"}
            </h2>

            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Type</label>
                <select className="input" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                  <option value="socks">SOCKS5 Proxy</option>
                  <option value="relay">UDP Relay</option>
                  <option value="forward">TCP Forward</option>
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Listen Address</label>
                <input className="input" value={form.listen} onChange={(e) => setForm({ ...form, listen: e.target.value })} placeholder="127.0.0.1:1080" />
              </div>

              {form.type === "forward" && (
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Target Address</label>
                  <input className="input" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} placeholder="10.0.0.1:22" />
                </div>
              )}

              {form.type === "relay" && (
                <div>
                  <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Remote Port (0 = tunneled, &gt;0 = direct bypass)</label>
                  <input className="input" type="number" value={form.remote_port} onChange={(e) => setForm({ ...form, remote_port: parseInt(e.target.value) || 0 })} placeholder="8091" />
                </div>
              )}

              <div>
                <label style={{ display: "block", fontSize: 13, color: "var(--text-secondary)", marginBottom: 6 }}>Remark</label>
                <input className="input" value={form.remark} onChange={(e) => setForm({ ...form, remark: e.target.value })} placeholder="Optional note" />
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 12, marginTop: 28 }}>
              <button className="btn btn-ghost" onClick={() => setShowModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleSave}>
                {editing ? "Save" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
