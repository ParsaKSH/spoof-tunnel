"use client";
import { useEffect } from "react";

export default function Home() {
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      window.location.href = "/dashboard";
    } else {
      window.location.href = "/login";
    }
  }, []);

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh" }}>
      <div className="status-dot starting" style={{ width: 20, height: 20 }} />
    </div>
  );
}
