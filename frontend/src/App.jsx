/* eslint-disable react-hooks/exhaustive-deps */
import { useState, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import {
  ResponsiveContainer, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from "recharts";
import {
  LayoutDashboard,
  Activity,
  Cpu,
  AlertTriangle,
  FileText,
  Scan,
  FileCode,
  Users,
  ShieldCheck,
  FileBarChart,
  Lock,
  Unlock,
  Shield,
  ShieldAlert,
  Server,
  HardDrive,
  Globe,
  Microscope,
  Clock,
  Zap,
  Flame,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Info,
  ChevronUp,
  ChevronDown,
  Search,
  Monitor,
  Wrench,
  Usb,
  Trash2,
  Check,
  X,
  Play,
  RotateCcw,
  LogOut,
  Menu
} from "lucide-react";
import "./styles.css";

/* ─── Constants ─── */
const MAX_HIST = 30;
const API_BASE = "";

/* ─── Token helpers ─── */
function getTokenPayload() {
  const token = localStorage.getItem("hids_jwt_token");
  if (!token) return null;
  try {
    const b64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(b64));
  } catch(_) { return null; }
}

function isTokenExpired() {
  const payload = getTokenPayload();
  if (!payload?.exp) return true;
  return Date.now() / 1000 > payload.exp;
}

function getTokenExpiresIn() {
  const payload = getTokenPayload();
  if (!payload?.exp) return null;
  return Math.max(0, Math.round(payload.exp - Date.now() / 1000));
}

// Global auth-expired event — any component can listen
const AUTH_EXPIRED_EVENT = "hids_auth_expired";
function fireAuthExpired() { window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT)); }

/* ─── API helper ─── */
async function api(url, opts = {}) {
  const token = localStorage.getItem("hids_jwt_token");
  // Proactive check: if token is already expired don't even send the request
  if (token && isTokenExpired()) {
    fireAuthExpired();
    throw new Error("Token has expired — please log in again");
  }
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(API_BASE + url, { ...opts, headers });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const j = await res.json(); msg = j.detail || msg; } catch(_) {}
    // 401 = expired or invalid token → trigger global logout
    if (res.status === 401) {
      fireAuthExpired();
    }
    throw new Error(msg);
  }
  return res.json();
}

/* ─── Formatters ─── */
function fTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts.includes("T") || ts.includes("Z") ? ts : ts.replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}
function sevClass(s = "") {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high")     return "high";
  if (lower === "medium")   return "medium";
  return "low";
}

/* ─── Count-up hook ─── */
function useCountUp(target, duration = 600) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (target === 0) { setVal(0); return; }
    const start = Date.now();
    const frame = () => {
      const pct = Math.min(1, (Date.now() - start) / duration);
      setVal(Math.round(target * pct));
      if (pct < 1) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }, [target]);
  return val;
}

/* ─── Uptime helpers ─── */
// Returns a live-ticking uptime in seconds derived from the PC boot epoch.
// Ticks every 1 second entirely on the client — no server poll needed.
function useSystemUptime(bootEpochSeconds) {
  const compute = () =>
    bootEpochSeconds ? Math.floor(Date.now() / 1000 - bootEpochSeconds) : 0;
  const [secs, setSecs] = useState(compute);
  useEffect(() => {
    if (!bootEpochSeconds) return;
    setSecs(compute());
    const t = setInterval(() => setSecs(compute()), 1000);
    return () => clearInterval(t);
  }, [bootEpochSeconds]);
  return secs;
}

function formatUptime(totalSecs) {
  if (!totalSecs || totalSecs <= 0) return "00:00:00";
  const d = Math.floor(totalSecs / 86400);
  const h = Math.floor((totalSecs % 86400) / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  const s = totalSecs % 60;
  const hms = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  return d > 0 ? `${d}d ${hms}` : hms;
}

/* ─── Animated Background ─── */
function BgCanvas() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    let raf;
    let mouse = { x: window.innerWidth / 2, y: window.innerHeight / 2, active: false };

    const handleMouseMove = (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    };

    const handleMouseLeave = () => {
      mouse.active = false;
    };

    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseleave", handleMouseLeave);

    const pts = Array.from({ length: 65 }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - .5) * .35,
      vy: (Math.random() - .5) * .35,
      r: Math.random() * 1.6 + .5,
    }));

    const tick = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      // Ambient gradient
      const grad = ctx.createRadialGradient(canvas.width*.35, canvas.height*.3, 0, canvas.width*.5, canvas.height*.5, canvas.width*.8);
      grad.addColorStop(0, "rgba(15,25,60,.5)");
      grad.addColorStop(1, "rgba(6,8,18,0)");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Mouse Spotlight Glow
      if (mouse.active) {
        const mouseGrad = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 350);
        mouseGrad.addColorStop(0, "rgba(6,182,212,.14)");
        mouseGrad.addColorStop(0.5, "rgba(59,130,246,.05)");
        mouseGrad.addColorStop(1, "transparent");
        ctx.fillStyle = mouseGrad;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
      }

      // Particles
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width)  p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(59,130,246,.3)";
        ctx.fill();

        // Connect to mouse if close
        if (mouse.active) {
          const mdx = p.x - mouse.x;
          const mdy = p.y - mouse.y;
          const mdist = Math.sqrt(mdx*mdx + mdy*mdy);
          if (mdist < 140) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(mouse.x, mouse.y);
            ctx.strokeStyle = `rgba(6,182,212,${.22 * (1 - mdist/140)})`;
            ctx.lineWidth = .7;
            ctx.stroke();
          }
        }
      });

      // Connections between particles
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x;
          const dy = pts[i].y - pts[j].y;
          const dist = Math.sqrt(dx*dx + dy*dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(pts[i].x, pts[i].y);
            ctx.lineTo(pts[j].x, pts[j].y);
            ctx.strokeStyle = `rgba(59,130,246,${.08 * (1 - dist/120)})`;
            ctx.lineWidth = .5;
            ctx.stroke();
          }
        }
      }
      raf = requestAnimationFrame(tick);
    };
    tick();
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);
  return <canvas ref={canvasRef} className="bg-canvas" />;
}

/* ─── Custom Tooltip ─── */
function CTip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tip">
      <div style={{ fontFamily: "var(--mono)", fontSize: ".68rem", color: "var(--muted)", marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: ".75rem" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: p.color, flexShrink: 0 }} />
          <span style={{ color: "var(--muted)", fontFamily: "var(--mono)" }}>{p.name}:</span>
          <strong style={{ color: p.color, fontFamily: "var(--mono)" }}>{typeof p.value === "number" ? p.value.toFixed(1) : p.value}</strong>
        </div>
      ))}
    </div>
  );
}

/* ─── Mini Bar ─── */
function MiniBar({ value = 0, color = "#3b82f6" }) {
  const pct = Math.min(100, Math.max(0, parseFloat(value) || 0));
  return (
    <div className="mbar">
      <span className="mbar-val" style={{ color }}>{pct.toFixed(1)}%</span>
      <div className="mbar-track"><div className="mbar-fill" style={{ width: `${pct}%`, background: color }} /></div>
    </div>
  );
}

/* ─── Live Area Chart ─── */
function LiveAreaChart({ data, names, prefix, height = 180 }) {
  const colors = ["#3b82f6","#06b6d4","#10b981","#8b5cf6","#f59e0b"];
  if (!data.length) return <div className="empty-chart">Waiting for telemetry…</div>;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <defs>
          {names.map((n, i) => (
            <linearGradient key={n} id={`${prefix}-g${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={colors[i % colors.length]} stopOpacity={.25} />
              <stop offset="95%" stopColor={colors[i % colors.length]} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 4" stroke="rgba(148,170,206,.05)" />
        <XAxis dataKey="tick" tick={false} axisLine={false} tickLine={false} />
        <YAxis tick={{ fontSize: 10, fill: "#60748a" }} axisLine={false} tickLine={false} unit="%" />
        <Tooltip content={<CTip />} cursor={{ stroke: 'rgba(59,130,246,0.35)', strokeWidth: 1, strokeDasharray: '4 3' }} />
        {names.map((n, i) => (
          <Area key={n} type="monotone" dataKey={n} stroke={colors[i % colors.length]}
            strokeWidth={1.5} fill={`url(#${prefix}-g${i})`} dot={false} isAnimationActive={false} />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

/* ─── Empty State ─── */
function EmptyState({ text = "No data" }) {
  return (
    <div className="empty-state">
      <div className="radar" />
      <span>{text}</span>
    </div>
  );
}

/* ══════════════════════════════════════
   LOGIN SCREEN — Glassmorphism Edition
══════════════════════════════════════ */
function EyeIcon({ open }) {
  return open ? (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  ) : (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0110 0v4"/>
    </svg>
  );
}

function LoginScreen({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw]   = useState(false);
  const [error, setError]       = useState("");
  const [busy, setBusy]         = useState(false);
  const [focusField, setFocus]  = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) { const j = await res.json(); throw new Error(j.detail || "Login failed"); }
      const data = await res.json();
      localStorage.setItem("hids_jwt_token", data.access_token);
      localStorage.setItem("hids_jwt_user", data.username || username);
      localStorage.setItem("hids_jwt_role", data.role || "analyst");
      onLoginSuccess();
    } catch(e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div className="login-wrap">
      <BgCanvas />

      {/* Glassmorphism glow orbs */}
      <div className="login-orb login-orb-1" />
      <div className="login-orb login-orb-2" />
      <div className="login-orb login-orb-3" />

      <form className="login-card-v2" onSubmit={handleLogin} autoComplete="off">

        {/* Header */}
        <div className="login-header">
          <div className="login-logo-v2">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="#fff" strokeWidth="1.8" strokeLinejoin="round"/>
              <path d="M2 17l10 5 10-5" stroke="rgba(255,255,255,.7)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 12l10 5 10-5" stroke="rgba(255,255,255,.5)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div className="login-brand">
            <div className="login-badge-row">
              <span className="login-badge">
                <ShieldIcon /> SENTINEL v2.0
              </span>
            </div>
            <h1 className="login-heading">AI-HIDS Sentinel</h1>
            <p className="login-subheading">Host Intrusion Detection &amp; Threat Intelligence Platform</p>
          </div>
        </div>

        {/* Divider */}
        <div className="login-divider">
          <span>ANALYST AUTHENTICATION</span>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="login-error">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            {error}
          </div>
        )}

        {/* Fields */}
        <div className="login-fields">

          {/* Username */}
          <div className={`login-field-wrap ${focusField === "user" ? "focused" : ""}`}>
            <label className="login-label">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              Username
            </label>
            <div className="login-input-wrap">
              <input
                id="login-user"
                className="login-input"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                onFocus={() => setFocus("user")}
                onBlur={() => setFocus("")}
                placeholder="Enter your username"
                autoFocus
                autoComplete="username"
              />
            </div>
          </div>

          {/* Password */}
          <div className={`login-field-wrap ${focusField === "pass" ? "focused" : ""}`}>
            <label className="login-label">
              <LockIcon />
              Password
            </label>
            <div className="login-input-wrap">
              <input
                id="login-pass"
                className="login-input"
                type={showPw ? "text" : "password"}
                value={password}
                onChange={e => setPassword(e.target.value)}
                onFocus={() => setFocus("pass")}
                onBlur={() => setFocus("")}
                placeholder="••••••••••••"
                autoComplete="current-password"
              />
              <button
                type="button"
                className="login-pw-toggle"
                onClick={() => setShowPw(v => !v)}
                title={showPw ? "Hide password" : "Show password"}
                tabIndex={-1}
              >
                <EyeIcon open={showPw} />
              </button>
            </div>
          </div>
        </div>

        {/* Submit */}
        <button
          id="login-submit"
          type="submit"
          className={`login-btn ${busy ? "loading" : ""}`}
          disabled={busy || !username || !password}
        >
          {busy ? (
            <>
              <span className="login-spinner" />
              Authenticating…
            </>
          ) : (
            <>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
              Access Dashboard
            </>
          )}
        </button>

        {/* Security badges */}
        <div className="login-security-row">
          <span className="login-sec-badge emerald"><ShieldIcon /> bcrypt</span>
          <span className="login-sec-badge blue"><LockIcon /> HS512 JWT</span>
          <span className="login-sec-badge cyan">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><ellipse cx="12" cy="12" rx="10" ry="4"/><path d="M2 12c0 4 4.5 8 10 8s10-4 10-8"/><line x1="12" y1="2" x2="12" y2="22"/></svg>
            MongoDB Atlas
          </span>
        </div>

      </form>
    </div>
  );
}


/* ══════════════════════════════════════
   SIDEBAR NAV
══════════════════════════════════════ */
const NAV = [
  { id: "overview",  icon: LayoutDashboard, tip: "Overview" },
  { id: "monitor",   icon: Activity,        tip: "Monitor" },
  { id: "processes", icon: Cpu,             tip: "Processes" },
  { id: "alerts",    icon: AlertTriangle,   tip: "Alerts" },
  { id: "events",    icon: FileText,        tip: "Events" },
  { id: "simulate",  icon: Scan,            tip: "Scanner" },
  { id: "yara",      icon: FileCode,        tip: "YARA" },
  { id: "agents",    icon: Users,           tip: "Agents" },
  { id: "baseline",  icon: ShieldCheck,     tip: "Baseline" },
  { id: "report",    icon: FileBarChart,    tip: "Report" },
  { id: "admin",     icon: Lock,            tip: "Admin", adminOnly: true },
];

function Sidebar({ page, setPage, alertCount, monLive, onLogout, userRole }) {
  return (
    <nav className="sidebar">
      <div className="sb-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="#fff" strokeWidth="2" strokeLinejoin="round"/>
          <path d="M2 17l10 5 10-5M2 12l10 5 10-5" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </div>
      {NAV.filter(n => !n.adminOnly || userRole === "admin").map(n => {
        const Icon = n.icon;
        return (
          <button key={n.id} id={`nav-${n.id}`} className={`sb-btn ${page === n.id ? "active" : ""}`} onClick={() => setPage(n.id)} title={n.tip}>
            <Icon size={18} />
            {n.id === "alerts" && alertCount > 0 && <span className="sb-alert-dot" />}
            <span className="sb-tip">{n.tip}{n.id === "alerts" && alertCount > 0 ? ` (${alertCount})` : ""}</span>
          </button>
        );
      })}
      <div className="sb-bottom">
        <div className="sb-divider" />
        <button className="sb-btn" onClick={onLogout} title="Logout">
          <LogOut size={18} />
          <span className="sb-tip">Logout</span>
        </button>
      </div>
    </nav>
  );
}

function MobileDrawer({ open, onClose, page, setPage, alertCount, onLogout, userRole }) {
  return (
    <>
      <div className={`mobile-drawer-overlay ${open ? "open" : ""}`} onClick={onClose} />
      <div className={`mobile-drawer ${open ? "open" : ""}`}>
        <div className="mobile-drawer-header">
          <div className="flex-center gap-8">
            <div className="sb-logo" style={{ marginBottom: 0, width: 32, height: 32 }}>
              <Shield size={18} color="#fff" />
            </div>
            <strong style={{ fontSize: "0.95rem", color: "var(--text)" }}>AI-HIDS Sentinel</strong>
          </div>
          <button className="sb-btn" onClick={onClose} style={{ width: 32, height: 32 }}>
            <X size={18} />
          </button>
        </div>
        <div className="mobile-nav-list">
          {NAV.filter(n => !n.adminOnly || userRole === "admin").map(n => {
            const Icon = n.icon;
            return (
              <button
                key={n.id}
                id={`mobile-nav-${n.id}`}
                className={`mobile-nav-item ${page === n.id ? "active" : ""}`}
                onClick={() => { setPage(n.id); onClose(); }}
              >
                <Icon size={18} />
                <span>{n.tip}</span>
                {n.id === "alerts" && alertCount > 0 && (
                  <span className="pill critical mono" style={{ marginLeft: "auto", fontSize: ".65rem" }}>
                    {alertCount}
                  </span>
                )}
              </button>
            );
          })}
        </div>
        <div style={{ marginTop: "auto", paddingTop: 16, borderTop: "1px solid var(--border)" }}>
          <button className="mobile-nav-item" onClick={() => { onLogout(); onClose(); }} style={{ color: "var(--red)", width: "100%" }}>
            <LogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </>
  );
}

/* ══════════════════════════════════════
   OVERVIEW PAGE
══════════════════════════════════════ */
const METRIC_DEFS = [
  { id: "total_events",    label: "Total Events",   color: "var(--primary)", desc: "Total telemetry events ingested since last restart." },
  { id: "total_alerts",    label: "Alerts",         color: "var(--red)",     desc: "Security alerts generated by detection engine." },
  { id: "critical_alerts", label: "Critical",       color: "#ff4040",        desc: "Critical severity alerts requiring immediate action." },
  { id: "events_per_hour", label: "Events/hr",      color: "var(--cyan)",    desc: "Event ingestion rate in the last hour." },
  { id: "system_uptime",   label: "PC Uptime",      color: "var(--emerald)", desc: "Live system uptime since last PC boot (HH:MM:SS)." },
  { id: "anomaly_score",   label: "Anomaly Score",  color: "var(--amber)",   desc: "Average IsolationForest anomaly score across recent alerts." },
];

function MetricTile({ def, value, selected, onClick }) {
  // String values (e.g. formatted uptime "02:14:31") bypass the count-up animation
  const isString = typeof value === "string";
  const numVal   = isString ? 0 : (typeof value === "number" ? value : parseFloat(value) || 0);
  const animated = useCountUp(numVal);
  return (
    <div className={`metric-tile ${selected ? "sel" : ""}`} style={{ "--c": def.color }} onClick={onClick} id={`tile-${def.id}`}>
      <div className="metric-label">{def.label}</div>
      <div className="metric-val" style={isString ? { fontFamily: "var(--mono)", letterSpacing: "0.04em" } : {}}>
        {isString ? value : animated}
      </div>
    </div>
  );
}

function PageOverview({ metrics, alerts, events, system, monitor, setPage, topProc, selMetric, setSelMetric }) {
  const [cpuH, setCpuH] = useState([]);
  const [evH,  setEvH]  = useState([]);
  const tick = useRef(0);

  useEffect(() => {
    if (!topProc?.length) return;
    tick.current++;
    const t = tick.current;
    const cpu = { tick: t };
    topProc.slice(0, 5).forEach(p => { cpu[p.name] = parseFloat(p.cpu_percent) || 0; });
    setCpuH(h => { const n = [...h, cpu]; return n.length > MAX_HIST ? n.slice(-MAX_HIST) : n; });
  }, [topProc]);

  useEffect(() => {
    if (!events?.length) return;
    tick.current++;
    setEvH(h => {
      const n = [...h, { tick: tick.current, count: events.length }];
      return n.length > MAX_HIST ? n.slice(-MAX_HIST) : n;
    });
  }, [events?.length]);

  const procNames = (topProc || []).slice(0, 5).map(p => p.name);
  const critCount   = alerts?.filter(a => a.severity?.toLowerCase() === "critical").length || 0;
  // Live uptime ticks every 1 second locally — no server round-trip
  const liveUptimeSecs = useSystemUptime(metrics?.system_boot_time);
  const metricVal = (id) => {
    if (id === "total_events")    return metrics?.total_events ?? events?.length ?? 0;
    if (id === "total_alerts")    return metrics?.total_alerts ?? alerts?.length ?? 0;
    if (id === "critical_alerts") return metrics?.critical_alerts ?? critCount;
    if (id === "events_per_hour") return metrics?.events_per_hour ?? 0;
    if (id === "system_uptime")   return formatUptime(liveUptimeSecs);  // string → bypasses count-up
    if (id === "anomaly_score")   return parseFloat(metrics?.anomaly_score ?? 0).toFixed(2);
    return 0;
  };

  const selDef = METRIC_DEFS.find(d => d.id === selMetric) || METRIC_DEFS[0];
  const recentAlerts = (alerts || []).slice(0, 5);
  const recentEvents = (events || []).slice(0, 6);

  return (
    <div className="panel" style={{ gap: 12 }}>
      {/* Metric Row */}
      <div className="metric-row" style={{ flexShrink: 0 }}>
        {METRIC_DEFS.map(def => (
          <MetricTile key={def.id} def={def} value={metricVal(def.id)} selected={selMetric === def.id} onClick={() => setSelMetric(def.id)} />
        ))}
      </div>

      {/* Middle row */}
      <div className="grid-32 fill" style={{ minHeight: 0 }}>
        {/* Left: charts */}
        <div className="flex-col" style={{ minHeight: 0, gap: 10 }}>
          <div className="card" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
            <div className="card-hd">
              <div><p className="eyebrow">Live CPU Telemetry</p><h3>Top 5 Processes</h3></div>
              <div className="live-ring"><div className="live-ring-dot live" />LIVE</div>
            </div>
            <div style={{ flex: 1, minHeight: 0 }}>
              <LiveAreaChart data={cpuH} names={procNames} prefix="ov-cpu" height="100%" />
            </div>
          </div>

          <div className="card" style={{ flexShrink: 0 }}>
            <p className="eyebrow" style={{ marginBottom: 4 }}>{selDef.label}</p>
            <p className="metric-desc">{selDef.desc}</p>
          </div>
        </div>

        {/* Right: alerts + events feed */}
        <div className="flex-col" style={{ minHeight: 0, gap: 10 }}>
          <div className="card" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <div className="card-hd">
              <div><p className="eyebrow">Security Queue</p><h3>Recent Alerts</h3></div>
              <button className="btn ghost sm" onClick={() => setPage("alerts")}>View All →</button>
            </div>
            <div className="scroll-zone" style={{ flex: 1 }}>
              {recentAlerts.length ? recentAlerts.map(a => (
                <div key={a.id} className={`alert-card ${sevClass(a.severity) === "critical" ? "crit" : ""}`} style={{ marginBottom: 8 }}>
                  <div className="alert-hd">
                    <span className={`sev-dot ${sevClass(a.severity)}`} />
                    <strong style={{ flex: 1, fontSize: ".82rem" }}>{a.summary}</strong>
                    <span className={`pill ${sevClass(a.severity)}`}>{a.severity}</span>
                  </div>
                  <div className="alert-meta">
                    <span>{a.host || "—"}</span>
                    <span>·</span>
                    <span>{fTime(a.created_at)}</span>
                    {a.mitre_tags?.length > 0 && <><span>·</span><span style={{ color: "var(--violet)" }}>{a.mitre_tags[0]}</span></>}
                  </div>
                </div>
              )) : <EmptyState text="No alerts — system clean" />}
            </div>
          </div>

          <div className="card" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <div className="card-hd">
              <div><p className="eyebrow">Telemetry Stream</p><h3>Recent Events</h3></div>
              <button className="btn ghost sm" onClick={() => setPage("events")}>View All →</button>
            </div>
            <div className="scroll-zone" style={{ flex: 1 }}>
              {recentEvents.length ? recentEvents.map(ev => (
                <div key={ev.id} className="ev-card" style={{ marginBottom: 8 }}>
                  <div className="ev-top">
                    <span className="pill info" style={{ fontSize: ".65rem" }}>{ev.event_type}</span>
                    <span className="ev-type">{fTime(ev.timestamp || ev.created_at)}</span>
                  </div>
                  <div className="ev-who">
                    <span>{ev.user || "system"}</span>
                    <span style={{ color: "var(--subtle)" }}>on</span>
                    <span>{ev.host || "—"}</span>
                    {ev.process_name && <><span style={{ color: "var(--subtle)" }}>·</span><span style={{ color: "var(--cyan)" }}>{ev.process_name}</span></>}
                  </div>
                </div>
              )) : <EmptyState text="Waiting for telemetry…" />}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   MONITOR PAGE
══════════════════════════════════════ */
function PageMonitor({ system, monitor, busy, act }) {
  const procNames = (system.top_processes || []).slice(0, 5).map(p => p.name);
  const [cpuH, setCpuH] = useState([]);
  const [memH, setMemH] = useState([]);
  const tick = useRef(0);

  useEffect(() => {
    if (!system.top_processes?.length) return;
    tick.current++;
    const t = tick.current;
    const cpu = { tick: t }, mem = { tick: t };
    system.top_processes.slice(0, 5).forEach(p => {
      cpu[p.name] = parseFloat(p.cpu_percent) || 0;
      mem[p.name] = parseFloat(p.memory_percent) || 0;
    });
    setCpuH(h => { const n = [...h, cpu]; return n.length > MAX_HIST ? n.slice(-MAX_HIST) : n; });
    setMemH(h => { const n = [...h, mem]; return n.length > MAX_HIST ? n.slice(-MAX_HIST) : n; });
  }, [system.top_processes]);

  return (
    <div className="panel">
      {/* SOAR Controls */}
      <div className="soar-bar" style={{ flexShrink: 0 }}>
        <div className="soar-status">
          <div className={`live-ring-dot ${monitor.enabled ? "live" : ""}`} />
          <span style={{ fontFamily: "var(--mono)", fontSize: ".78rem" }}>
            Monitor: <strong style={{ color: monitor.enabled ? "var(--emerald)" : "var(--muted)" }}>
              {monitor.enabled ? "ACTIVE" : "STOPPED"}
            </strong>
          </span>
          <span style={{ color: "var(--subtle)", fontSize: ".72rem", fontFamily: "var(--mono)" }}>
            Host: {system.hostname || "—"} · OS: {system.os || "—"}
          </span>
        </div>
        <div className="action-row">
          <button id="btn-start-monitor" className="btn primary sm" onClick={() => act("start", "/api/monitor/start")} disabled={busy !== "" || monitor.enabled}>▶ Start</button>
          <button id="btn-stop-monitor"  className="btn ghost sm"   onClick={() => act("stop",  "/api/monitor/stop")}  disabled={busy !== "" || !monitor.enabled}>⏸ Stop</button>
          <button id="btn-scan"         className="btn secondary sm" onClick={() => act("scan",  "/api/monitor/scan")}  disabled={busy !== ""}>⬡ Force Scan</button>
        </div>
      </div>

      {/* Charts */}
      <div className="grid-2 fill" style={{ minHeight: 0 }}>
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-hd">
            <div><p className="eyebrow">Real-time</p><h3>CPU Usage — Live</h3></div>
            <div className="live-ring"><div className={`live-ring-dot ${monitor.enabled ? "live" : ""}`} />LIVE</div>
          </div>
          <div style={{ flex: 1, minHeight: 0 }}>
            <LiveAreaChart data={cpuH} names={procNames} prefix="mon-cpu" />
          </div>
        </div>
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-hd">
            <div><p className="eyebrow">Real-time</p><h3>Memory — Live</h3></div>
            <div className="live-ring"><div className={`live-ring-dot ${monitor.enabled ? "live" : ""}`} />LIVE</div>
          </div>
          <div style={{ flex: 1, minHeight: 0 }}>
            <LiveAreaChart data={memH} names={procNames} prefix="mon-mem" />
          </div>
        </div>
      </div>

      {/* Host info grid */}
      <div className="card" style={{ flexShrink: 0 }}>
        <p className="eyebrow" style={{ marginBottom: 8 }}>Host Telemetry Snapshot</p>
        <div className="stat-grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))" }}>
          {[
            ["Hostname",     system.hostname    || "—"],
            ["OS",           system.os          || "—"],
            ["CPU",          system.cpu_name    ? system.cpu_name.replace(/\(R\)/gi, "®").replace(/\(TM\)/gi, "™").split("@")[0].trim() : (system.cpu_count ? `${system.cpu_count} cores` : "—")],
            ["CPU Cores",    system.cpu_count   ? `${system.cpu_count} logical / ${system.cpu_physical_cores || "?"} physical` : "—"],
            ["RAM (GB)",     system.total_memory_gb ? `${parseFloat(system.total_memory_gb).toFixed(1)} GB` : "—"],
            ["Disk (GB)",    system.disk_total_gb   ? `${parseFloat(system.disk_total_gb).toFixed(0)} GB` : "—"],
            ["Manufacturer", system.manufacturer || "—"],
            ["Model",        system.model        || "—"],
            ["Architecture", system.os_arch      || "—"],
            ["Boot Time",    fTime(system.boot_time) || "—"],
            ["Platform",     system.platform     || "—"],
            ["Monitor Mode", monitor.mode        || system.monitor_mode || "—"],
          ].map(([l, v]) => (
            <div key={l} className="stat-item">
              <div className="lbl">{l}</div>
              <div className="val" style={{ fontSize: ".78rem", wordBreak: "break-word" }}>{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   PROCESSES PAGE
══════════════════════════════════════ */
function PageProcesses({ topProc = [], suspicious = [], setPage }) {
  const [search, setSearch] = useState("");
  const [modalProc, setModalProc] = useState(null);
  const [showSuspList, setShowSuspList] = useState(false);
  const [cpuH, setCpuH] = useState([]);
  const [memH, setMemH] = useState([]);
  const tick = useRef(0);

  useEffect(() => {
    if (!topProc?.length) return;
    tick.current++;
    const t = tick.current;
    const cpu = { tick: t }, mem = { tick: t };
    topProc.slice(0, 5).forEach(p => {
      cpu[p.name] = parseFloat(p.cpu_percent) || 0;
      mem[p.name] = parseFloat(p.memory_percent) || 0;
    });
    setCpuH(h => { const n = [...h, cpu]; return n.length > MAX_HIST ? n.slice(-MAX_HIST) : n; });
    setMemH(h => { const n = [...h, mem]; return n.length > MAX_HIST ? n.slice(-MAX_HIST) : n; });
  }, [topProc]);

  const names = (topProc || []).slice(0, 5).map(p => p.name);
  const filtered = topProc.filter(p => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (p.name?.toLowerCase().includes(q) || p.username?.toLowerCase().includes(q) || String(p.pid).includes(q));
  });

  const barData = (topProc || []).slice(0, 8).map(p => ({
    name: p.name?.length > 10 ? p.name.slice(0, 9) + "…" : p.name,
    CPU: parseFloat(p.cpu_percent) || 0,
    Memory: parseFloat(p.memory_percent) || 0,
  }));

  return (
    <div className="panel">
      {/* KPI strip */}
      <div className="flex-row" style={{ flexShrink: 0, gap: 10 }}>
        <div className="card" style={{ flex: 1, padding: "10px 14px" }}>
          <div className="metric-label">Tracked PIDs</div>
          <div style={{ fontSize: "1.4rem", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--cyan)" }}>{topProc.length}</div>
        </div>
        <div className="card tbl-click" style={{ flex: 1, padding: "10px 14px", borderColor: suspicious.length ? "rgba(239,68,68,.3)" : "var(--border)" }} onClick={() => setShowSuspList(true)}>
          <div className="metric-label" style={{ color: "var(--red)" }}>Suspicious Flags</div>
          <div style={{ fontSize: "1.4rem", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--red)" }}>{suspicious.length}</div>
        </div>
        <div style={{ flex: 3 }}>
          <input className="search-input" placeholder="Search by Name, PID, Username…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>

      {/* Main grid */}
      <div className="proc-layout fill" style={{ minHeight: 0 }}>
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-hd"><div><p className="eyebrow">Real-time</p><h3>CPU Live</h3></div><div className="live-ring"><div className="live-ring-dot live" />LIVE</div></div>
          <div style={{ flex: 1, minHeight: 0 }}><LiveAreaChart data={cpuH} names={names} prefix="pr-cpu" /></div>
        </div>
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-hd"><div><p className="eyebrow">Real-time</p><h3>Memory Live</h3></div><div className="live-ring"><div className="live-ring-dot live" />LIVE</div></div>
          <div style={{ flex: 1, minHeight: 0 }}><LiveAreaChart data={memH} names={names} prefix="pr-mem" /></div>
        </div>
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-hd"><div><p className="eyebrow">Snapshot</p><h3>CPU vs Memory</h3></div></div>
          {barData.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }} barGap={3}>
                <CartesianGrid strokeDasharray="3 4" stroke="rgba(148,170,206,.05)" />
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: "#60748a" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#60748a" }} axisLine={false} tickLine={false} unit="%" />
                <Tooltip content={<CTip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: ".7rem", color: "#60748a" }} />
                <Bar dataKey="CPU"    fill="#3b82f6" radius={[3,3,0,0]} maxBarSize={18} />
                <Bar dataKey="Memory" fill="#10b981" radius={[3,3,0,0]} maxBarSize={18} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyState text="No snapshot" />}
        </div>
        <div className="card" style={{ display: "flex", flexDirection: "column" }}>
          <div className="card-hd">
            <div><p className="eyebrow">All Workloads</p><h3>Process Table</h3></div>
            <span className="pill neutral">{filtered.length} PIDs</span>
          </div>
          <div className="scroll-zone fill">
            {filtered.length ? (
              <table className="tbl">
                <thead>
                  <tr><th>Process</th><th>PID</th><th>User</th><th>CPU</th><th>Mem</th></tr>
                </thead>
                <tbody>
                  {filtered.map(p => (
                    <tr key={`${p.pid}-${p.name}`}>
                      <td className="name">{p.name}</td>
                      <td><span className="pill neutral" style={{ fontSize: ".65rem" }}>{p.pid}</span></td>
                      <td className="dim">{p.username}</td>
                      <td><MiniBar value={p.cpu_percent}    color="#3b82f6" /></td>
                      <td><MiniBar value={p.memory_percent} color="#10b981" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <EmptyState text="No processes found" />}
          </div>
        </div>
      </div>

      {/* Suspicious modal */}
      {showSuspList && createPortal(
        <div className="modal-back" onClick={e => { if (e.target === e.currentTarget) setShowSuspList(false); }}>
          <div className="modal-box">
            <div className="modal-hd">
              <h2>⚠ Suspicious Processes ({suspicious.length})</h2>
              <button className="modal-close" onClick={() => setShowSuspList(false)}>✕</button>
            </div>
            {suspicious.length ? suspicious.map((p, i) => (
              <div key={i} className="agent-card" style={{ marginBottom: 8, cursor: "pointer" }} onClick={() => { setModalProc(p); setShowSuspList(false); }}>
                <div className="agent-icon" style={{ background: "var(--red-dim)" }}>⚠</div>
                <div className="agent-info">
                  <div className="agent-name">{p.name}</div>
                  <div className="agent-meta">PID {p.pid} · {p.username} · Score {p.score ?? p.anomaly_score ?? "—"}</div>
                </div>
                <span className="pill high">Inspect →</span>
              </div>
            )) : <EmptyState text="No suspicious processes" />}
          </div>
        </div>,
        document.body
      )}
      {modalProc && createPortal(
        <div className="modal-back" onClick={e => { if (e.target === e.currentTarget) setModalProc(null); }}>
          <div className="modal-box">
            <div className="modal-hd">
              <h2>⚠ {modalProc.name}</h2>
              <button className="modal-close" onClick={() => setModalProc(null)}>✕</button>
            </div>
            <div className="modal-chips">
              {[["PID", modalProc.pid], ["User", modalProc.username], ["CPU", `${parseFloat(modalProc.cpu_percent||0).toFixed(1)}%`], ["Mem", `${parseFloat(modalProc.memory_percent||0).toFixed(1)}%`], ["Score", modalProc.score ?? modalProc.anomaly_score ?? "—"]].map(([l, v]) => (
                <div key={l} className="modal-chip"><span>{l}</span> <strong>{v}</strong></div>
              ))}
            </div>
            {(modalProc.reasons || modalProc.flags || []).length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <p className="eyebrow" style={{ marginBottom: 6 }}>Why flagged</p>
                {(modalProc.reasons || modalProc.flags).map((r, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 6, marginBottom: 4, fontSize: ".8rem" }}>
                    <span style={{ color: "var(--red)", flexShrink: 0 }}>▸</span>
                    <span>{r}</span>
                  </div>
                ))}
              </div>
            )}
            {(modalProc.mitre_tags || modalProc.mitre || []).length > 0 && (
              <div>
                <p className="eyebrow" style={{ marginBottom: 6 }}>MITRE ATT&CK</p>
                <div className="ev-chips">
                  {(modalProc.mitre_tags || modalProc.mitre).map((t, i) => <div key={i} className="ev-chip"><strong>{t}</strong></div>)}
                </div>
              </div>
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}

/* ══════════════════════════════════════
   ALERTS PAGE
══════════════════════════════════════ */
function PageAlerts({ alerts }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const filtered = (alerts || []).filter(a => {
    if (filter !== "all" && sevClass(a.severity) !== filter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return a.summary?.toLowerCase().includes(q) || a.host?.toLowerCase().includes(q) || a.mitre_tags?.join(" ").toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="panel">
      <div className="flex-row" style={{ flexShrink: 0 }}>
        <p className="eyebrow" style={{ fontSize: ".8rem", color: "var(--text)", fontFamily: "var(--font)" }}>
          <strong>Security Alerts</strong>
        </p>
        <span className="pill info">{(alerts || []).length} total</span>
        <div className="chip-row" style={{ marginLeft: "auto" }}>
          {["all","critical","high","medium","low"].map(s => (
            <button key={s} className={`chip ${filter === s ? "active" : ""}`} onClick={() => setFilter(s)}>{s}</button>
          ))}
        </div>
        <input className="search-input" style={{ width: 220 }} placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      <div className="scroll-zone fill" style={{ minHeight: 0 }}>
        {filtered.length ? filtered.map(a => (
          <div key={a.id} className={`alert-card ${sevClass(a.severity) === "critical" ? "crit" : ""}`} style={{ marginBottom: 10 }}>
            <div className="alert-hd">
              <span className={`sev-dot ${sevClass(a.severity)}`} />
              <strong style={{ flex: 1 }}>{a.summary}</strong>
              <span className={`pill ${sevClass(a.severity)}`}>{a.severity}</span>
            </div>
            <div className="alert-meta">
              <span>{a.host || "—"}</span><span>·</span>
              <span>{fTime(a.created_at)}</span><span>·</span>
              <span>Score: <strong style={{ color: "var(--cyan)", fontFamily: "var(--mono)" }}>{a.score}</strong></span>
              {a.mitre_tags?.length > 0 && <><span>·</span><span style={{ color: "var(--violet)", fontFamily: "var(--mono)", fontSize: ".7rem" }}>{a.mitre_tags.join(", ")}</span></>}
            </div>
            {a.reasons?.length > 0 && (
              <p style={{ marginTop: 8, fontSize: ".75rem", color: "var(--muted)", lineHeight: 1.5 }}>{a.reasons.join(" · ")}</p>
            )}
          </div>
        )) : <EmptyState text="No alerts match filter" />}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   EVENTS PAGE
══════════════════════════════════════ */
function PageEvents({ events }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(new Set());
  const prevIds = useRef(new Set());
  const [freshIds, setFreshIds] = useState(new Set());

  useEffect(() => {
    const incoming = new Set((events || []).map(e => e.id));
    const fresh = new Set([...incoming].filter(id => !prevIds.current.has(id)));
    if (fresh.size > 0) {
      setFreshIds(fresh);
      const t = setTimeout(() => setFreshIds(new Set()), 2500);
      return () => clearTimeout(t);
    }
    prevIds.current = incoming;
  }, [events]);

  const filtered = (events || []).filter(e => {
    if (filter !== "all" && e.event_type !== filter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return [e.event_type, e.process_name, e.user, e.host].some(v => v?.toLowerCase().includes(q));
    }
    return true;
  });

  const toggle = id => setExpanded(prev => {
    const n = new Set(prev);
    n.has(id) ? n.delete(id) : n.add(id);
    return n;
  });

  const EVENT_TYPES = [...new Set((events || []).map(e => e.event_type).filter(Boolean))].slice(0, 6);

  return (
    <div className="panel">
      <div className="flex-row" style={{ flexShrink: 0, flexWrap: "wrap" }}>
        <div className="live-ring"><div className="live-ring-dot live" /><span style={{ fontFamily: "var(--mono)", fontSize: ".72rem" }}>LIVE STREAM</span></div>
        <div className="chip-row">
          <button className={`chip ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}>All ({(events||[]).length})</button>
          {EVENT_TYPES.map(t => (
            <button key={t} className={`chip ${filter === t ? "active" : ""}`} onClick={() => setFilter(t)}>{t}</button>
          ))}
        </div>
        <input className="search-input" style={{ width: 240, marginLeft: "auto" }} placeholder="Search events…" value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {/* Ticker */}
      {events?.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 10, background: "rgba(0,0,0,.3)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: "6px 12px", flexShrink: 0 }}>
          <span className="pill cyan" style={{ flexShrink: 0 }}>RECENT</span>
          <div className="ticker">
            <span className="ticker-inner">{(events||[]).slice(0,12).map(e => `${e.process_name || "system"}:${e.event_type}`).join(" · ")}</span>
          </div>
        </div>
      )}

      <div className="scroll-zone fill" style={{ minHeight: 0 }}>
        {filtered.length ? filtered.map((ev, idx) => {
          const isNew = freshIds.has(ev.id);
          const isOpen = expanded.has(ev.id);
          const meta = Object.entries(ev.metadata || {});
          return (
            <div key={ev.id} className={`ev-card ${isNew ? "fresh" : ""}`} style={{ marginBottom: 8, animationDelay: `${Math.min(idx * 30, 300)}ms` }}>
              <div className="ev-top">
                <span className="pill info">{ev.event_type}</span>
                {isNew && <span className="pill cyan" style={{ fontSize: ".6rem" }}>NEW</span>}
                <span className="ev-type">{fTime(ev.timestamp || ev.created_at)}</span>
              </div>
              <div className="ev-who">
                <span>{ev.user || "system"}</span>
                <span style={{ color: "var(--subtle)" }}>on</span>
                <span>{ev.host || "—"}</span>
                {ev.process_name && <><span style={{ color: "var(--subtle)" }}>·</span><span style={{ color: "var(--cyan)" }}>{ev.process_name}</span></>}
              </div>
              {meta.length > 0 && (
                <>
                  <button onClick={() => toggle(ev.id)} style={{ marginTop: 6, background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: ".7rem", fontFamily: "var(--mono)", padding: 0 }}>
                    {isOpen ? "▴ hide" : `▾ ${meta.length} attrs`}
                  </button>
                  {isOpen && (
                    <div className="ev-chips">
                      {meta.slice(0, 10).map(([k, v]) => (
                        <div key={k} className="ev-chip"><span>{k.replaceAll("_"," ")}:</span><strong>{String(v)}</strong></div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          );
        }) : <EmptyState text="No events match filter" />}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   DEEP SYSTEM SCANNER  (real hardware / firmware / IOC scan)
══════════════════════════════════════ */

// Small helper: colour a severity string
function SevBadge({ sev }) {
  const c = sev === "critical" ? "var(--red)" : sev === "high" ? "#f97316" : sev === "medium" ? "var(--amber)" : "var(--emerald)";
  return <span style={{ color: c, fontFamily: "var(--mono)", fontSize: ".68rem", fontWeight: 700, textTransform: "uppercase" }}>{sev}</span>;
}

// Collapsible card used throughout the scan results
function ScanCard({ title, icon: Icon, badge, badgeColor, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="card" style={{ flexShrink: 0 }}>
      <div className="card-hd" onClick={() => setOpen(o => !o)} style={{ cursor: "pointer", userSelect: "none" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ display: "flex", alignItems: "center", color: "var(--primary)" }}>
            {typeof Icon === "function" || (typeof Icon === "object" && Icon !== null) ? <Icon size={16} /> : Icon}
          </span>
          <h3 style={{ margin: 0, fontSize: ".85rem" }}>{title}</h3>
          {badge != null && (
            <span style={{ fontSize: ".65rem", background: badgeColor || "var(--surface)", color: "#fff", borderRadius: 4, padding: "2px 7px", fontFamily: "var(--mono)" }}>{badge}</span>
          )}
        </div>
        <span style={{ color: "var(--muted)", display: "flex", alignItems: "center" }}>{open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</span>
      </div>
      {open && <div style={{ padding: "12px 16px 16px", display: "flex", flexDirection: "column", gap: 8 }}>{children}</div>}
    </div>
  );
}

// Key-value row
function KVRow({ label, value, mono, color }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,.04)", padding: "5px 0", fontSize: ".78rem" }}>
      <span style={{ color: "var(--muted)" }}>{label}</span>
      <span style={{ fontFamily: mono ? "var(--mono)" : undefined, color: color || "var(--text)", maxWidth: "60%", textAlign: "right" }}>{value ?? "—"}</span>
    </div>
  );
}

// Progress steps shown while the real scan runs
const SCAN_STEPS = [
  "Reading BIOS / Firmware metadata…",
  "Detecting UEFI / Legacy BIOS type…",
  "Checking Secure Boot state…",
  "Querying TPM chip status…",
  "Collecting CPU, GPU, motherboard info…",
  "Scanning memory sticks & capacity…",
  "Enumerating disk partitions…",
  "Querying Windows Defender status…",
  "Checking Firewall profiles (Domain / Private / Public)…",
  "Checking pending Windows Updates…",
  "Scanning running services…",
  "Reading startup registry Run keys (HKLM + HKCU)…",
  "Scanning scheduled tasks for persistence IOCs…",
  "Enumerating network adapters & listening ports…",
  "Detecting connected USB / PnP devices…",
  "Scanning all running processes for IOC signatures…",
  "Computing security posture score…",
  "Finalising deep-scan report…",
];

function PageSimulate() {
  const [scanning, setScanning]       = useState(false);
  const [scanLog, setScanLog]         = useState([]);
  const [stepIdx, setStepIdx]         = useState(0);
  const [result, setResult]           = useState(null);
  const [error, setError]             = useState("");
  const [activeTab, setActiveTab]     = useState("posture");
  const stepRef = useRef(null);

  // Elevation state
  const [elevStatus,    setElevStatus]    = useState(null);
  const [elevData,      setElevData]      = useState(null);
  const [elevRunning,   setElevRunning]   = useState(false);
  const [elevError,     setElevError]     = useState("");
  const [showElevModal, setShowElevModal] = useState(false);

  // Finding detail popup
  const [findingDetail, setFindingDetail] = useState(null); // { finding, items[] }

  // Advance the progress log while waiting for the real API response
  function startStepTicker() {
    let i = 0;
    stepRef.current = setInterval(() => {
      i++;
      setStepIdx(Math.min(i, SCAN_STEPS.length - 1));
      setScanLog(prev => [...prev.slice(-30), `[${new Date().toLocaleTimeString()}] ${SCAN_STEPS[Math.min(i, SCAN_STEPS.length - 1)]}`]);
    }, 1500);
  }

  function stopStepTicker() {
    clearInterval(stepRef.current);
  }

  // ── Check elevation status on mount and after each scan ─────────────────
  async function checkElevStatus() {
    try {
      const s = await api("/api/system/elevation-status");
      setElevStatus(s);
      if (s.has_result) {
        const r = await api("/api/system/elevated-result");
        setElevData(r);
      }
    } catch (_) { /* ignore — elevation endpoints may not be loaded yet */ }
  }

  useEffect(() => { checkElevStatus(); }, []);

  // ── Elevated scan ─────────────────────────────────────────────────────────
  async function startElevatedScan() {
    setElevRunning(true);
    setElevError("");
    setShowElevModal(false);
    try {
      // This call blocks until the elevated PS finishes (up to 130s)
      const data = await api("/api/system/elevated-scan", { method: "POST" });
      setElevData(data);
      await checkElevStatus();
    } catch(e) {
      setElevError(e.message || "Elevated scan failed");
    } finally {
      setElevRunning(false);
    }
  }

  async function startScan() {
    if (scanning) return;
    setScanning(true); setResult(null); setError(""); setScanLog([]); setStepIdx(0);
    setScanLog([`[${new Date().toLocaleTimeString()}] Initiating real deep-scan of local system…`]);
    startStepTicker();
    try {
      const data = await api("/api/system/deep-scan", { method: "POST" });
      stopStepTicker();
      setScanLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ✅ Scan complete — posture score: ${data.posture?.score ?? "?"}/${100}`]);
      setResult(data);
    } catch (e) {
      stopStepTicker();
      setScanLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ❌ Scan error: ${e.message}`]);
      setError(e.message);
    } finally {
      setScanning(false);
    }
  }

  useEffect(() => () => stopStepTicker(), []);

  const pct = scanning ? Math.round((stepIdx / (SCAN_STEPS.length - 1)) * 95) : result ? 100 : 0;

  // ── Map a posture finding to its underlying data items ─────────────────────
  function resolveFindingItems(finding, scanResult) {
    if (!scanResult) return [];
    const cat = (finding.category || "").toLowerCase();
    const issue = (finding.issue || "").toLowerCase();

    // Startup / persistence
    if (cat === "persistence" || issue.includes("startup")) {
      const items = scanResult.persistence?.startup_items || [];
      // Return suspicious ones first, then all
      const sus = items.filter(x => x.suspicious || x.is_suspicious);
      return sus.length ? sus : items;
    }

    // Network open ports
    if (cat === "network" || issue.includes("port") || issue.includes("listen")) {
      return (scanResult.network?.open_ports || []).slice(0, 30);
    }

    // Processes
    if (cat === "process" || issue.includes("process") || issue.includes("unsigned")) {
      const procs = scanResult.processes?.list || scanResult.processes || [];
      const sus = procs.filter(p => p.suspicious || p.is_suspicious || p.unsigned);
      return sus.length ? sus : procs.slice(0, 20);
    }

    // Scheduled tasks
    if (cat === "tasks" || issue.includes("task") || issue.includes("scheduled")) {
      const tasks = scanResult.persistence?.scheduled_tasks || [];
      const sus = tasks.filter(t => t.suspicious || t.is_suspicious);
      return sus.length ? sus : tasks.slice(0, 20);
    }

    // Firewall
    if (cat === "firewall" || issue.includes("firewall")) {
      return [];
    }

    // Devices / USB
    if (cat === "devices" || issue.includes("device") || issue.includes("usb")) {
      const devs = scanResult.devices || [];
      return devs.filter(d => d.suspicious || d.is_suspicious || d.class?.toLowerCase().includes("usb"));
    }

    // Fallback: try persistence items
    return scanResult.persistence?.startup_items?.filter(x => x.suspicious || x.is_suspicious) || [];
  }

  // ── Render a single item row inside the finding detail modal ────────────────
  function renderDetailItem(item, idx) {
    // Startup items: { source, name, command, suspicious }
    // Processes:     { pid, process_name, image_path, suspicious, unsigned }
    // Ports:         { port, protocol, service }
    // Tasks:         { name, path, command, suspicious }
    const name   = item.name || item.process_name || item.program || item.service || `Item ${idx + 1}`;
    const path   = item.command || item.path || item.image_path || item.executable || "";
    const loc    = item.source  || item.location || item.registry_key || item.key || "";
    const pid    = item.pid  != null ? `PID ${item.pid}`   : null;
    const port   = item.port != null ? `:${item.port}`      : null;
    const proto  = item.protocol || null;
    const isSus  = item.suspicious || item.is_suspicious || item.unsigned;
    const reason = item.reason || (item.unsigned ? "Unsigned executable" : null);

    return (
      <div key={idx} style={{
        padding: "10px 14px", borderRadius: 8, marginBottom: 6,
        background: isSus ? "rgba(220,38,38,.07)" : "rgba(255,255,255,.03)",
        border: `1px solid ${isSus ? "rgba(220,38,38,.22)" : "rgba(255,255,255,.07)"}`,
      }}>
        {/* Row 1: name + badges */}
        <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
          <span style={{ fontSize:".82rem", fontWeight:700, color: isSus ? "var(--red)" : "var(--text)" }}>
            {isSus ? "⚠ " : ""}{name}
          </span>
          {pid   && <span style={{ fontSize:".68rem", color:"var(--muted)", fontFamily:"var(--mono)",
            background:"rgba(255,255,255,.06)", padding:"1px 6px", borderRadius:3 }}>{pid}</span>}
          {port  && <span style={{ fontSize:".68rem", color:"var(--cyan)", fontFamily:"var(--mono)",
            background:"rgba(99,179,237,.08)", padding:"1px 6px", borderRadius:3 }}>
            {proto ? `${proto}${port}` : port}
          </span>}
          {loc   && <span style={{ fontSize:".63rem", color:"var(--amber)", fontFamily:"var(--mono)",
            background:"rgba(251,191,36,.07)", padding:"1px 6px", borderRadius:3, maxWidth:240,
            overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }} title={loc}>
            {loc}
          </span>}
        </div>
        {/* Row 2: command / path */}
        {path && (
          <div style={{ fontSize:".7rem", color:"var(--muted)", fontFamily:"var(--mono)",
            marginTop:4, wordBreak:"break-all", lineHeight:1.5 }}>
            {path}
          </div>
        )}
        {/* Row 3: reason */}
        {reason && (
          <div style={{ fontSize:".68rem", color:"var(--red)", marginTop:4,
            display:"flex", alignItems:"center", gap:4 }}>
            ⚑ {reason}
          </div>
        )}
      </div>
    );
  }


  // --- Render helpers --------------------------------------------------------
  function renderPosture(posture, scanResult) {
    const score = posture?.score ?? 0;
    const grade = posture?.grade ?? "?";
    const scoreColor = score >= 90 ? "var(--emerald)" : score >= 70 ? "var(--amber)" : "var(--red)";
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {/* Big score */}
        <div style={{ display: "flex", alignItems: "center", gap: 20, padding: "16px", background: "rgba(255,255,255,.03)", borderRadius: 10, border: "1px solid rgba(255,255,255,.07)" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: "3rem", fontWeight: 900, fontFamily: "var(--mono)", color: scoreColor, lineHeight: 1 }}>{score}</div>
            <div style={{ fontSize: ".65rem", color: "var(--muted)", marginTop: 2 }}>/ 100</div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: scoreColor, fontFamily: "var(--mono)" }}>Grade {grade}</div>
            <div style={{ marginTop: 6, height: 8, background: "var(--surface)", borderRadius: 4, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${score}%`, background: scoreColor, borderRadius: 4, transition: "width 1s" }} />
            </div>
            <div style={{ fontSize: ".72rem", color: "var(--muted)", marginTop: 4 }}>
              {score >= 90 ? "Excellent security posture" : score >= 70 ? "Good — address the issues below" : score >= 50 ? "Fair — several risks detected" : "Poor — critical issues must be resolved immediately"}
            </div>
          </div>
        </div>
        {/* Findings – clickable */}
        {(posture?.findings || []).map((f, i) => {
          const items = resolveFindingItems(f, scanResult);
          const hasItems = items.length > 0;
          return (
            <div key={i}
              onClick={() => setFindingDetail({ finding: f, items })}
              style={{
                display: "flex", gap: 12, padding: "10px 14px",
                background: "rgba(255,255,255,.025)", borderRadius: 8,
                border: `1px solid ${f.severity === "critical" ? "rgba(255,60,60,.2)" : f.severity === "high" ? "rgba(249,115,22,.15)" : "rgba(255,255,255,.06)"}`,
                cursor: hasItems ? "pointer" : "default",
                transition: "background .15s, border-color .15s",
              }}
              onMouseEnter={e => { if(hasItems) { e.currentTarget.style.background="rgba(255,255,255,.05)"; e.currentTarget.style.borderColor = f.severity==="critical" ? "rgba(255,60,60,.5)" : "rgba(249,115,22,.4)"; } }}
              onMouseLeave={e => { e.currentTarget.style.background="rgba(255,255,255,.025)"; e.currentTarget.style.borderColor = f.severity==="critical" ? "rgba(255,60,60,.2)" : f.severity==="high" ? "rgba(249,115,22,.15)" : "rgba(255,255,255,.06)"; }}
            >
              <div style={{ fontSize: "1rem", flexShrink: 0 }}>
                {f.severity === "critical" ? "🚨" : f.severity === "high" ? "⚠️" : "ℹ️"}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 3 }}>
                  <SevBadge sev={f.severity} />
                  <span style={{ fontSize: ".78rem", fontWeight: 600 }}>{f.issue}</span>
                  <span style={{ marginLeft: "auto", display:"flex", alignItems:"center", gap:6 }}>
                    {hasItems && <span style={{ fontSize:".63rem", color:"var(--primary)", fontFamily:"var(--mono)" }}>🔍 click to view {items.length} item{items.length!==1?"s":""}</span>}
                    <span style={{ fontSize: ".65rem", color: "var(--muted)", fontFamily: "var(--mono)" }}>-{f.deduction}pts</span>
                  </span>
                </div>
                <div style={{ fontSize: ".72rem", color: "var(--cyan)" }}>Fix: {f.fix}</div>
              </div>
            </div>
          );
        })}
        {(posture?.findings || []).length === 0 && (
          <div style={{ color: "var(--emerald)", fontSize: ".82rem", textAlign: "center", padding: 16 }}>✅ No security issues detected</div>
        )}
      </div>
    );
  }

  function renderFirmware(fw, elev) {
    const bios  = fw?.bios || {};
    const sb    = elev?.secure_boot || fw?.secure_boot || {};
    const tpm   = elev?.tpm        || fw?.tpm         || {};
    const mb    = fw?.motherboard  || {};
    const ftStr = fw?.firmware_type || "Unknown";

    // Has the user done the elevated scan?
    const hasElev = !!elev;

    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>

        {/* ── Elevation banner ────────────────────────────────────── */}
        <div style={{ padding: "12px 16px", borderRadius: 10,
          background: hasElev ? "rgba(16,163,127,.08)" : "rgba(250,204,21,.06)",
          border: `1px solid ${hasElev ? "rgba(16,163,127,.3)" : "rgba(250,204,21,.25)"}`,
          display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <div style={{ fontSize: "1.4rem", display: "flex", alignItems: "center" }}>{hasElev ? <Unlock size={20} color="var(--emerald)" /> : <Lock size={20} color="var(--amber)" />}</div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontWeight: 700, fontSize: ".82rem",
              color: hasElev ? "var(--emerald)" : "var(--amber)" }}>
              {hasElev
                ? "Elevated data loaded — TPM and Secure Boot fetched with admin rights"
                : "Some firmware data requires Windows Administrator privileges"}
            </div>
            <div style={{ fontSize: ".7rem", color: "var(--muted)", marginTop: 2 }}>
              {hasElev
                ? `Last elevated scan: ${elev.scan_time ? new Date(elev.scan_time).toLocaleString() : "—"}`
                : "Get-Tpm and Confirm-SecureBootUEFI need admin access. Click below to trigger a UAC elevation prompt."}
            </div>
          </div>
          {elevRunning
            ? <div className="live-ring"><div className="live-ring-dot live" /><span style={{ fontSize: ".7rem", fontFamily:"var(--mono)" }}>Waiting for UAC…</span></div>
            : <button
                className={`btn ${hasElev ? "ghost" : "primary"} sm`}
                onClick={() => setShowElevModal(true)}
                style={{ whiteSpace:"nowrap", display: "flex", alignItems: "center", gap: 6 }}
              >
                {hasElev ? <><RefreshCw size={14} /> Re-run Elevated Scan</> : <><Lock size={14} /> Request Admin Elevation</>}
              </button>
          }
          {elevError && <div style={{ width:"100%", color:"var(--red)", fontSize:".72rem" }}>❌ {elevError}</div>}
        </div>

        <ScanCard title="BIOS / Firmware" icon={Wrench} defaultOpen>
          <KVRow label="BIOS Manufacturer" value={bios.manufacturer} />
          <KVRow label="BIOS Name"         value={bios.name} mono />
          <KVRow label="BIOS Version"      value={bios.version} mono />
          <KVRow label="Release Date"      value={bios.release_date} mono />
          <KVRow label="System Mfr."       value={bios.system_manufacturer} />
          <KVRow label="System Model"      value={bios.system_model} mono />
          <KVRow label="Firmware Type"     value={ftStr} color={ftStr === "UEFI" ? "var(--emerald)" : "var(--amber)"} />
        </ScanCard>

        <ScanCard title="Secure Boot" icon={Lock}
          badge={sb.status}
          badgeColor={sb.enabled ? "#16a34a" : sb.enabled === false ? "#dc2626" : "#6b7280"}
          defaultOpen>
          <KVRow label="Status" value={sb.status || (hasElev ? "Unknown" : "Requires elevation")} color={sb.enabled ? "var(--emerald)" : sb.enabled === false ? "var(--red)" : "var(--muted)"} />
          <KVRow label="Source" value={sb.source || (hasElev ? "elevated" : "registry (no-admin)")} mono />
        </ScanCard>

        <ScanCard title="TPM" icon={ShieldCheck}
          badge={tpm.spec_version && tpm.spec_version !== "Unknown" ? `TPM ${tpm.spec_version}` : tpm.present ? "Present" : hasElev ? "Not Found" : "Needs Elevation"}
          badgeColor={tpm.present ? "#16a34a" : hasElev ? "#6b7280" : "#ca8a04"}
          defaultOpen>
          {!hasElev && (
            <div style={{ fontSize:".72rem", color:"var(--amber)", marginBottom:6, display:"flex", alignItems:"center", gap:6 }}>
              <AlertTriangle size={14} color="var(--amber)" /> TPM details require admin rights — click "Request Admin Elevation" above
            </div>
          )}
          <KVRow label="Device Name"   value={tpm.name} />
          <KVRow label="Present"       value={tpm.present  ? "Yes" : (hasElev ? "No" : "—")}  color={tpm.present ? "var(--emerald)" : hasElev ? "var(--red)" : "var(--muted)"} />
          <KVRow label="Ready / OK"    value={tpm.ready    ? "Yes" : tpm.present ? "Needs init" : (hasElev ? "—" : "—")} color={tpm.ready ? "var(--emerald)" : tpm.present ? "var(--amber)" : "var(--muted)"} />
          <KVRow label="Spec Version"  value={tpm.spec_version} mono />
          {hasElev && <KVRow label="Manufacturer" value={tpm.manufacturer} />}
          {hasElev && <KVRow label="Owned"        value={tpm.owned ? "Yes" : "No"} />}
          <KVRow label="Device Status" value={tpm.status} color={tpm.status === "OK" ? "var(--emerald)" : "var(--muted)"} />
          <KVRow label="Detection"     value={tpm.source} mono />
          {tpm.note && <div style={{ fontSize:".65rem", color:"var(--muted)", marginTop:4, fontStyle:"italic" }}>{tpm.note}</div>}
        </ScanCard>

        <ScanCard title="Motherboard" icon={Server}>
          <KVRow label="Manufacturer" value={mb.manufacturer} />
          <KVRow label="Product"      value={mb.product} mono />
          <KVRow label="Version"      value={mb.version} mono />
        </ScanCard>
      </div>
    );
  }

  function renderHardware(hw, os) {
    const cpu = hw?.cpu || {}; const mem = hw?.memory || {};
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ScanCard title="CPU" icon={Cpu} defaultOpen>
          <KVRow label="Name"        value={cpu.name} />
          <KVRow label="Cores / Logical" value={`${cpu.cores} / ${cpu.logical}`} mono />
          <KVRow label="Max Freq"    value={cpu.max_mhz ? `${cpu.max_mhz} MHz` : "—"} mono />
          <KVRow label="Current Use" value={`${cpu.current_usage}%`} color={cpu.current_usage > 85 ? "var(--red)" : "var(--emerald)"} />
        </ScanCard>
        <ScanCard title="Memory" icon={HardDrive} defaultOpen>
          <KVRow label="Total"    value={`${mem.total_gb} GB`} mono />
          <KVRow label="Used"     value={`${mem.used_gb} GB (${mem.percent}%)`} color={mem.percent > 85 ? "var(--red)" : "var(--text)"} />
          <KVRow label="Swap"     value={`${mem.swap_used_gb} / ${mem.swap_total_gb} GB`} mono />
          {(mem.sticks || []).map((s, i) => (
            <KVRow key={i} label={`Stick ${i+1}`} value={`${s.capacity_gb}GB  ${s.speed_mhz}MHz  ${s.manufacturer}`} mono />
          ))}
        </ScanCard>
        <ScanCard title="Disks" icon={HardDrive}>
          {(hw?.disks || []).map((d, i) => (
            <KVRow key={i} label={d.device} value={`${d.used_gb}/${d.total_gb}GB (${d.percent}%) ${d.fstype}`} color={d.percent > 90 ? "var(--red)" : "var(--text)"} mono />
          ))}
        </ScanCard>
        <ScanCard title="GPU" icon={Monitor}>
          {(hw?.gpu || []).map((g, i) => (
            <KVRow key={i} label={g.name} value={g.vram_mb ? `${g.vram_mb} MB VRAM • Driver ${g.driver_version}` : `Driver ${g.driver_version}`} mono />
          ))}
        </ScanCard>
        <ScanCard title="OS" icon={Server} defaultOpen>
          <KVRow label="Caption"       value={os?.caption} />
          <KVRow label="Version"       value={os?.version} mono />
          <KVRow label="Build"         value={os?.build} mono />
          <KVRow label="Architecture"  value={os?.architecture} />
          <KVRow label="Hostname"      value={os?.hostname} mono />
          <KVRow label="Python Ver."   value={os?.python_version} mono />
          <KVRow label="Uptime"        value={os?.uptime_seconds ? `${Math.floor(os.uptime_seconds/3600)}h ${Math.floor((os.uptime_seconds%3600)/60)}m` : "—"} />
        </ScanCard>
      </div>
    );
  }

  function renderSecurity(sec) {
    const wd = sec?.windows_defender || {};
    const fw = sec?.firewall || {};
    const upd = sec?.windows_updates || {};
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ScanCard title="Windows Defender" icon={Shield} defaultOpen>
          <KVRow label="Service Enabled"     value={wd.service_enabled     ? "Yes" : "No"} color={wd.service_enabled ? "var(--emerald)" : "var(--red)"} />
          <KVRow label="Real-time Protection" value={wd.realtime_protection ? "Active" : "Off"} color={wd.realtime_protection ? "var(--emerald)" : "var(--red)"} />
          <KVRow label="Signature Version"   value={wd.signature_version} mono />
          <KVRow label="Sig. Last Updated"   value={wd.signature_last_updated} mono />
        </ScanCard>
        <ScanCard title="Firewall" icon={Flame} defaultOpen>
          {Object.entries(fw).map(([profile, enabled]) => (
            <KVRow key={profile} label={profile.charAt(0).toUpperCase() + profile.slice(1)} value={enabled ? "Enabled" : "Disabled"} color={enabled ? "var(--emerald)" : "var(--red)"} />
          ))}
        </ScanCard>
        <ScanCard title="Windows Updates" icon={RefreshCw} defaultOpen>
          <KVRow label="Pending Updates" value={upd.status} color={upd.pending_count === 0 ? "var(--emerald)" : "var(--amber)"} />
        </ScanCard>
      </div>
    );
  }

  function renderPersistence(persist) {
    const startup = persist?.startup_items || [];
    const tasks   = persist?.scheduled_tasks || [];
    const suspStartup = startup.filter(s => s.suspicious);
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ScanCard title="Startup Items (Registry Run Keys)" icon={Zap} badge={startup.length} defaultOpen>
          {startup.length === 0 && <div style={{ color: "var(--muted)", fontSize: ".78rem" }}>No startup entries found</div>}
          {startup.map((s, i) => (
            <div key={i} style={{ padding: "6px 10px", borderRadius: 6, background: s.suspicious ? "rgba(255,60,60,.08)" : "rgba(255,255,255,.03)", border: `1px solid ${s.suspicious ? "rgba(255,60,60,.2)" : "rgba(255,255,255,.06)"}`, fontSize: ".72rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{s.name}</span>
                {s.suspicious && <span style={{ color: "var(--red)", fontWeight: 700, display: "flex", alignItems: "center", gap: 4 }}><AlertTriangle size={13} /> Suspicious</span>}
              </div>
              <div style={{ color: "var(--muted)", marginTop: 2, wordBreak: "break-all" }}>{s.source} → {s.command}</div>
            </div>
          ))}
          {suspStartup.length > 0 && <div style={{ color: "var(--red)", fontSize: ".75rem", fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}><AlertTriangle size={14} /> {suspStartup.length} suspicious startup entries detected — review immediately</div>}
        </ScanCard>
        <ScanCard title="Scheduled Tasks (Active)" icon={Clock} badge={tasks.length}>
          <div style={{ maxHeight: 200, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
            {tasks.map((t, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: ".72rem", padding: "4px 0", borderBottom: "1px solid rgba(255,255,255,.04)" }}>
                <span style={{ fontFamily: "var(--mono)", color: "var(--text)" }}>{t.name}</span>
                <span style={{ color: "var(--muted)" }}>{t.path}</span>
              </div>
            ))}
          </div>
        </ScanCard>
      </div>
    );
  }

  function renderNetwork(net) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ScanCard title="Network Adapters" icon={Globe} defaultOpen>
          {(net?.adapters || []).filter(a => a.ipv4).map((a, i) => (
            <KVRow key={i} label={a.name} value={`${a.ipv4}  •  ${a.is_up ? "UP" : "DOWN"}  •  ${a.speed_mb}Mbps`} mono color={a.is_up ? "var(--emerald)" : "var(--muted)"} />
          ))}
        </ScanCard>
        <ScanCard title="Listening Ports" icon={Usb} badge={net?.listening_ports?.length} defaultOpen>
          <div style={{ maxHeight: 220, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: ".72rem" }}>
              <thead><tr>{["Port", "Address", "PID", "Process"].map(h => <th key={h} style={{ padding: "4px 8px", textAlign: "left", color: "var(--muted)", borderBottom: "1px solid rgba(255,255,255,.06)" }}>{h}</th>)}</tr></thead>
              <tbody>
                {(net?.listening_ports || []).map((p, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,.03)" }}>
                    <td style={{ padding: "4px 8px", fontFamily: "var(--mono)", color: "var(--cyan)" }}>{p.port}</td>
                    <td style={{ padding: "4px 8px", fontFamily: "var(--mono)" }}>{p.addr}</td>
                    <td style={{ padding: "4px 8px", fontFamily: "var(--mono)" }}>{p.pid}</td>
                    <td style={{ padding: "4px 8px" }}>{p.process}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ScanCard>
        <ScanCard title="Installed Software" icon={FileText}>
          <KVRow label="Total installed programs" value={net?.installed_software_count} mono />
        </ScanCard>
      </div>
    );
  }

  function renderProcesses(procs) {
    const susp = procs?.suspicious || [];
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ScanCard title="Process IOC Scan" icon={Microscope} defaultOpen badge={susp.length > 0 ? `${susp.length} THREAT` : "CLEAN"} badgeColor={susp.length > 0 ? "#dc2626" : "#16a34a"}>
          <KVRow label="Total processes scanned" value={procs?.total_processes} mono />
          <KVRow label="IOC matches"              value={susp.length} color={susp.length > 0 ? "var(--red)" : "var(--emerald)"} />
          {susp.map((p, i) => (
            <div key={i} style={{ padding: "8px 12px", borderRadius: 8, background: "rgba(255,60,60,.08)", border: "1px solid rgba(255,60,60,.2)", fontSize: ".72rem", display: "flex", flexDirection: "column", gap: 4 }}>
              <div style={{ display: "flex", gap: 8 }}>
                <span style={{ color: "var(--red)", fontWeight: 700, display: "flex", alignItems: "center", gap: 4 }}><AlertTriangle size={13} /> {p.name}</span>
                <span style={{ color: "var(--muted)" }}>PID {p.pid}</span>
                <span style={{ color: "var(--muted)", marginLeft: "auto" }}>Match: {p.ioc_match}</span>
              </div>
              <div style={{ color: "var(--muted)", wordBreak: "break-all" }}>{p.exe}</div>
              {p.cmdline && <div style={{ color: "var(--amber)", fontFamily: "var(--mono)", fontSize: ".65rem", wordBreak: "break-all" }}>{p.cmdline.slice(0, 160)}</div>}
            </div>
          ))}
          {susp.length === 0 && <div style={{ color: "var(--emerald)", fontSize: ".78rem", display: "flex", alignItems: "center", gap: 6 }}><CheckCircle2 size={15} /> No suspicious processes found by IOC signature scan</div>}
        </ScanCard>
      </div>
    );
  }

  function renderDevices(devices) {
    return (
      <ScanCard title="USB / PnP Devices" icon={Usb} badge={devices?.length} defaultOpen>
        {(devices || []).length === 0 && <div style={{ color: "var(--muted)", fontSize: ".78rem" }}>No USB devices detected</div>}
        {(devices || []).map((d, i) => (
          <KVRow key={i} label={d.name} value={d.manufacturer} />
        ))}
      </ScanCard>
    );
  }

  function renderMachineInfo(scanResult) {
    const os  = scanResult?.os || {};
    const hw  = scanResult?.hardware || {};
    const cpu = hw.cpu || {};
    const mem = hw.memory || {};
    const fw  = scanResult?.firmware || {};
    const bios = fw.bios || {};
    const mb   = fw.motherboard || {};
    const uptime = os.uptime_seconds || 0;
    const uptimeStr = `${Math.floor(uptime/86400)}d ${Math.floor((uptime%86400)/3600)}h ${Math.floor((uptime%3600)/60)}m`;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <ScanCard title="System Identity" icon={Server} defaultOpen>
          <KVRow label="Hostname"       value={os.hostname} mono />
          <KVRow label="Manufacturer"   value={bios.system_manufacturer} />
          <KVRow label="Model"          value={bios.system_model} />
          <KVRow label="Platform"       value={os.platform} />
          <KVRow label="Architecture"   value={os.architecture} />
        </ScanCard>
        <ScanCard title="Operating System" icon={Server} defaultOpen>
          <KVRow label="OS Name"        value={os.caption} />
          <KVRow label="Version"        value={os.version} mono />
          <KVRow label="Build Number"   value={os.build} mono />
          <KVRow label="Uptime"         value={uptimeStr} />
          <KVRow label="Python Version" value={os.python_version} mono />
        </ScanCard>
        <ScanCard title="Processor" icon={Cpu} defaultOpen>
          <KVRow label="CPU Name"       value={cpu.name} />
          <KVRow label="Manufacturer"   value={cpu.manufacturer} />
          <KVRow label="Physical Cores" value={cpu.cores} mono />
          <KVRow label="Logical Cores"  value={cpu.logical} mono />
          <KVRow label="Base Freq."     value={cpu.max_mhz ? `${(cpu.max_mhz/1000).toFixed(2)} GHz` : "—"} mono />
          <KVRow label="Current Usage"  value={`${cpu.current_usage}%`} color={cpu.current_usage > 85 ? "var(--red)" : "var(--emerald)"} />
          {(cpu.per_core || []).length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: ".68rem", color: "var(--muted)", marginBottom: 4 }}>Per-Core Usage</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {(cpu.per_core || []).map((pct, i) => (
                  <div key={i} style={{ background: pct > 80 ? "rgba(239,68,68,.2)" : "rgba(255,255,255,.05)", border: `1px solid ${pct > 80 ? "rgba(239,68,68,.3)" : "rgba(255,255,255,.08)"}`, borderRadius: 6, padding: "4px 8px", fontSize: ".65rem", fontFamily: "var(--mono)", color: pct > 80 ? "var(--red)" : "var(--text)" }}>
                    C{i} {pct}%
                  </div>
                ))}
              </div>
            </div>
          )}
        </ScanCard>
        <ScanCard title="Memory" icon={HardDrive} defaultOpen>
          <KVRow label="Total"          value={`${mem.total_gb} GB`} mono />
          <KVRow label="Used"           value={`${mem.used_gb} GB (${mem.percent}%)`} color={mem.percent > 85 ? "var(--red)" : "var(--text)"} />
          <KVRow label="Available"      value={`${mem.available_gb} GB`} mono />
          {(mem.sticks || []).map((s, i) => (
            <KVRow key={i} label={`Stick ${i+1}`} value={`${s.capacity_gb} GB  ${s.speed_mhz} MHz  ${s.manufacturer}`} mono />
          ))}
        </ScanCard>
        <ScanCard title="Motherboard" icon={Server}>
          <KVRow label="Manufacturer"   value={mb.manufacturer} />
          <KVRow label="Product"        value={mb.product} mono />
          <KVRow label="Version"        value={mb.version} mono />
          <KVRow label="BIOS Version"   value={bios.version} mono />
          <KVRow label="BIOS Date"      value={bios.release_date} mono />
          <KVRow label="Firmware Type"  value={fw.firmware_type} color={fw.firmware_type === "UEFI" ? "var(--emerald)" : "var(--amber)"} />
        </ScanCard>
        <ScanCard title="GPU" icon={Monitor}>
          {(hw.gpu || []).map((g, i) => (
            <KVRow key={i} label={g.name} value={g.vram_mb ? `${g.vram_mb} MB VRAM  •  Driver ${g.driver_version}` : `Driver ${g.driver_version}`} mono />
          ))}
          {!(hw.gpu || []).length && <div style={{ color: "var(--muted)", fontSize: ".78rem" }}>No GPU detected via wmic</div>}
        </ScanCard>
      </div>
    );
  }

  const TABS = [
    { id: "posture",     label: "Posture Score", icon: ShieldCheck },
    { id: "machine",     label: "Machine Info",  icon: Server },
    { id: "firmware",    label: "Firmware/BIOS", icon: Wrench },
    { id: "hardware",    label: "Hardware",      icon: Cpu },
    { id: "security",    label: "Security",      icon: Shield },
    { id: "persistence", label: "Persistence",   icon: Zap },
    { id: "network",     label: "Network",       icon: Globe },
    { id: "processes",   label: "Processes",     icon: Microscope },
    { id: "devices",     label: "Devices",       icon: Usb },
  ];

  return (
    <div className="panel">
      {/* Header */}
      <div className="flex-row" style={{ flexShrink: 0, flexWrap: "wrap", gap: 10 }}>
        <div>
          <p className="eyebrow">Real Hardware · Firmware · IOC Scan</p>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 700 }}>Deep System Security Scanner</h2>
        </div>
        {result && (
          <div style={{ display: "flex", gap: 6, alignItems: "center", marginLeft: 8 }}>
            <span style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: result.posture.score >= 70 ? "var(--emerald)" : "var(--red)" }}>
              Score: {result.posture.score}/100 (Grade {result.posture.grade})
            </span>
          </div>
        )}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          {scanning && <div className="live-ring"><div className="live-ring-dot live" /><span style={{ fontFamily: "var(--mono)", fontSize: ".72rem" }}>Scanning {pct}%…</span></div>}
          {result  && <button className="btn ghost sm" onClick={() => setResult(null)}>✕ Clear</button>}
          <button id="btn-deep-scan" className="btn primary" onClick={startScan} disabled={scanning}>
            {scanning ? `${pct}%…` : "▶ Start Deep Scan"}
          </button>
        </div>
      </div>

      {/* Idle state — Cyber Scanner Hero */}
      {!scanning && !result && !error && (
        <div className="cyber-scanner-hero">
          {/* Tech HUD Corners */}
          <div className="hud-corner tl" />
          <div className="hud-corner tr" />
          <div className="hud-corner bl" />
          <div className="hud-corner br" />

          {/* Animated Cyber Radar Scanner Core */}
          <div className="cyber-radar-ring">
            <div className="cyber-radar-spin" />
            <div className="cyber-radar-pulse" />
            <Scan size={42} color="var(--cyan)" style={{ filter: "drop-shadow(0 0 12px var(--cyan))" }} />
          </div>

          {/* Headline & Description */}
          <div style={{ textAlign: "center", maxWidth: 640, zIndex: 1 }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "3px 10px", borderRadius: 20, background: "rgba(6,182,212,0.12)", border: "1px solid rgba(6,182,212,0.3)", color: "var(--cyan)", fontFamily: "var(--mono)", fontSize: ".68rem", fontWeight: 700, marginBottom: 10 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />
              CYBER RECONNAISSANCE ENGINE ACTIVE
            </div>
            <h3 style={{ fontSize: "1.45rem", fontWeight: 800, color: "#fff", letterSpacing: "-.01em", margin: 0 }}>
              Real-Time Deep System Security Scanner
            </h3>
            <p style={{ color: "var(--muted)", fontSize: ".84rem", lineHeight: 1.6, marginTop: 8 }}>
              Direct kernel &amp; WMI telemetry collector for BIOS/UEFI firmware, Secure Boot, TPM 2.0 chip, CPU/GPU/RAM specs, Windows Defender status, active run-keys, and YARA process IOC signatures.
            </p>
          </div>

          {/* Feature Modules Grid */}
          <div className="cyber-grid-4" style={{ zIndex: 1, margin: "6px 0 10px" }}>
            <div className="cyber-module-card">
              <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--cyan)", fontSize: ".82rem", fontWeight: 700 }}>
                <Lock size={15} /> Firmware &amp; TPM
              </div>
              <p style={{ fontSize: ".7rem", color: "var(--muted)", margin: 0 }}>Confirm Secure Boot, TPM version &amp; UAC elevated checks</p>
            </div>

            <div className="cyber-module-card">
              <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--primary)", fontSize: ".82rem", fontWeight: 700 }}>
                <Cpu size={15} /> Hardware &amp; OS
              </div>
              <p style={{ fontSize: ".7rem", color: "var(--muted)", margin: 0 }}>CPU usage, RAM sticks, motherboard, disks &amp; GPU specs</p>
            </div>

            <div className="cyber-module-card">
              <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--amber)", fontSize: ".82rem", fontWeight: 700 }}>
                <Zap size={15} /> Persistence
              </div>
              <p style={{ fontSize: ".7rem", color: "var(--muted)", margin: 0 }}>Registry startup run-keys &amp; active Windows scheduled tasks</p>
            </div>

            <div className="cyber-module-card">
              <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--emerald)", fontSize: ".82rem", fontWeight: 700 }}>
                <Microscope size={15} /> Process &amp; IOC
              </div>
              <p style={{ fontSize: ".7rem", color: "var(--muted)", margin: 0 }}>Scan running processes against YARA malware signatures</p>
            </div>
          </div>

          {/* Action Callout Button */}
          <button className="cyber-btn-primary" onClick={startScan} style={{ zIndex: 1 }}>
            <Play size={18} fill="#fff" />
            <span>Initiate Full Cyber Scan</span>
          </button>
        </div>
      )}

      {/* Scan log */}
      {(scanning || (scanLog.length > 0 && !result)) && (
        <div className="card" style={{ flexShrink: 0, maxHeight: 180 }}>
          <div className="card-hd"><div><p className="eyebrow">Live Scan Progress</p><h3>Scan Log</h3></div><div className="live-ring"><div className="live-ring-dot live" />LIVE</div></div>
          <div style={{ padding: "8px 16px 14px", fontFamily: "var(--mono)", fontSize: ".68rem", color: "var(--muted)", overflowY: "auto", maxHeight: 120, display: "flex", flexDirection: "column", gap: 2 }}>
            {scanLog.map((l, i) => <div key={i} style={{ color: l.includes("✅") ? "var(--emerald)" : l.includes("❌") ? "var(--red)" : "var(--muted)" }}>{l}</div>)}
          </div>
          {scanning && (
            <div style={{ padding: "0 16px 12px" }}>
              <div style={{ height: 4, background: "var(--surface)", borderRadius: 2 }}>
                <div style={{ height: "100%", width: `${pct}%`, background: "var(--primary)", borderRadius: 2, transition: "width .4s" }} />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="card" style={{ borderColor: "var(--red)", flexShrink: 0 }}>
          <div style={{ padding: "12px 16px", color: "var(--red)", fontSize: ".82rem" }}>❌ {error}</div>
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Tab nav */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", flexShrink: 0 }}>
            {TABS.map(t => {
              const Icon = t.icon;
              return (
                <button key={t.id} className={`btn ${activeTab === t.id ? "primary" : "ghost"} sm`} onClick={() => setActiveTab(t.id)} style={{ fontSize: ".7rem", display: "flex", alignItems: "center", gap: 5 }}>
                  <Icon size={13} /> {t.label}
                </button>
              );
            })}
          </div>

          {/* Tab content */}
          <div className="fill" style={{ overflowY: "auto", minHeight: 0, display: "flex", flexDirection: "column", gap: 10 }}>
            {activeTab === "posture"     && renderPosture(result.posture, result)}
            {activeTab === "machine"     && renderMachineInfo(result)}
            {activeTab === "firmware"    && renderFirmware(result.firmware, elevData)}
            {activeTab === "hardware"    && renderHardware(result.hardware, result.os)}
            {activeTab === "security"    && renderSecurity(result.security)}
            {activeTab === "persistence" && renderPersistence(result.persistence)}
            {activeTab === "network"     && renderNetwork(result.network)}
            {activeTab === "processes"   && renderProcesses(result.processes)}
            {activeTab === "devices"     && renderDevices(result.devices)}
          </div>
        </>
      )}

      {/* ── Finding Detail Modal ──────────────────────────────────────────── */}
      {findingDetail && (() => {
        const { finding: f, items } = findingDetail;
        const sevColor = f.severity === "critical" ? "var(--red)" : f.severity === "high" ? "var(--amber)" : "var(--cyan)";
        const borderCol = f.severity === "critical" ? "rgba(220,38,38,.35)" : f.severity === "high" ? "rgba(249,115,22,.35)" : "rgba(99,179,237,.25)";
        return (
          <div
            style={{ position:"fixed", inset:0, background:"rgba(0,0,0,.82)", zIndex:10000,
              display:"flex", alignItems:"center", justifyContent:"center", backdropFilter:"blur(6px)" }}
            onClick={() => setFindingDetail(null)}
          >
            <div
              style={{ background:"#0f172a", border:`1px solid ${borderCol}`,
                borderRadius:16, width:"min(680px, calc(100vw - 40px))",
                maxHeight:"80vh", display:"flex", flexDirection:"column",
                boxShadow:"0 30px 80px rgba(0,0,0,.7)" }}
              onClick={e => e.stopPropagation()}
            >
              {/* Modal header */}
              <div style={{ padding:"20px 24px", borderBottom:"1px solid rgba(255,255,255,.08)",
                display:"flex", alignItems:"flex-start", gap:14, flexShrink:0 }}>
                <div style={{ display: "flex", alignItems: "center" }}>
                  {f.severity === "critical" ? <AlertCircle size={22} color="var(--red)" /> : f.severity === "high" ? <AlertTriangle size={22} color="var(--amber)" /> : <Info size={22} color="var(--primary)" />}
                </div>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10, flexWrap:"wrap", marginBottom:4 }}>
                    <SevBadge sev={f.severity} />
                    <span style={{ fontWeight:800, fontSize:".95rem", color:"var(--text)" }}>{f.issue}</span>
                    <span style={{ marginLeft:"auto", fontFamily:"var(--mono)", fontSize:".68rem",
                      color:sevColor, border:`1px solid ${borderCol}`, borderRadius:4, padding:"2px 7px" }}>
                      -{f.deduction} pts
                    </span>
                  </div>
                  <div style={{ fontSize:".73rem", color:"var(--cyan)", marginTop:2, display: "flex", alignItems: "center", gap: 4 }}>
                    <Zap size={13} color="var(--cyan)" /> Fix: {f.fix}
                  </div>
                </div>
                <button onClick={() => setFindingDetail(null)}
                  style={{ background:"none", border:"none", color:"var(--muted)",
                    fontSize:"1.2rem", cursor:"pointer", lineHeight:1, padding:"0 4px", flexShrink:0 }}>
                  ✕
                </button>
              </div>

              {/* Item count subheader */}
              <div style={{ padding:"8px 24px", background:"rgba(255,255,255,.02)",
                fontSize:".72rem", color:"var(--muted)", borderBottom:"1px solid rgba(255,255,255,.05)",
                flexShrink:0, display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ color:sevColor, fontWeight:700 }}>{items.length}</span>
                {f.severity === "critical" || f.severity === "high" ? " suspicious" : ""} item{items.length !== 1 ? "s" : ""} detected
                {items.some(x => x.suspicious || x.is_suspicious) && (
                  <span style={{ marginLeft:"auto", color:"var(--red)", fontSize:".65rem" }}>
                    ⚠ Red = flagged as suspicious
                  </span>
                )}
              </div>

              {/* Scrollable item list */}
              <div style={{ overflowY:"auto", padding:"14px 24px 20px", flex:1 }}>
                {items.length === 0 ? (
                  <div style={{ color:"var(--muted)", fontSize:".8rem", textAlign:"center", padding:24 }}>
                    No detailed items available for this finding.
                  </div>
                ) : (
                  items.map((item, idx) => renderDetailItem(item, idx))
                )}
              </div>

              {/* Footer */}
              <div style={{ padding:"12px 24px", borderTop:"1px solid rgba(255,255,255,.06)",
                display:"flex", justifyContent:"space-between", alignItems:"center", flexShrink:0 }}>
                <span style={{ fontSize:".68rem", color:"var(--muted)" }}>
                  Click outside or ✕ to close
                </span>
                <button className="btn ghost sm" onClick={() => setFindingDetail(null)}>Close</button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* ── UAC Elevation Modal ─────────────────────────────────────────── */}
      {showElevModal && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,.75)", zIndex:9999,
          display:"flex", alignItems:"center", justifyContent:"center", backdropFilter:"blur(4px)" }}>
          <div style={{ background:"#111827", border:"1px solid rgba(255,255,255,.12)", borderRadius:16,
            padding:"28px 32px", maxWidth:520, width:"calc(100% - 40px)", boxShadow:"0 25px 60px rgba(0,0,0,.6)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:18 }}>
              <div style={{ fontSize:"2rem" }}>🔐</div>
              <div>
                <div style={{ fontWeight:800, fontSize:"1rem" }}>Request Windows Administrator Access</div>
                <div style={{ fontSize:".72rem", color:"var(--muted)", marginTop:2 }}>UAC elevation required for TPM &amp; Secure Boot queries</div>
              </div>
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10, marginBottom:20 }}>
              {[
                ["1", "Click \"Confirm Elevation\" below — this page will wait up to 2 minutes"],
                ["2", "A Windows UAC dialog will appear on your desktop asking for admin access"],
                ["3", "Click \"Yes\" in the UAC prompt to allow administrator access"],
                ["4", "A PowerShell window will briefly open, run the firmware scan, then close"],
                ["5", "Results will auto-load here — no page refresh needed"],
              ].map(([n, txt]) => (
                <div key={n} style={{ display:"flex", gap:12, alignItems:"flex-start" }}>
                  <div style={{ width:22, height:22, borderRadius:"50%", background:"var(--primary)",
                    display:"flex", alignItems:"center", justifyContent:"center",
                    fontSize:".7rem", fontWeight:800, flexShrink:0, marginTop:1 }}>{n}</div>
                  <div style={{ fontSize:".78rem", color:"var(--text)", lineHeight:1.5 }}>{txt}</div>
                </div>
              ))}
            </div>
            <div style={{ fontSize:".68rem", color:"var(--muted)", background:"rgba(255,255,255,.04)",
              borderRadius:8, padding:"8px 12px", marginBottom:18, border:"1px solid rgba(255,255,255,.06)" }}>
              <Shield size={13} style={{ display: "inline", verticalAlign: "middle", marginRight: 4 }} /> <strong>What the elevated script accesses:</strong> Get-Tpm (TPM chip state &amp; spec version),
              Confirm-SecureBootUEFI (Secure Boot enforcement), Win32_Tpm CIM class (manufacturer ID),
              Get-MpComputerStatus (Windows Defender full status). Results are written to %TEMP% and
              deleted immediately after reading. <strong>Nothing is sent externally.</strong>
            </div>
            <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
              <button className="btn ghost sm" onClick={() => setShowElevModal(false)}>Cancel</button>
              <button id="btn-confirm-elevation" className="btn primary" onClick={startElevatedScan}
                style={{ display:"flex", alignItems:"center", gap:8 }}>
                <Lock size={14} /> Confirm Elevation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════
   YARA PAGE
══════════════════════════════════════ */
function PageYARA() {
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  const run = async () => {
    if (!target.trim()) return;
    setScanning(true); setErr(""); setResult(null);
    try {
      const res = await api("/api/scan/yara", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target: target.trim() }) });
      setResult(res);
    } catch(e) { setErr(e.message); }
    finally { setScanning(false); }
  };

  return (
    <div className="panel">
      <div style={{ flexShrink: 0 }}>
        <p className="eyebrow">Malware Inspection</p>
        <h2 style={{ fontSize: "1.1rem", fontWeight: 700, marginBottom: 4 }}>YARA Signature Scanner</h2>
        <p style={{ color: "var(--muted)", fontSize: ".8rem" }}>Scan files or strings against Mimikatz, Ransomware, Cobalt Strike, and Webshell signatures.</p>
      </div>

      <div className="card" style={{ flexShrink: 0 }}>
        <p className="eyebrow" style={{ marginBottom: 8 }}>Scan Target</p>
        <div className="flex-row">
          <input id="yara-target" className="search-input" style={{ flex: 1 }} placeholder="File path (e.g. C:\\Temp\\file.exe) or suspicious string…" value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} />
          <button id="btn-yara-scan" className="btn primary" onClick={run} disabled={scanning || !target.trim()}>
            {scanning ? "Scanning…" : "Run YARA Scan"}
          </button>
        </div>
        {err && <div className="info-banner err" style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 6 }}><AlertTriangle size={14} /> {err}</div>}
      </div>

      {result && (
        <div className={`yara-result ${result.is_malicious ? "threat" : "clean"}`}>
          <div className="flex-row" style={{ marginBottom: 12 }}>
            <h3 style={{ fontSize: ".95rem", flex: 1, color: result.is_malicious ? "var(--red)" : "var(--emerald)", display: "flex", alignItems: "center", gap: 8 }}>
              {result.is_malicious ? <><AlertTriangle size={18} /> MALICIOUS PATTERN DETECTED</> : <><CheckCircle2 size={18} /> CLEAN — No Matches Found</>}
            </h3>
            <span className="pill neutral">{result.match_count || 0} matches</span>
          </div>
          {result.matches?.length > 0 && result.matches.map((m, i) => (
            <div key={i} className="alert-card" style={{ marginBottom: 8 }}>
              <div className="alert-hd">
                <span className={`sev-dot ${sevClass(m.severity)}`} />
                <strong style={{ flex: 1 }}>{m.rule_name}</strong>
                <span className={`pill ${sevClass(m.severity)}`}>{m.severity}</span>
              </div>
              <p style={{ fontSize: ".75rem", color: "var(--muted)", marginTop: 4 }}>{m.description}</p>
              {m.tags?.length > 0 && <div className="ev-chips" style={{ marginTop: 6 }}>{m.tags.map((t, j) => <div key={j} className="ev-chip"><strong>{t}</strong></div>)}</div>}
            </div>
          ))}
        </div>
      )}

      {!result && !scanning && (
        <div className="fill" style={{ minHeight: 0 }}>
          <EmptyState text="Enter a target path or string above to begin YARA scanning" />
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════
   AGENTS PAGE
══════════════════════════════════════ */
function PageAgents() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [regHost, setRegHost] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try { setAgents(await api("/api/agents")); }
    catch(_) {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const register = async () => {
    if (!regHost.trim()) return;
    try {
      await api("/api/agents/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hostname: regHost.trim(), os: "Linux", ip_address: "0.0.0.0" }) });
      setRegHost(""); load();
    } catch(e) { alert(e.message); }
  };

  return (
    <div className="panel">
      <div className="flex-row" style={{ flexShrink: 0 }}>
        <div>
          <p className="eyebrow">Enterprise Fleet</p>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 700 }}>Multi-Host Endpoint Agents</h2>
        </div>
        <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={load} disabled={loading}>{loading ? "Refreshing…" : "⟳ Refresh"}</button>
      </div>

      <div className="card" style={{ flexShrink: 0 }}>
        <p className="eyebrow" style={{ marginBottom: 8 }}>Register New Agent</p>
        <div className="flex-row">
          <input id="agent-hostname" className="search-input" style={{ flex: 1 }} placeholder="Remote hostname (e.g. prod-db-02)…" value={regHost} onChange={e => setRegHost(e.target.value)} onKeyDown={e => e.key === "Enter" && register()} />
          <button id="btn-register-agent" className="btn primary" onClick={register} disabled={!regHost.trim()}>Register Agent</button>
        </div>
      </div>

      <div className="scroll-zone fill" style={{ minHeight: 0 }}>
        {agents.length ? agents.map(a => (
          <div key={a.id} className="agent-card" style={{ marginBottom: 8 }}>
            <div className="agent-icon">{a.os?.toLowerCase().includes("win") ? "🪟" : "🐧"}</div>
            <div className="agent-info">
              <div className="agent-name">{a.hostname}</div>
              <div className="agent-meta">{a.os} · {a.ip_address} · Events: {a.events_ingested}</div>
              <div className="agent-meta">Last seen: {fTime(a.last_heartbeat)}</div>
            </div>
            <div className="flex-col" style={{ alignItems: "flex-end", gap: 4 }}>
              <span className={`pill ${a.status === "online" ? "low" : "neutral"}`}>{a.status}</span>
              <span className="pill neutral" style={{ fontSize: ".62rem" }}>{a.id?.slice(0, 8)}…</span>
            </div>
          </div>
        )) : <EmptyState text="No agents registered" />}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   BASELINE PAGE
══════════════════════════════════════ */
const FEAT_META = {
  failed_login_count:     { name: "Failed Logins",      desc: "Auth failure velocity — detects brute-force." },
  file_modifications:     { name: "File Modifications",  desc: "FIM mod count — detects ransomware / tampering." },
  outbound_connections:   { name: "Outbound Connections",desc: "Socket count — detects C2 or reverse shells." },
  data_transfer_mb:       { name: "Data Transfer (MB)",  desc: "Egress volume — detects exfiltration." },
  new_services_installed: { name: "New Services",        desc: "Service installs — detects persistence." },
  cpu_percent:            { name: "CPU Utilization",     desc: "CPU baseline — detects cryptomining." },
  memory_percent:         { name: "Memory Utilization",  desc: "RAM baseline — detects injection." },
  process_spawn_velocity: { name: "Process Spawn Rate",  desc: "Spawn freq — detects fork bombs." },
};

function PageBaseline({ baseline = {} }) {
  const entries = Object.entries(baseline);
  return (
    <div className="panel">
      <div style={{ flexShrink: 0 }}>
        <p className="eyebrow">Adaptive ML Profile</p>
        <h2 style={{ fontSize: "1.1rem", fontWeight: 700, marginBottom: 2 }}>Behavioral Baseline — IsolationForest</h2>
        <p style={{ color: "var(--muted)", fontSize: ".78rem" }}>3σ Gaussian boundaries computed from real OS telemetry. Deviations trigger anomaly scoring.</p>
      </div>

      {entries.length === 0
        ? <EmptyState text="Baseline not yet calibrated — start the monitor to build a profile" />
        : (
          <div className="scroll-zone fill" style={{ minHeight: 0 }}>
            <div className="bl-grid">
              {entries.map(([n, s]) => {
                const meta = FEAT_META[n] || { name: n.replaceAll("_"," "), desc: "Monitored metric." };
                const m  = typeof s?.mean === "number" ? s.mean : 0;
                const sd = typeof s?.std  === "number" ? s.std  : 0;
                const lo = Math.max(0, m - 3 * sd);
                const hi = m + 3 * sd;
                const fill = hi > 0 ? Math.min(100, (m / hi) * 100) : 20;
                return (
                  <div key={n} className="bl-card">
                    <div className="bl-card-name">{meta.name}</div>
                    <div className="bl-card-desc">{meta.desc}</div>
                    <div className="bl-row"><span>Mean (μ)</span><strong>{m.toFixed(4)}</strong></div>
                    <div className="bl-row"><span>Std Dev (σ)</span><strong>{sd.toFixed(4)}</strong></div>
                    <div className="bl-row"><span>3σ Bounds</span><strong style={{ fontSize: ".68rem" }}>[{lo.toFixed(2)} → {hi.toFixed(2)}]</strong></div>
                    <div className="bl-vbar"><div className="bl-vfill" style={{ width: `${fill}%` }} /></div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
    </div>
  );
}

/* ══════════════════════════════════════
   REPORT PAGE
══════════════════════════════════════ */
function PageReport({ report, busy, onExport, onRefresh }) {
  const [activeTab, setActiveTab] = useState("overview"); // overview, deep_scan, owasp, soar
  const score = report?.executive_summary?.security_posture_score ?? null;
  const scoreColor = score === null ? "var(--muted)" : score >= 80 ? "var(--emerald)" : score >= 60 ? "var(--amber)" : "var(--red)";
  const grade = score === null ? "—" : score >= 80 ? "Grade A · Secure" : score >= 60 ? "Grade B · Warning" : "Grade C · Action Required";

  const deepScan = report?.deep_scan;
  const fw = deepScan?.firmware || {};
  const sec = deepScan?.security || {};
  const pers = deepScan?.persistence || {};
  const net = deepScan?.network || {};

  return (
    <div className="panel" style={{ gap: 14 }}>
      {/* Top Header & Export Toolbar */}
      <div className="flex-row" style={{ flexShrink: 0, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div className="flex-center gap-8" style={{ justifyContent: "flex-start" }}>
            <FileBarChart size={20} color="var(--cyan)" />
            <h2 style={{ fontSize: "1.15rem", fontWeight: 700 }}>{report?.title || "HIDS Security Audit & Deep Scan Report"}</h2>
          </div>
          {report?.generated_at && (
            <p style={{ fontSize: ".72rem", color: "var(--muted)", fontFamily: "var(--mono)", marginTop: 2 }}>
              Audit Snapshot: {fTime(report.generated_at)} · Target: <strong style={{ color: "var(--text)" }}>{report?.executive_summary?.host || "LocalHost"}</strong>
            </p>
          )}
        </div>

        <div className="posture-ring" style={{ marginLeft: "auto", padding: "6px 14px", marginBottom: 0, flex: "0 0 auto" }}>
          <div className="posture-score" style={{ color: scoreColor }}>{score ?? "—"}</div>
          <div>
            <div style={{ fontFamily: "var(--mono)", fontSize: ".65rem", color: "var(--muted)", textTransform: "uppercase" }}>Posture Score</div>
            <div style={{ fontFamily: "var(--mono)", fontSize: ".72rem", color: scoreColor, fontWeight: 600 }}>{grade}</div>
          </div>
        </div>

        <div className="action-row" style={{ flexShrink: 0 }}>
          <button
            id="btn-export-pdf"
            className="cyber-btn-primary"
            style={{ padding: "8px 18px", fontSize: ".82rem" }}
            onClick={() => onExport("pdf")}
            disabled={busy !== ""}
          >
            <FileText size={16} />
            {busy === "export-pdf" ? "Generating PDF…" : "Export PDF Formal Report"}
          </button>

          <button
            id="btn-export-docx"
            className="btn secondary sm"
            style={{ padding: "8px 14px" }}
            onClick={() => onExport("word")}
            disabled={busy !== ""}
          >
            <FileCode size={16} />
            Word DOCX
          </button>

          <button
            className="btn ghost sm"
            style={{ padding: "8px 12px" }}
            onClick={onRefresh}
            disabled={busy !== ""}
          >
            <RefreshCw size={15} />
            {busy === "report" ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>

      {/* Tab Selector */}
      <div className="chip-row" style={{ flexShrink: 0, borderBottom: "1px solid var(--border)", paddingBottom: 10 }}>
        <button className={`chip ${activeTab === "overview" ? "active" : ""}`} onClick={() => setActiveTab("overview")}>
          Executive Overview
        </button>
        <button className={`chip ${activeTab === "deep_scan" ? "active" : ""}`} onClick={() => setActiveTab("deep_scan")}>
          Deep Scan Inspection {deepScan ? "✓" : ""}
        </button>
        <button className={`chip ${activeTab === "owasp" ? "active" : ""}`} onClick={() => setActiveTab("owasp")}>
          OWASP Matrix ({report?.owasp_alignment?.length || 0})
        </button>
        <button className={`chip ${activeTab === "soar" ? "active" : ""}`} onClick={() => setActiveTab("soar")}>
          SOAR Playbook ({report?.recommended_actions?.length || 0})
        </button>
      </div>

      {/* Tab Content */}
      <div className="fill" style={{ minHeight: 0, overflowY: "auto" }}>

        {/* ── TAB 1: EXECUTIVE OVERVIEW ── */}
        {activeTab === "overview" && (
          <div className="report-layout">
            <div className="flex-col" style={{ gap: 12 }}>
              {/* Executive Summary Card */}
              <div className="card">
                <p className="eyebrow" style={{ marginBottom: 10 }}>Executive Audit Summary</p>
                <div className="stat-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))" }}>
                  {[
                    ["Target Host", report?.executive_summary?.host || "—"],
                    ["Monitor State", (report?.executive_summary?.monitor_state || "—").toUpperCase()],
                    ["Posture Score", `${report?.executive_summary?.security_posture_score ?? "—"} / 100`],
                    ["Deep Scan Status", deepScan ? "Completed" : "Not Run"],
                    ["Events Recorded", report?.executive_summary?.events_observed ?? "0"],
                    ["Alerts Triggered", report?.executive_summary?.alerts_generated ?? "0"],
                    ["Critical Alerts", report?.executive_summary?.critical_alerts ?? "0"],
                    ["High Alerts", report?.executive_summary?.high_alerts ?? "0"],
                  ].map(([l, v]) => (
                    <div key={l} className="stat-item">
                      <div className="lbl">{l}</div>
                      <div className="val" style={{ fontSize: ".84rem", wordBreak: "break-word" }}>{v}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* OWASP Summary Card */}
              <div className="card">
                <p className="eyebrow" style={{ marginBottom: 10 }}>OWASP Security Compliance</p>
                {report?.owasp_alignment?.length ? report.owasp_alignment.slice(0, 3).map((item, i) => (
                  <div key={i} className="owasp-item" style={{ marginBottom: 10 }}>
                    <div className="owasp-hd">
                      <span className="owasp-area">{item.area}</span>
                      <span className={`pill ${sevClass(item.status === "aligned" ? "low" : item.status === "attention" ? "high" : "medium")}`}>
                        {item.status}
                      </span>
                    </div>
                    <div className="owasp-detail"><strong>Finding:</strong> {item.finding}</div>
                  </div>
                )) : <EmptyState text="No OWASP records" />}
              </div>
            </div>

            <div className="flex-col" style={{ gap: 12 }}>
              {/* Priority Findings Card */}
              <div className="card" style={{ flex: 1 }}>
                <p className="eyebrow" style={{ marginBottom: 10 }}>Priority Threat Findings</p>
                {report?.top_findings?.length ? report.top_findings.map((f, i) => (
                  <div key={i} className={`alert-card ${sevClass(f.severity) === "critical" ? "crit" : ""}`} style={{ marginBottom: 10 }}>
                    <div className="alert-hd">
                      <span className={`sev-dot ${sevClass(f.severity)}`} />
                      <strong style={{ flex: 1, fontSize: ".82rem" }}>{f.summary}</strong>
                      <span className={`pill ${sevClass(f.severity)}`}>{f.severity}</span>
                    </div>
                    <div className="alert-meta">
                      <span>Host: {f.host || "—"}</span>
                      <span>·</span>
                      <span>Score: <strong style={{ color: "var(--cyan)", fontFamily: "var(--mono)" }}>{f.score}</strong></span>
                    </div>
                    {f.reasons?.length > 0 && (
                      <p style={{ fontSize: ".72rem", color: "var(--muted)", marginTop: 6, lineHeight: 1.5 }}>
                        {f.reasons.join(" · ")}
                      </p>
                    )}
                  </div>
                )) : <EmptyState text="System clean — zero threat findings" />}
              </div>
            </div>
          </div>
        )}

        {/* ── TAB 2: DEEP SCAN INSPECTION ── */}
        {activeTab === "deep_scan" && (
          <div className="flex-col" style={{ gap: 14 }}>
            {!deepScan ? (
              <div className="card cyber-scanner-hero">
                <div className="hud-corner tl" /><div className="hud-corner tr" />
                <div className="hud-corner bl" /><div className="hud-corner br" />
                <div className="cyber-radar-ring">
                  <ShieldAlert size={36} color="var(--amber)" />
                </div>
                <h3 style={{ fontSize: "1.1rem" }}>Deep System Scan Data Not Loaded</h3>
                <p style={{ fontSize: ".82rem", color: "var(--muted)", textAlign: "center", maxWidth: 500 }}>
                  Run a system deep scan on the Firmware Scanner page to populate complete BIOS/UEFI metadata, TPM status, Windows Defender profiles, and startup persistence IOCs.
                </p>
                <button className="cyber-btn-primary" onClick={() => window.location.hash = "simulate"}>
                  <Scan size={18} /> Launch Deep System Scan Now
                </button>
              </div>
            ) : (
              <>
                {/* Firmware & Security Controls row */}
                <div className="report-layout">
                  <div className="card">
                    <p className="eyebrow" style={{ marginBottom: 10 }}>Firmware & Hardware Integrity</p>
                    <div className="stat-grid" style={{ gridTemplateColumns: "repeat(2, 1fr)" }}>
                      <div className="stat-item"><div className="lbl">Firmware Type</div><div className="val">{fw.firmware_type || "—"}</div></div>
                      <div className="stat-item"><div className="lbl">Secure Boot</div><div className="val" style={{ color: fw.secure_boot === "Enabled" ? "var(--emerald)" : "var(--amber)" }}>{fw.secure_boot || "—"}</div></div>
                      <div className="stat-item"><div className="lbl">TPM Chip</div><div className="val">{fw.tpm?.status || "—"}</div></div>
                      <div className="stat-item"><div className="lbl">BIOS Vendor</div><div className="val">{fw.bios?.vendor || "—"}</div></div>
                    </div>
                  </div>

                  <div className="card">
                    <p className="eyebrow" style={{ marginBottom: 10 }}>Endpoint Security Controls</p>
                    <div className="stat-grid" style={{ gridTemplateColumns: "repeat(2, 1fr)" }}>
                      <div className="stat-item"><div className="lbl">Windows Defender</div><div className="val" style={{ color: sec.windows_defender?.real_time_protection === "Enabled" ? "var(--emerald)" : "var(--red)" }}>{sec.windows_defender?.real_time_protection || "—"}</div></div>
                      <div className="stat-item"><div className="lbl">Defender Signatures</div><div className="val">{sec.windows_defender?.signature_age ? `${sec.windows_defender.signature_age} days` : "Current"}</div></div>
                      <div className="stat-item"><div className="lbl">Firewall Private</div><div className="val">{sec.firewall?.private || "—"}</div></div>
                      <div className="stat-item"><div className="lbl">Firewall Public</div><div className="val">{sec.firewall?.public || "—"}</div></div>
                    </div>
                  </div>
                </div>

                {/* Persistence IOC Table */}
                <div className="card">
                  <div className="card-hd">
                    <div><p className="eyebrow">Registry & Task Persistence</p><h3>Startup & Task IOC Inspection</h3></div>
                    <span className="pill neutral">{(pers.startup_items || []).length} items</span>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr><th>Name</th><th>Location / Source</th><th>Command / Executable Path</th><th>Flag</th></tr>
                      </thead>
                      <tbody>
                        {(pers.startup_items || []).slice(0, 10).map((item, i) => (
                          <tr key={i}>
                            <td className="name">{item.name}</td>
                            <td><span className="pill neutral" style={{ fontSize: ".65rem" }}>{item.source}</span></td>
                            <td className="mono truncate" style={{ maxWidth: 300 }}>{item.command || item.path}</td>
                            <td><span className={`pill ${item.suspicious ? "critical" : "low"}`}>{item.suspicious ? "SUSPICIOUS" : "CLEAN"}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Network Open Ports */}
                <div className="card">
                  <div className="card-hd">
                    <div><p className="eyebrow">Network Surface</p><h3>Active Listening Ports</h3></div>
                    <span className="pill cyan">{(net.listening_ports || []).length} open ports</span>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr><th>Port</th><th>Protocol</th><th>Service / Process Name</th><th>State</th></tr>
                      </thead>
                      <tbody>
                        {(net.listening_ports || []).slice(0, 10).map((p, i) => (
                          <tr key={i}>
                            <td className="mono" style={{ color: "var(--cyan)", fontWeight: 700 }}>:{p.port}</td>
                            <td><span className="pill neutral" style={{ fontSize: ".65rem" }}>{p.protocol}</span></td>
                            <td className="name">{p.service || p.process}</td>
                            <td><span className="pill low" style={{ fontSize: ".65rem" }}>LISTENING</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── TAB 3: OWASP MATRIX ── */}
        {activeTab === "owasp" && (
          <div className="flex-col" style={{ gap: 12 }}>
            <div className="card">
              <p className="eyebrow" style={{ marginBottom: 10 }}>OWASP Top 10 Security Guidance Alignment</p>
              {report?.owasp_alignment?.length ? report.owasp_alignment.map((item, i) => (
                <div key={i} className="owasp-item" style={{ marginBottom: 14 }}>
                  <div className="owasp-hd">
                    <span className="owasp-area" style={{ fontSize: ".9rem", fontWeight: 700 }}>{item.area}</span>
                    <span className={`pill ${sevClass(item.status === "aligned" ? "low" : item.status === "attention" ? "high" : "medium")}`}>
                      {item.status}
                    </span>
                  </div>
                  <div className="owasp-guidance" style={{ marginTop: 6 }}>{item.guidance}</div>
                  <div className="owasp-detail" style={{ marginTop: 6 }}><strong>Host Finding:</strong> {item.finding}</div>
                  <div className="owasp-detail" style={{ marginTop: 4 }}><strong>Recommendation:</strong> {item.recommendation}</div>
                </div>
              )) : <EmptyState text="No OWASP matrix data" />}
            </div>
          </div>
        )}

        {/* ── TAB 4: SOAR PLAYBOOK ── */}
        {activeTab === "soar" && (
          <div className="flex-col" style={{ gap: 12 }}>
            <div className="card">
              <p className="eyebrow" style={{ marginBottom: 10 }}>Prioritized SOAR Action Playbook</p>
              {report?.recommended_actions?.length ? report.recommended_actions.map((action, i) => (
                <div key={i} style={{ display: "flex", gap: 12, alignItems: "flex-start", marginBottom: 14 }}>
                  <div style={{ width: 28, height: 28, borderRadius: "50%", background: "var(--primary-dim)", border: "1px solid var(--border-bright)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: ".75rem", fontFamily: "var(--mono)", fontWeight: 700, color: "var(--cyan)", flexShrink: 0 }}>
                    {String(i + 1).padStart(2, "0")}
                  </div>
                  <div>
                    <p style={{ fontSize: ".85rem", lineHeight: 1.5, color: "var(--text)", fontWeight: 600 }}>{action}</p>
                    <p style={{ fontSize: ".74rem", color: "var(--muted)", marginTop: 2 }}>Recommended automated or manual response step for incident isolation.</p>
                  </div>
                </div>
              )) : <EmptyState text="No SOAR actions" />}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}


/* ══════════════════════════════════════
   ADMIN MANAGEMENT DASHBOARD PAGE
══════════════════════════════════════ */
function PageAdmin({ userRole, onRefresh }) {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [busy, setBusy]         = useState("");
  const [msg, setMsg]           = useState(null);
  const [showReset, setShowReset] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [newUser, setNewUser]   = useState({ username: "", password: "", role: "analyst" });

  const isAdmin = userRole === "admin";

  async function load() {
    setLoading(true);
    try {
      const d = await api("/api/admin/dashboard");
      setData(d);
    } catch(e) {
      setMsg({ type: "error", text: e.message });
    } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function handleReset() {
    setBusy("reset");
    try {
      const r = await api("/api/admin/reset", { method: "POST" });
      setMsg({ type: "success", text: r.message });
      setShowReset(false);
      await load();
      onRefresh?.();
    } catch(e) { setMsg({ type: "error", text: e.message }); }
    finally { setBusy(""); }
  }

  async function handleRestart() {
    setBusy("restart");
    setMsg({ type: "warn", text: "Restarting server… reconnecting in 5 seconds." });
    try { await api("/api/admin/restart", { method: "POST" }); } catch(_) {}
    setTimeout(() => { window.location.reload(); }, 5000);
  }

  async function handleCreateUser(e) {
    e.preventDefault();
    setBusy("create");
    try {
      const r = await api("/api/admin/users", {
        method: "POST",
        body: JSON.stringify(newUser),
      });
      setMsg({ type: "success", text: `User '${r.username}' created with role '${r.role}'.` });
      setShowCreate(false);
      setNewUser({ username: "", password: "", role: "analyst" });
      await load();
    } catch(e) { setMsg({ type: "error", text: e.message }); }
    finally { setBusy(""); }
  }

  const scoreColor = (score) => score >= 90 ? "var(--emerald)" : score >= 70 ? "var(--amber)" : "var(--red)";
  const checkIcon  = (st) => st === "pass" ? <CheckCircle2 size={16} color="var(--emerald)" /> : st === "warn" ? <AlertTriangle size={16} color="var(--amber)" /> : <XCircle size={16} color="var(--red)" />;
  const checkCls   = (st) => st === "pass" ? "sev-low" : st === "warn" ? "sev-medium" : "sev-critical";

  if (loading) return (
    <div className="panel" style={{ alignItems: "center", justifyContent: "center", gap: 12 }}>
      <div className="live-ring"><div className="live-ring-dot live" /></div>
      <p style={{ color: "var(--muted)" }}>Loading security dashboard…</p>
    </div>
  );

  const score = data?.security_score ?? 0;
  const checks = data?.checks ?? {};
  const items  = data?.security_items ?? [];
  const sysInfo = data?.system_info ?? {};
  const stats  = data?.data_stats ?? {};
  const users  = data?.users ?? [];

  return (
    <div className="panel" style={{ gap: 14, overflowY: "auto" }}>

      {/* Banner message */}
      {msg && (
        <div className={`info-banner ${msg.type === "error" ? "err" : msg.type === "warn" ? "" : ""}`}
          style={{ borderColor: msg.type === "success" ? "var(--emerald)" : msg.type === "warn" ? "var(--amber)" : "var(--red)",
                   borderLeft: "3px solid", padding: "8px 14px", fontSize: ".8rem", borderRadius: 6,
                   background: "rgba(0,0,0,.3)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>{msg.text}</span>
          <button onClick={() => setMsg(null)} style={{ background: "none", border: "none", color: "var(--muted)", cursor: "pointer" }}>✕</button>
        </div>
      )}

      {/* Top row: score + actions */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, flexShrink: 0 }}>

        {/* Security Score */}
        <div className="card" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6, padding: "20px 14px" }}>
          <p className="eyebrow">Security Posture</p>
          <div style={{ fontSize: "3rem", fontWeight: 800, color: scoreColor(score), lineHeight: 1 }}>{score}%</div>
          <div style={{ display: "flex", gap: 10, fontSize: ".72rem", marginTop: 4, alignItems: "center" }}>
            <span style={{ color: "var(--emerald)", display: "flex", alignItems: "center", gap: 4 }}><CheckCircle2 size={13} /> {checks.passed} passed</span>
            <span style={{ color: "var(--amber)", display: "flex", alignItems: "center", gap: 4 }}><AlertTriangle size={13} /> {checks.warned} warn</span>
            <span style={{ color: "var(--red)", display: "flex", alignItems: "center", gap: 4 }}><XCircle size={13} /> {checks.failed} fail</span>
          </div>
          <div style={{ width: "100%", height: 6, background: "rgba(255,255,255,.1)", borderRadius: 3, marginTop: 6 }}>
            <div style={{ width: `${score}%`, height: "100%", background: scoreColor(score), borderRadius: 3, transition: "width .6s" }} />
          </div>
        </div>

        {/* System Info */}
        <div className="card" style={{ padding: "16px 14px" }}>
          <p className="eyebrow" style={{ marginBottom: 10 }}>System Configuration</p>
          {[
            ["JWT Expiry",       `${sysInfo.jwt_expire_minutes}m`],
            ["SOAR Enabled",     sysInfo.soar_enabled ? "Yes" : "No"],
            ["SOAR Threshold",   sysInfo.soar_threshold],
            ["Approval Gate",    sysInfo.soar_require_approval ? "Enabled (On)" : "Disabled (Off)"],
            ["AI Classifier",    sysInfo.gemini_active ? "Gemini API" : "Local ML"],
            ["Python",           sysInfo.python_version],
            ["Events in DB",     stats.events_in_db],
            ["Alerts in DB",     stats.alerts_in_db],
          ].map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: ".73rem", marginBottom: 4 }}>
              <span style={{ color: "var(--muted)" }}>{k}</span>
              <span style={{ fontFamily: "var(--mono)" }}>{v}</span>
            </div>
          ))}
        </div>

        {/* Danger Zone */}
        <div className="card" style={{ padding: "16px 14px" }}>
          <p className="eyebrow" style={{ marginBottom: 10, color: "var(--red)" }}>Danger Zone</p>
          {isAdmin ? (
            <>
              <button
                className="btn"
                style={{ width: "100%", marginBottom: 10, background: "rgba(255,60,60,.15)", borderColor: "var(--red)", color: "var(--red)", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
                onClick={() => setShowReset(true)}
              ><Trash2 size={14} /> Clear All Data</button>
              <button
                className="btn"
                style={{ width: "100%", background: "rgba(245,158,11,.12)", borderColor: "var(--amber)", color: "var(--amber)", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
                onClick={handleRestart}
                disabled={busy === "restart"}
              >{busy === "restart" ? "Restarting…" : <><RotateCcw size={14} /> Restart Application</>}</button>
              <p style={{ fontSize: ".68rem", color: "var(--muted)", marginTop: 10, lineHeight: 1.5 }}>
                Clear Data removes all events and alerts from the database. Restart reloads the server process.
              </p>
            </>
          ) : (
            <p style={{ fontSize: ".75rem", color: "var(--muted)", display: "flex", alignItems: "center", gap: 4 }}><Lock size={14} /> Admin role required for these actions.</p>
          )}
        </div>
      </div>

      {/* Security Checklist */}
      <div className="card fill" style={{ overflow: "hidden", display: "flex", flexDirection: "column", minHeight: 0 }}>
        <div className="card-hd">
          <div><p className="eyebrow">Security Controls</p><h3>Hardening Checklist</h3></div>
          <button className="btn" onClick={load} style={{ fontSize: ".72rem", padding: "4px 10px" }}>↻ Refresh</button>
        </div>
        <div style={{ overflowY: "auto", flex: 1 }}>
          {items.map(item => (
            <div key={item.id} style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,.05)" }}>
              <span style={{ fontSize: "1rem", flexShrink: 0, marginTop: 1 }}>{checkIcon(item.status)}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                  <span style={{ fontWeight: 600, fontSize: ".8rem" }}>{item.label}</span>
                  <span className={`pill ${checkCls(item.status)}`} style={{ fontSize: ".6rem", padding: "2px 6px" }}>
                    {item.status.toUpperCase()}
                  </span>
                </div>
                <p style={{ fontSize: ".72rem", color: "var(--muted)", margin: 0 }}>{item.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* User Management */}
      {isAdmin && (
        <div className="card" style={{ flexShrink: 0 }}>
          <div className="card-hd">
            <div><p className="eyebrow">IAM</p><h3>User Accounts</h3></div>
            <button className="btn primary" onClick={() => setShowCreate(true)} style={{ fontSize: ".72rem", padding: "4px 12px" }}>+ New User</button>
          </div>
          <div className="table-wrap">
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: ".78rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,.08)" }}>
                  {["Username", "Role", "Status", "Last Login", "Display ID"].map(h => (
                    <th key={h} style={{ padding: "6px 8px", textAlign: "left", color: "var(--muted)", fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,.04)" }}>
                    <td style={{ padding: "7px 8px", fontFamily: "var(--mono)" }}>{u.username}</td>
                    <td style={{ padding: "7px 8px" }}>
                      <span className={`pill ${u.role === "admin" ? "critical" : u.role === "analyst" ? "medium" : "low"}`} style={{ fontSize: ".6rem" }}>
                        {u.role}
                      </span>
                    </td>
                    <td style={{ padding: "7px 8px" }}>
                      <span style={{ color: u.is_active ? "var(--emerald)" : "var(--red)" }}>{u.is_active ? "Active" : "Disabled"}</span>
                    </td>
                    <td style={{ padding: "7px 8px", color: "var(--muted)" }}>{u.last_login ? new Date(u.last_login).toLocaleString() : "Never"}</td>
                    <td style={{ padding: "7px 8px", fontFamily: "var(--mono)", fontSize: ".68rem", color: "var(--muted)" }}>{u.display_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Reset Confirmation Modal */}
      {showReset && createPortal(
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.7)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div className="card" style={{ width: 400, padding: 24, gap: 16, display: "flex", flexDirection: "column" }}>
            <h3 style={{ color: "var(--red)", margin: 0 }}>⚠ Confirm Data Reset</h3>
            <p style={{ fontSize: ".82rem", color: "var(--muted)", margin: 0, lineHeight: 1.6 }}>
              This will permanently delete <strong>all events and alerts</strong> from the database and reset all monitor counters and the ML baseline. This action cannot be undone.
            </p>
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <button className="btn" onClick={() => setShowReset(false)}>Cancel</button>
              <button
                className="btn"
                style={{ background: "rgba(255,60,60,.2)", borderColor: "var(--red)", color: "var(--red)" }}
                onClick={handleReset}
                disabled={busy === "reset"}
              >{busy === "reset" ? "Clearing…" : "Clear All Data"}</button>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Create User Modal */}
      {showCreate && createPortal(
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.7)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <form className="card" style={{ width: 420, padding: 24, gap: 14, display: "flex", flexDirection: "column" }} onSubmit={handleCreateUser}>
            <h3 style={{ margin: 0 }}>Create User Account</h3>
            <div>
              <label className="field-label">Username</label>
              <input className="input-field" type="text" value={newUser.username} onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))} required minLength={3} placeholder="jdoe" />
            </div>
            <div>
              <label className="field-label">Password (min 12 chars)</label>
              <input className="input-field" type="password" value={newUser.password} onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))} required minLength={12} placeholder="••••••••••••" />
            </div>
            <div>
              <label className="field-label">Role</label>
              <select className="input-field" value={newUser.role} onChange={e => setNewUser(p => ({ ...p, role: e.target.value }))} style={{ background: "var(--card)", color: "var(--text)" }}>
                <option value="viewer">Viewer (read-only)</option>
                <option value="analyst">Analyst (view + respond)</option>
                <option value="admin">Admin (full access)</option>
              </select>
            </div>
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", marginTop: 4 }}>
              <button type="button" className="btn" onClick={() => setShowCreate(false)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy === "create"}>
                {busy === "create" ? "Creating…" : "Create User"}
              </button>
            </div>
          </form>
        </div>,
        document.body
      )}

    </div>
  );
}

/* ══════════════════════════════════════
   ROOT APP
══════════════════════════════════════ */
const VALID_PAGES = new Set(NAV.map(n => n.id));
function getHashPage() {
  const h = window.location.hash.replace("#", "").trim();
  return VALID_PAGES.has(h) ? h : "overview";
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(() => {
    // On mount, check if the stored token is already expired
    const token = localStorage.getItem("hids_jwt_token");
    if (!token) return false;
    if (isTokenExpired()) {
      localStorage.removeItem("hids_jwt_token");
      localStorage.removeItem("hids_jwt_user");
      return false;
    }
    return true;
  });
  const [page, setPage]       = useState(getHashPage);
  const [selMetric, setSel]   = useState("total_events");
  const [busy, setBusy]       = useState("");
  const [error, setError]     = useState("");
  const [tokenExp, setTokExp] = useState(() => getTokenExpiresIn());
  const [mobileOpen, setMobileOpen] = useState(false);
  const [d, setD] = useState({ metrics: {}, alerts: [], events: [], baseline: {}, system: {}, monitor: {}, report: null });

  // ── Logout helper ────────────────────────────────────────────────────
  const doLogout = useCallback(async () => {
    // Call server-side logout to blacklist the token
    try { await api("/api/auth/logout", { method: "POST" }); } catch(_) {}
    localStorage.removeItem("hids_jwt_token");
    localStorage.removeItem("hids_jwt_user");
    localStorage.removeItem("hids_jwt_role");
    setAuthenticated(false);
    setD({ metrics: {}, alerts: [], events: [], baseline: {}, system: {}, monitor: {}, report: null });
    setError("");
  }, []);

  // ── Listen for global auth-expired events fired by api() ─────────────
  useEffect(() => {
    window.addEventListener(AUTH_EXPIRED_EVENT, doLogout);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, doLogout);
  }, [doLogout]);

  // ── Countdown token expiry timer ─────────────────────────────────────
  useEffect(() => {
    if (!authenticated) return;
    const t = setInterval(() => {
      const secs = getTokenExpiresIn();
      setTokExp(secs);
      if (secs !== null && secs <= 0) doLogout();
    }, 10000); // check every 10s
    return () => clearInterval(t);
  }, [authenticated, doLogout]);

  async function refresh() {
    if (!authenticated) return;
    try {
      const [metrics, alerts, events, baseline, system, monitor, report] = await Promise.all([
        api("/api/metrics"), api("/api/alerts"), api("/api/events"),
        api("/api/baseline"), api("/api/system"), api("/api/monitor/status"), api("/api/report"),
      ]);
      setD({ metrics, alerts, events, baseline, system, monitor, report });
      setError("");
    } catch(e) {
      // Only show error if still authenticated (avoid stale errors after auto-logout)
      if (authenticated) setError(e.message);
    }
  }

  useEffect(() => {
    if (!authenticated) return;
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [authenticated]);

  // WebSocket push
  useEffect(() => {
    if (!authenticated) return;
    const token = localStorage.getItem("hids_jwt_token");
    if (!token) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/telemetry?token=${encodeURIComponent(token)}`;
    let ws;
    try {
      ws = new WebSocket(wsUrl);
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === "event" && msg.data) {
            setD(prev => ({
              ...prev,
              events: [msg.data, ...(prev.events || []).slice(0, 99)],
              // Immediately bump counters so tiles update without waiting for next poll
              metrics: {
                ...prev.metrics,
                total_events:    (prev.metrics?.total_events    || 0) + 1,
                events_per_hour: (prev.metrics?.events_per_hour || 0) + 1,
              },
            }));
          } else if (msg.type === "alert" && msg.data) {
            const sev = (msg.data.severity || "").toLowerCase();
            setD(prev => ({
              ...prev,
              alerts: [msg.data, ...(prev.alerts || [])],
              metrics: {
                ...prev.metrics,
                total_alerts:    (prev.metrics?.total_alerts    || 0) + 1,
                critical_alerts: (prev.metrics?.critical_alerts || 0) + (sev === "critical" ? 1 : 0),
                // Update rolling anomaly score with latest alert score
                anomaly_score: msg.data.anomaly_score != null
                  ? parseFloat(msg.data.anomaly_score).toFixed(2)
                  : prev.metrics?.anomaly_score,
              },
            }));
          }
        } catch(_) {}
      };
    } catch(_) {}
    return () => { ws?.close(); };
  }, [authenticated]);

  // Hash nav
  useEffect(() => {
    const onHash = () => setPage(getHashPage());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  function navigate(id) { window.location.hash = id; }

  async function act(key, url) {
    setBusy(key);
    try { await api(url, { method: "POST" }); await refresh(); }
    catch(e) { setError(e.message); }
    finally { setBusy(""); }
  }

  async function exportReport(fmt) {
    setBusy(`export-${fmt}`);
    try {
      const token = localStorage.getItem("hids_jwt_token");
      const r = await fetch(`/api/report/export?format=${fmt}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!r.ok) throw new Error(`Export failed: ${r.status}`);
      const blob = await r.blob();
      const disp = r.headers.get("Content-Disposition") || "";
      const m = disp.match(/filename="(.+)"/);
      const fn = m ? m[1] : `hids-report.${fmt === "word" ? "docx" : fmt}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = fn;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } catch(e) { setError(e.message); }
    finally { setBusy(""); }
  }

  async function regenReport() {
    setBusy("report");
    try { const r = await api("/api/report"); setD(c => ({ ...c, report: r })); setError(""); }
    catch(e) { setError(e.message); }
    finally { setBusy(""); }
  }

  if (!authenticated) return <LoginScreen onLoginSuccess={() => setAuthenticated(true)} />;

  const { metrics, alerts, events, baseline, system, monitor, report } = d;
  const topProc    = system.top_processes || [];
  const suspicious = system.suspicious_processes || [];
  const critCount  = (alerts || []).filter(a => a.severity?.toLowerCase() === "critical").length;

  const PAGE_TITLE = {
    overview: "Overview",  monitor: "Host Monitor",   processes: "Processes",
    alerts: "Alerts",      events: "Event Stream",    simulate: "Firmware Scanner",
    yara: "YARA Scanner",  agents: "Agent Fleet",     baseline: "Baseline",   report: "Security Report",
    admin: "Security Admin",
  };
  const userRole = localStorage.getItem("hids_jwt_role") || "analyst";

  return (
    <>
      <BgCanvas />
      <MobileDrawer
        open={mobileOpen}
        onClose={() => setMobileOpen(false)}
        page={page}
        setPage={navigate}
        alertCount={critCount}
        onLogout={doLogout}
        userRole={userRole}
      />
      <div className="shell">
        <Sidebar page={page} setPage={navigate} alertCount={critCount} monLive={monitor.enabled} onLogout={doLogout} userRole={userRole} />
        <main className="main">
          {/* Top bar */}
          <div className="topbar">
            <button className="mobile-menu-btn" onClick={() => setMobileOpen(true)} title="Open Menu">
              <Menu size={18} />
            </button>
            <div className="topbar-title">
              <strong>AI-HIDS Sentinel</strong> / {PAGE_TITLE[page] || page}
            </div>
            {error && <div className="info-banner err" style={{ padding: "4px 10px", fontSize: ".72rem" }}>⚠ {error}</div>}
            <div className="live-ring">
              <div className={`live-ring-dot ${monitor.enabled ? "live" : ""}`} />
              <span>{monitor.enabled ? "LIVE" : "IDLE"}</span>
            </div>
            {tokenExp !== null && tokenExp < 3600 && (
              <span
                className={`pill mono ${tokenExp < 300 ? "high" : "neutral"}`}
                style={{ fontSize: ".65rem", cursor: "default" }}
                title={`Session expires in ${tokenExp}s`}
              >
                {tokenExp < 60 ? `⚠ ${tokenExp}s` : tokenExp < 3600 ? `⏱ ${Math.round(tokenExp/60)}m` : ""}
              </span>
            )}
            <span className="pill neutral mono" style={{ fontSize: ".65rem" }}>{system.hostname || "—"}</span>
          </div>

          {/* Panel host */}
          <div className="panel-host">
            {page === "overview"  && <PageOverview  metrics={metrics} alerts={alerts} events={events} system={system} monitor={monitor} setPage={navigate} topProc={topProc} selMetric={selMetric} setSelMetric={setSel} />}
            {page === "monitor"   && <PageMonitor   system={system} monitor={monitor} busy={busy} act={act} />}
            {page === "processes" && <PageProcesses topProc={topProc} suspicious={suspicious} setPage={navigate} />}
            {page === "alerts"    && <PageAlerts    alerts={alerts} />}
            {page === "events"    && <PageEvents    events={events} />}
            {page === "simulate"  && <PageSimulate suspicious={suspicious} />}
            {page === "yara"      && <PageYARA />}
            {page === "agents"    && <PageAgents />}
            {page === "baseline"  && <PageBaseline baseline={baseline} />}
            {page === "report"    && <PageReport   report={report} busy={busy} onExport={exportReport} onRefresh={regenReport} />}
            {page === "admin"     && <PageAdmin userRole={userRole} onRefresh={refresh} />}
          </div>
        </main>
      </div>
    </>
  );
}
