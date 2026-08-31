/**
 * Animated brand mark — the "Guardian Orbit". A shield-and-flame RAKSHAK core
 * inside two counter-rotating rings: an inner ring of analytic nodes
 * (detect / protect / analyze / evaluate / correlate) and an outer ring of
 * white surface badges (globe / shield / wifi / bug / database / cloud).
 * Pure CSS animation, no client state — safe in server components.
 *
 * Authored on the design canvas "Rakshak Guardian Orbit" and ported here.
 * Everything is laid out in a fixed 600px coordinate space and scaled to
 * `size`, so all five call sites (110–320px) keep the same composition.
 */
const BASIS = 600;

interface IntelligenceCoreProps {
  size?: number;
  className?: string;
}

interface RingItem {
  left: string;
  top: string;
  color?: string;
  dark?: boolean;
  icon: React.ReactNode;
}

const S = {
  ink: "#605d5d",
  accent: "#ae1800",
  flame: "#ec3013",
} as const;

// 6 badges evenly spaced 60° apart on r=262 about (300,300), as % of the 600 box.
// Dark ShieldCheck anchors dead-bottom (A=180°).
const OUTER_BADGES: RingItem[] = [
  { left: "50%", top: "6.333%", color: S.ink, icon: <DatabaseLock /> },
  { left: "87.817%", top: "28.167%", color: S.ink, icon: <WifiLock /> },
  { left: "87.817%", top: "71.833%", color: S.accent, icon: <BugMark /> },
  { left: "50%", top: "93.667%", dark: true, icon: <ShieldCheck /> },
  { left: "12.183%", top: "71.833%", color: S.ink, icon: <CloudLock /> },
  { left: "12.183%", top: "28.167%", color: S.accent, icon: <GlobeLock /> },
];

const INNER_NODES: RingItem[] = [
  { left: "33.9%", top: "30.85%", color: S.accent, icon: <Crosshair /> },
  { left: "66.1%", top: "30.85%", color: S.ink, icon: <ShieldLock /> },
  { left: "73.5%", top: "58.55%", color: S.ink, icon: <SearchMark /> },
  { left: "50%", top: "75%", color: S.ink, icon: <Firewall /> },
  { left: "27.9%", top: "61.73%", color: S.ink, icon: <MailWarn /> },
];

export function IntelligenceCore({ size = 240, className }: IntelligenceCoreProps) {
  return (
    <div
      className={className}
      style={{ width: size, height: size, position: "relative", flex: "none" }}
      role="img"
      aria-label="Rakshak Intelligence Core: detect, analyze, correlate, evaluate, protect"
    >
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: BASIS,
          height: BASIS,
          transform: `scale(${size / BASIS})`,
          transformOrigin: "top left",
        }}
      >
        <svg
          viewBox="0 0 600 600"
          width={600}
          height={600}
          fill="none"
          style={{ position: "absolute", inset: 0 }}
        >
          <circle cx="300" cy="300" r="262" stroke="rgba(32,30,29,.30)" strokeWidth="1" />
          <circle cx="300" cy="300" r="150" stroke="var(--rk-neutral-400)" strokeWidth="1" strokeDasharray="3 6" />
          <g stroke="var(--rk-neutral-300)" strokeWidth="1">
            <line x1="203.6" y1="185.1" x2="266.6" y2="260.2" />
            <line x1="396.4" y1="185.1" x2="333.4" y2="260.2" />
            <line x1="441.0" y1="351.3" x2="348.9" y2="317.8" />
            <line x1="300.0" y1="450.0" x2="300.0" y2="352.0" />
            <line x1="167.5" y1="370.4" x2="254.1" y2="275.6" />
          </g>
        </svg>

        <span
          style={{
            position: "absolute",
            left: 299,
            top: 38,
            width: 2,
            height: 262,
            background: "linear-gradient(to top, rgba(236,48,19,0), rgba(236,48,19,.55))",
            transformOrigin: "50% 100%",
            animation: "rk-spin 14s linear infinite",
          }}
        />

        <div style={{ position: "absolute", inset: 0, animation: "rk-spin-rev 60s linear infinite" }}>
          {INNER_NODES.map((n, i) => (
            <div
              key={i}
              style={{
                position: "absolute",
                left: n.left,
                top: n.top,
                width: 40,
                height: 40,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                transform: "translate(-50%,-50%)",
                color: n.color,
                animation: "rk-spin 60s linear infinite",
              }}
            >
              {n.icon}
            </div>
          ))}
        </div>

        <div style={{ position: "absolute", inset: 0, animation: "rk-spin 46s linear infinite" }}>
          {OUTER_BADGES.map((b, i) => (
            <div
              key={i}
              style={{
                position: "absolute",
                left: b.left,
                top: b.top,
                width: 58,
                height: 58,
                transform: "translate(-50%,-50%)",
              }}
            >
              <div
                style={{
                  width: "100%",
                  height: "100%",
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: b.dark ? "#201e1d" : "#ffffff",
                  color: b.dark ? "#f8f4f4" : b.color,
                  boxShadow: "0 6px 16px rgba(45,43,43,.18), 0 1px 3px rgba(45,43,43,.12)",
                  animation: "rk-spin-rev 46s linear infinite",
                }}
              >
                {b.icon}
              </div>
            </div>
          ))}
        </div>

        <div
          style={{
            position: "absolute",
            left: "50%",
            top: "50%",
            transform: "translate(-50%,-50%)",
            width: 260,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 8,
            textAlign: "center",
          }}
        >
          <span
            style={{
              position: "absolute",
              left: 55,
              top: 34,
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: "radial-gradient(circle, rgba(236,48,19,.30) 0%, rgba(236,48,19,0) 70%)",
              animation: "rk-breathe 3.6s ease-in-out infinite",
            }}
          />
          <svg width={108} height={108} viewBox="0 0 120 120" fill="none" style={{ position: "relative" }}>
            <path d="M60 8 L104 24 V58 C104 86 86 106 60 114 C34 106 16 86 16 58 V24 Z" fill={S.accent} />
            <path
              d="M60 8 L104 24 V58 C104 86 86 106 60 114 C34 106 16 86 16 58 V24 Z"
              fill="none"
              stroke="#7c1405"
              strokeWidth="2"
            />
            <path d="M42 30 L42 74 L60 88 L60 44 Z" fill={S.flame} />
            <path
              d="M60 20 C54 34 50 44 58 58 C52 56 47 50 47 42 C41 52 44 66 54 74 C48 74 46 80 50 88 L60 96 L70 88 C74 80 72 74 66 74 C76 66 79 52 73 42 C73 50 68 56 62 58 C70 44 66 34 60 20 Z"
              fill="#201e1d"
            />
          </svg>
          <span
            style={{
              fontFamily: "var(--font-archivo), system-ui, sans-serif",
              fontWeight: 800,
              fontSize: 33,
              letterSpacing: "0.1em",
              color: "#201e1d",
              lineHeight: 1,
            }}
          >
            RAKSHAK
          </span>
          <span
            style={{
              fontFamily: "var(--font-archivo), system-ui, sans-serif",
              fontWeight: 700,
              fontSize: 10,
              letterSpacing: "0.34em",
              color: S.accent,
              lineHeight: 1,
            }}
          >
            YOUR DIGITAL GUARDIAN
          </span>
        </div>
      </div>
    </div>
  );
}

/* ---- icons: 24x24, stroke = currentColor, ported from the design canvas ---- */

function Crosshair() {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="6" />
      <path d="M12 1v4M12 19v4M1 12h4M19 12h4" />
      <circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" />
    </svg>
  );
}

function ShieldLock() {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l8 3v6c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V5z" />
      <rect x="9" y="11" width="6" height="5" rx="1" />
      <path d="M10 11V9.5a2 2 0 0 1 4 0V11" />
    </svg>
  );
}

function SearchMark() {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="M20 20l-4.7-4.7" />
      <path d="M8 10.5h5M10.5 8v5" stroke="#ae1800" />
    </svg>
  );
}

function Firewall() {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="5" width="18" height="14" rx="1" />
      <path d="M3 10h18M3 14.5h18M9 5v5M15 10v4.5M12 14.5V19M6 14.5V19" />
      <path d="M15.5 13.5l2.5 1 2.5-1V16c0 1.7-1.2 2.8-2.5 3.2-1.3-.4-2.5-1.5-2.5-3.2z" fill="#ae1800" stroke="#ae1800" />
    </svg>
  );
}

function MailWarn() {
  return (
    <svg viewBox="0 0 24 24" width={24} height={24} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="5" width="18" height="14" rx="1.5" />
      <path d="M3.5 6l8.5 7 8.5-7" />
      <circle cx="19" cy="7" r="3.4" fill="#ae1800" stroke="none" />
      <path d="M19 5.4v2M19 8.7v.2" stroke="#fff" strokeWidth="1.6" />
    </svg>
  );
}

function GlobeLock() {
  return (
    <svg viewBox="0 0 24 24" width={26} height={26} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <path d="M3 11h16M11 3c3 2.5 3 13.5 0 16M11 3C8 5.5 8 16.5 11 19" />
      <rect x="14.5" y="15" width="7" height="6" rx="1" fill="#fff" />
      <rect x="14.5" y="15" width="7" height="6" rx="1" />
      <path d="M16 15v-1.5a2 2 0 0 1 4 0V15" />
    </svg>
  );
}

function ShieldCheck() {
  return (
    <svg viewBox="0 0 24 24" width={26} height={26} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l8 3v6c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V5z" />
      <path d="M8.5 12l2.5 2.5L16 9" />
    </svg>
  );
}

function WifiLock() {
  return (
    <svg viewBox="0 0 24 24" width={26} height={26} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 9c5-4 13-4 18 0M6 12.5c3.6-2.8 8.4-2.8 12 0M9 16c1.8-1.3 4.2-1.3 6 0" />
      <circle cx="12" cy="19.5" r="1.2" fill="currentColor" stroke="none" />
      <rect x="15.5" y="15" width="7" height="6" rx="1" fill="#ae1800" stroke="#ae1800" />
      <path d="M17 15v-1.5a2 2 0 0 1 4 0V15" stroke="#ae1800" />
    </svg>
  );
}

function BugMark() {
  return (
    <svg viewBox="0 0 24 24" width={26} height={26} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="12" cy="13" rx="5" ry="6" />
      <path d="M12 7V4M9.5 5l-2-2M14.5 5l2-2" />
      <path d="M7 10L3.5 8.5M7 13H3M7 16l-3.5 1.5M17 10l3.5-1.5M17 13h4M17 16l3.5 1.5" />
      <path d="M12 7v12" />
    </svg>
  );
}

function DatabaseLock() {
  return (
    <svg viewBox="0 0 24 24" width={26} height={26} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="12" cy="6" rx="7" ry="3" />
      <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
      <rect x="14.5" y="14.5" width="7" height="6" rx="1" fill="#ae1800" stroke="#ae1800" />
      <path d="M16 14.5V13a2 2 0 0 1 4 0v1.5" stroke="#ae1800" />
    </svg>
  );
}

function CloudLock() {
  return (
    <svg viewBox="0 0 24 24" width={26} height={26} fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d="M7 18a4.5 4.5 0 0 1 0-9 6 6 0 0 1 11.5 1.5A4 4 0 0 1 18 18z" />
      <rect x="9.5" y="14" width="6" height="5" rx="1" fill="#ae1800" stroke="#ae1800" />
      <path d="M11 14v-1.3a1.5 1.5 0 0 1 3 0V14" stroke="#ae1800" />
    </svg>
  );
}
