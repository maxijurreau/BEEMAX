import { useEffect, useRef, useState } from "react";
import "./UnifiedHUD.css";

type ChatMessage = { author: "system" | "user" | "manifold"; text: string };

const PRIVATE_KEY_DER_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

function decodePrivateSeed(hex: string): Uint8Array {
  const normalized = hex.trim();
  if (!/^(?:[0-9a-fA-F]{2}){32}$/.test(normalized)) {
    throw new Error("Enter a 64-character hex Ed25519 private seed.");
  }
  return Uint8Array.from(normalized.match(/.{2}/g)!, (byte) => Number.parseInt(byte, 16));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signPayload(payload: string, privateSeed: Uint8Array): Promise<string> {
  const pkcs8 = new Uint8Array(PRIVATE_KEY_DER_PREFIX.length + privateSeed.length);
  pkcs8.set(PRIVATE_KEY_DER_PREFIX);
  pkcs8.set(privateSeed, PRIVATE_KEY_DER_PREFIX.length);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    key,
    new TextEncoder().encode(payload),
  );
  return bytesToHex(new Uint8Array(signature));
}

/** Interactive spatial HUD. The chat response is a local visual demo, not an AI API. */
export function UnifiedHUD() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const chatLogRef = useRef<HTMLDivElement>(null);
  const colorRef = useRef("#10b981");
  const [endpoint, setEndpoint] = useState("http://localhost:8787");
  const [privateKey, setPrivateKey] = useState("");
  const [status, setStatus] = useState("STANDBY");
  const [output, setOutput] = useState("Awaiting signed sovereign query…");
  const [updatedAt, setUpdatedAt] = useState("—");
  const [busy, setBusy] = useState(false);
  const [chatText, setChatText] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([
    { author: "system", text: "BEEMAX Sovereign Manifold online. Chat responses are a local demo." },
  ]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const host = canvas?.parentElement;
    const context = canvas?.getContext("2d");
    if (!canvas || !host || !context) return;

    const points = Array.from({ length: 1200 }, () => ({
      x: (Math.random() - 0.5) * 50,
      y: (Math.random() - 0.5) * 50,
      z: (Math.random() - 0.5) * 50,
    }));
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    let rotation = 0;
    let width = 0;
    let height = 0;
    let pixelRatio = 1;

    const resize = () => {
      const rect = host.getBoundingClientRect();
      pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;
      canvas.width = Math.max(1, Math.floor(width * pixelRatio));
      canvas.height = Math.max(1, Math.floor(height * pixelRatio));
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    };

    const draw = () => {
      context.clearRect(0, 0, width, height);
      context.fillStyle = "#090c0b";
      context.fillRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height / 2;
      const cos = Math.cos(rotation);
      const sin = Math.sin(rotation);
      const projected = points.map((point) => {
        const x = point.x * cos - point.z * sin;
        const z = point.x * sin + point.z * cos + 55;
        const scale = 420 / Math.max(1, z);
        return { x: cx + x * scale, y: cy + point.y * scale, scale };
      });

      context.fillStyle = colorRef.current;
      for (const point of projected) {
        const size = Math.max(0.7, point.scale * 0.055);
        context.globalAlpha = Math.min(0.85, 0.25 + point.scale / 35);
        context.beginPath();
        context.arc(point.x, point.y, size, 0, Math.PI * 2);
        context.fill();
      }
      context.globalAlpha = 1;
      if (!reducedMotion) rotation += 0.0015;
      if (!reducedMotion) frame = requestAnimationFrame(draw);
    };

    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();
    draw();
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, []);

  useEffect(() => {
    const log = chatLogRef.current;
    if (log) log.scrollTop = log.scrollHeight;
  }, [messages]);

  async function dispatchQuery() {
    if (busy) return;
    setBusy(true);
    setStatus("CONNECTING");
    setOutput("Signing request and contacting the configured Worker…");
    try {
      const base = endpoint.trim().replace(/\/+$/, "");
      const target = new URL("/api/manifold/hud", base);
      if (target.protocol !== "https:" && target.hostname !== "localhost" && target.hostname !== "127.0.0.1") {
        throw new Error("Use HTTPS for non-local Worker endpoints.");
      }
      const timestamp = Date.now().toString();
      const identity = "maxjurreau-3";
      const signature = await signPayload(
        `${target.pathname}:${timestamp}:${identity}`,
        decodePrivateSeed(privateKey),
      );
      const response = await fetch(target, {
        method: "GET",
        headers: {
          Accept: "application/json",
          "X-QAL-Timestamp": timestamp,
          "X-QAL-Identity": identity,
          "X-QAL-Signature": signature,
        },
      });
      const text = await response.text();
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = { rawResponse: text };
      }
      setOutput(JSON.stringify(body, null, 2));
      setUpdatedAt(new Date().toLocaleTimeString());
      setStatus(`${response.status} ${response.ok ? "ACTIVE" : "DENIED"}`);
    } catch (error) {
      setOutput(`[Edge Error]\n${error instanceof Error ? error.message : "Request failed."}`);
      setStatus("ERROR");
    } finally {
      setBusy(false);
    }
  }

  function sendMessage() {
    const text = chatText.trim();
    if (!text) return;
    setChatText("");
    setMessages((current) => [...current, { author: "user", text }]);
    window.setTimeout(() => {
      setMessages((current) => [
        ...current,
        { author: "manifold", text: `Local demo response: vector target acknowledged for “${text}”. No AI service was contacted.` },
      ]);
      colorRef.current = Math.random() > 0.5 ? "#3b82f6" : "#10b981";
    }, 350);
  }

  return (
    <section className="sovereign-hud" aria-label="BEEMAX sovereign spatial HUD">
      <header className="sovereign-header">
        <div className="sovereign-brand"><span className="pulse-dot" />
          <h1>BEEMAX <span>// SOVEREIGN SPATIAL HUD</span></h1>
        </div>
        <div className="sovereign-meta">
          <span>IDENTITY <b>maxjurreau-3</b></span>
          <span>ISOLATE REGION <b className="region">JFK-EDGE</b></span>
          <span className={`connection ${status === "STANDBY" ? "" : status.includes("ACTIVE") ? "is-active" : status === "CONNECTING" ? "is-connecting" : "is-error"}`}>{status}</span>
        </div>
      </header>

      <div className="sovereign-workspace">
        <aside className="sovereign-sidebar">
          <section className="hud-panel credentials-panel">
            <h2>Edge credentials</h2>
            <label htmlFor="hud-endpoint">Worker endpoint URL</label>
            <input id="hud-endpoint" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} inputMode="url" autoComplete="url" />
            <label htmlFor="hud-private-key">Ed25519 private seed (hex)</label>
            <input
              id="hud-private-key"
              type="password"
              value={privateKey}
              onChange={(event) => setPrivateKey(event.target.value)}
              placeholder="64 hex characters"
              autoComplete="new-password"
              spellCheck={false}
            />
            <p className="key-warning">The key stays in this page's memory and is not saved. Only use a trusted origin; browser scripts can access entered keys.</p>
            <button type="button" className="dispatch-button" onClick={() => void dispatchQuery()} disabled={busy}>
              {busy ? "SIGNING…" : "DISPATCH SIGNED HUD QUERY"}
            </button>
          </section>

          <section className="hud-panel telemetry-panel">
            <div className="telemetry-heading"><h2>Live isolate telemetry</h2><time>{updatedAt}</time></div>
            <pre aria-live="polite">{output}</pre>
          </section>
        </aside>

        <div className="spatial-workspace">
          <div className="spatial-canvas" ref={undefined}>
            <canvas ref={canvasRef} aria-label="Animated spatial particle visualization" />
            <div className="mesh-label">SPATIAL RENDERING // <b>ACTIVE MESH MATRIX</b></div>
          </div>
          <section className="manifold-chat" aria-label="Manifold chat demo">
            <div className="chat-log" ref={chatLogRef} aria-live="polite">
              {messages.map((message, index) => (
                <p className={`chat-message ${message.author}`} key={`${message.author}-${index}`}>
                  <strong>{message.author === "user" ? "[maxjurreau-3]" : message.author === "manifold" ? "[BEEMAX Manifold]" : "[System]"}:</strong> {message.text}
                </p>
              ))}
            </div>
            <form className="chat-form" onSubmit={(event) => { event.preventDefault(); sendMessage(); }}>
              <label className="sr-only" htmlFor="manifold-input">Message the local manifold demo</label>
              <input id="manifold-input" value={chatText} onChange={(event) => setChatText(event.target.value)} maxLength={500} placeholder="Try a spatial query or agent command…" />
              <button type="submit" className="dispatch-button">TRANSMIT</button>
            </form>
          </section>
        </div>
      </div>
    </section>
  );
}
