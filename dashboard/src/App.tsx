import { useEffect, useState } from "react";
import { getToken, setToken, streamEvents } from "./lib/api";
import { Diagnostics, Devices, FloorPlan, Topology } from "./views/Spatial";
import { IncidentDetail, Incidents } from "./views/Incidents";
import { Network } from "./views/Network";
import { NodeDetail, Nodes, Settings } from "./views/Admin";
import { Overview } from "./views/Overview";

const NAV: Array<[string, string]> = [
  ["", "Overview"],
  ["network", "Network"],
  ["topology", "Topology"],
  ["floor", "Floor plan"],
  ["devices", "Devices"],
  ["nodes", "Nodes"],
  ["incidents", "Incidents"],
  ["diagnostics", "Diagnostics"],
  ["settings", "Settings"],
];

export function route(hash: string): { view: string; id?: string } {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  return { view: parts[0] ?? "", id: parts[1] ? decodeURIComponent(parts[1]) : undefined };
}

function useHash(): string {
  const [h, setH] = useState(window.location.hash);
  useEffect(() => {
    const f = () => setH(window.location.hash);
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  return h;
}

function Login({ onDone }: { onDone: () => void }) {
  const [t, setT] = useState("");
  return (
    <form
      className="login"
      onSubmit={(e) => {
        e.preventDefault();
        setToken(t.trim());
        onDone();
      }}
    >
      <h1>Home Observatory</h1>
      <label>
        API token (viewer or operator){" "}
        <input type="password" value={t} onChange={(e) => setT(e.target.value)} autoComplete="off" required />
      </label>
      <button type="submit">Sign in</button>
      <p className="muted">The token is kept in this tab only (sessionStorage) and sent as a Bearer header.</p>
    </form>
  );
}

function Live() {
  const [state, setState] = useState<"connecting" | "live" | "offline">("connecting");
  const [last, setLast] = useState<string | null>(null);
  useEffect(() => {
    const ac = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    const run = () => {
      setState("connecting");
      streamEvents((ev, data) => {
        setState("live");
        if (ev === "state") setLast(data.slice(0, 120));
      }, ac.signal).catch(() => {
        if (ac.signal.aborted) return;
        setState("offline");
        retry = setTimeout(run, 5000);
      });
    };
    run();
    return () => {
      ac.abort();
      if (retry) clearTimeout(retry);
    };
  }, []);
  return (
    <span className={`live ${state}`} title={last ?? ""}>
      {state === "live" ? "● live" : state === "connecting" ? "○ connecting" : "✖ stream offline (data may be stale)"}
    </span>
  );
}

export function App() {
  const hash = useHash();
  const [authed, setAuthed] = useState(!!getToken());
  if (!authed) return <Login onDone={() => setAuthed(true)} />;
  const { view, id } = route(hash);
  let body;
  switch (view) {
    case "network":
      body = <Network />;
      break;
    case "topology":
      body = <Topology />;
      break;
    case "floor":
      body = <FloorPlan />;
      break;
    case "devices":
      body = <Devices />;
      break;
    case "nodes":
      body = id ? <NodeDetail id={id} /> : <Nodes />;
      break;
    case "incidents":
      body = id ? <IncidentDetail id={id} /> : <Incidents />;
      break;
    case "diagnostics":
      body = <Diagnostics />;
      break;
    case "settings":
      body = <Settings />;
      break;
    default:
      body = <Overview />;
  }
  return (
    <>
      <header className="top">
        <strong>Home Observatory</strong>
        <nav aria-label="main">
          {NAV.map(([k, label]) => (
            <a key={k} href={`#/${k}`} aria-current={view === k ? "page" : undefined}>
              {label}
            </a>
          ))}
        </nav>
        <Live />
        <button
          onClick={() => {
            setToken(null);
            setAuthed(false);
          }}
        >
          Sign out
        </button>
      </header>
      <main>{body}</main>
    </>
  );
}
