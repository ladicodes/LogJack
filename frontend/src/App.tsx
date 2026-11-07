import { useEffect, useState } from "react";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { Activity, BarChart3, Database, FileText, FlaskConical, Gauge, Menu, Shield, Siren, Terminal, X } from "lucide-react";
import { cx } from "./components/ui";
import ErrorBoundary from "./components/ErrorBoundary";
import Overview from "./pages/Overview";
import Playground from "./pages/Playground";
import Datasets from "./pages/Datasets";
import Experiments from "./pages/Experiments";
import ExperimentDetail from "./pages/ExperimentDetail";
import Defenses from "./pages/Defenses";
import Tripwires from "./pages/Tripwires";
import Findings from "./pages/Findings";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/playground", label: "SOC Playground", icon: Terminal },
  { to: "/datasets", label: "Dataset Explorer", icon: Database },
  { to: "/experiments", label: "Experiments", icon: FlaskConical },
  { to: "/defenses", label: "Defense Comparison", icon: BarChart3 },
  { to: "/tripwires", label: "Tripwire Events", icon: Siren },
  { to: "/findings", label: "Findings & Exports", icon: FileText },
];

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="grid h-9 w-9 place-items-center rounded-lg border border-accent/40 bg-accent/10 text-accent">
          <Shield size={18} />
        </div>
        <div>
          <div className="text-base font-semibold tracking-tight">LogJack</div>
          <div className="text-[11px] uppercase tracking-widest text-muted">SOC · Injection Lab</div>
        </div>
      </div>
      <ul className="flex-1 space-y-0.5 px-3">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cx("flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  isActive ? "bg-raised text-ink shadow-[inset_2px_0_0_0_var(--color-accent)]" : "text-ink-2 hover:bg-raised/60 hover:text-ink")
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="m-3 rounded-lg border border-line bg-panel p-3 text-xs text-muted">
        <div className="mb-1 flex items-center gap-1.5 font-medium text-ink-2">
          <Activity size={13} className="text-good" /> Isolated simulation
        </div>
        Synthetic logs only. Tools are simulated; no external actions are ever executed.
      </div>
    </nav>
  );
}

export default function App() {
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  // Block body on purpose: newer Chrome returns a Promise from scrollTo(), and an effect
  // must return nothing or a cleanup function (returning the Promise crashed navigation).
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [loc.pathname]);

  return (
    <div className="relative z-10 flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-line bg-panel/80 backdrop-blur lg:block">
        <Sidebar />
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <aside className="absolute left-0 top-0 h-full w-72 border-r border-line bg-panel">
            <button className="absolute right-3 top-5 rounded p-1 text-muted hover:text-ink" onClick={() => setOpen(false)} aria-label="Close menu">
              <X size={18} />
            </button>
            <Sidebar onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-bg/80 px-4 py-3 backdrop-blur lg:hidden">
          <button onClick={() => setOpen(true)} className="rounded p-1.5 text-ink-2 hover:bg-raised" aria-label="Open menu">
            <Menu size={20} />
          </button>
          <Shield size={18} className="text-accent" />
          <span className="font-semibold">LogJack</span>
        </header>
        <main className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <ErrorBoundary resetKey={loc.pathname}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/playground" element={<Playground />} />
            <Route path="/datasets" element={<Datasets />} />
            <Route path="/experiments" element={<Experiments />} />
            <Route path="/experiments/:id" element={<ExperimentDetail />} />
            <Route path="/defenses" element={<Defenses />} />
            <Route path="/tripwires" element={<Tripwires />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="*" element={<div className="text-muted">Page not found.</div>} />
          </Routes>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
