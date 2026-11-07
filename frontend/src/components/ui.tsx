import { useEffect, useState, type ReactNode } from "react";
import { AlertOctagon, AlertTriangle, CheckCircle2, FlaskConical, HelpCircle, Loader2, X, Cpu } from "lucide-react";
import type { Verdict } from "../api";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

export function Card({ title, subtitle, action, children, className }: {
  title?: ReactNode; subtitle?: ReactNode; action?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-card/90 shadow-[0_1px_0_0_rgba(255,255,255,0.03)_inset]", className)}>
      {(title || action) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-3.5">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold tracking-wide text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink sm:text-2xl">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-ink-2">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Stat({ label, value, hint, icon, tone }: {
  label: string; value: ReactNode; hint?: ReactNode; icon?: ReactNode; tone?: "accent" | "good" | "crit";
}) {
  return (
    <div className="rounded-xl border border-line bg-card/90 p-4">
      <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wider text-muted">
        <span>{label}</span>
        <span className={cx(tone === "accent" && "text-accent", tone === "good" && "text-good", tone === "crit" && "text-crit")}>{icon}</span>
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums text-ink">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

const VERDICT: Record<string, { cls: string; icon: ReactNode; label: string }> = {
  benign: { cls: "border-good/40 bg-good/10 text-[#7ee07e]", icon: <CheckCircle2 size={13} />, label: "Benign" },
  suspicious: { cls: "border-warn/40 bg-warn/10 text-[#ffd77a]", icon: <AlertTriangle size={13} />, label: "Suspicious" },
  malicious: { cls: "border-crit/50 bg-crit/15 text-[#ff9a9a]", icon: <AlertOctagon size={13} />, label: "Malicious" },
};

export function VerdictBadge({ verdict }: { verdict: Verdict | string | null | undefined }) {
  const v = verdict ? VERDICT[verdict] : undefined;
  if (!v)
    return (
      <span className="inline-flex items-center gap-1 rounded-md border border-line-strong px-2 py-0.5 text-xs text-muted">
        <HelpCircle size={13} /> {verdict || "unparsed"}
      </span>
    );
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium", v.cls)}>
      {v.icon}
      {v.label}
    </span>
  );
}

export function Badge({ children, tone = "neutral", title }: {
  children: ReactNode; tone?: "neutral" | "accent" | "good" | "warn" | "crit" | "serious"; title?: string;
}) {
  const cls = {
    neutral: "border-line-strong bg-raised text-ink-2",
    accent: "border-accent/40 bg-accent/10 text-accent",
    good: "border-good/40 bg-good/10 text-[#7ee07e]",
    warn: "border-warn/40 bg-warn/10 text-[#ffd77a]",
    serious: "border-serious/40 bg-serious/10 text-[#ffb999]",
    crit: "border-crit/50 bg-crit/15 text-[#ff9a9a]",
  }[tone];
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-2 py-0.5 text-xs", cls)}>
      {children}
    </span>
  );
}

export function MockBadge({ isMock }: { isMock: boolean | number }) {
  return isMock ? (
    <Badge tone="serious" title="Produced by the deterministic mock provider. Not real model behaviour.">
      <FlaskConical size={12} /> SIMULATED
    </Badge>
  ) : (
    <Badge tone="accent" title="Produced by a real LLM API or local model.">
      <Cpu size={12} /> REAL LLM
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "completed" ? "good" : status === "running" || status === "pausing" ? "accent" : status === "failed" ? "crit"
      : status === "completed_with_errors" || status === "interrupted" ? "warn" : "neutral";
  return (
    <Badge tone={tone}>
      {(status === "running" || status === "pausing") && <Loader2 size={12} className="animate-spin" />}
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

export function Button({ children, variant = "secondary", className, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  const cls = {
    primary: "bg-accent text-[#04202a] hover:bg-[#5ee3f5] font-semibold",
    secondary: "border border-line-strong bg-raised text-ink hover:border-accent/60",
    ghost: "text-ink-2 hover:bg-raised hover:text-ink",
    danger: "border border-crit/40 text-[#ff9a9a] hover:bg-crit/15",
  }[variant];
  return (
    <button
      {...rest}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        cls,
        className,
      )}
    >
      {children}
    </button>
  );
}

export const inputCls =
  "w-full rounded-lg border border-line-strong bg-panel px-3 py-2 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-muted">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export function Select({ value, onChange, options, className }: {
  value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; className?: string;
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className={cx(inputCls, "pr-8", className)}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function Progress({ value, failed = 0 }: { value: number; failed?: number }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-raised" role="progressbar" aria-valuenow={Math.round(value * 100)}>
      <div className="flex h-full">
        <div className="h-full bg-accent transition-all duration-500" style={{ width: `${Math.min(100, value * 100)}%` }} />
        {failed > 0 && <div className="h-full bg-crit" style={{ width: `${Math.min(100, failed * 100)}%` }} />}
      </div>
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-muted">
      <Loader2 className="animate-spin" size={16} /> {label}
    </div>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-line-strong px-6 py-10 text-center">
      {icon && <div className="mb-3 text-muted">{icon}</div>}
      <div className="text-sm font-medium text-ink">{title}</div>
      {children && <div className="mt-1 max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return (
    <div className="flex items-start gap-2 rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-[#ffb3b3]">
      <AlertOctagon size={16} className="mt-0.5 shrink-0" />
      <span className="break-words">{error}</span>
    </div>
  );
}

export function Pre({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <pre className={cx("scroll-thin max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-panel p-3 font-mono text-xs leading-relaxed text-ink-2", className)}>
      {children}
    </pre>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: { id: string; label: string }[]; active: string; onChange: (id: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1 rounded-lg border border-line bg-panel p-1" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={active === t.id}
          onClick={() => onChange(t.id)}
          className={cx("rounded-md px-3 py-1 text-xs font-medium transition-colors",
            active === t.id ? "bg-raised text-ink shadow" : "text-muted hover:text-ink")}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 backdrop-blur-sm sm:p-8" onClick={onClose}>
      <div
        className={cx("relative w-full rounded-xl border border-line-strong bg-card shadow-2xl", wide ? "max-w-6xl" : "max-w-3xl")}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <div className="min-w-0 text-sm font-semibold">{title}</div>
          <button onClick={onClose} className="rounded p-1 text-muted hover:bg-raised hover:text-ink" aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    fn()
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e: Error) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1), setData };
}

export function Chip({ children, mono = true }: { children: ReactNode; mono?: boolean }) {
  return (
    <span className={cx("inline-block max-w-full truncate rounded border border-line-strong bg-panel px-1.5 py-0.5 text-xs text-ink-2", mono && "font-mono")}>
      {children}
    </span>
  );
}

export function Check({ checked, onChange, label, disabled, hint }: {
  checked: boolean; onChange: (v: boolean) => void; label: ReactNode; disabled?: boolean; hint?: ReactNode;
}) {
  return (
    <label className={cx("flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 text-sm transition-colors",
      checked ? "border-accent/50 bg-accent/5" : "border-line hover:border-line-strong", disabled && "cursor-not-allowed opacity-50")}>
      <input type="checkbox" className="mt-0.5 accent-[#22d3ee]" checked={checked} disabled={disabled}
        onChange={(e) => onChange(e.target.checked)} />
      <span className="min-w-0">
        <span className="block text-ink">{label}</span>
        {hint && <span className="block text-xs text-muted">{hint}</span>}
      </span>
    </label>
  );
}
