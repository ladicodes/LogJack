import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { BarChart3, ChevronLeft, ChevronRight, Download, Pause, RotateCcw } from "lucide-react";
import { api, ATTACK_LABEL, DEFENSE_LABEL, fmtTime, pct, type Experiment } from "../api";
import { Badge, Button, Card, ErrorNote, MockBadge, PageHeader, Progress, Select, Spinner, StatusBadge, VerdictBadge, useAsync } from "../components/ui";
import { ResultModal } from "../components/analysis";
import { MetricsTable } from "./Defenses";

const PAGE = 50;

export default function ExperimentDetail() {
  const { id = "" } = useParams();
  const exp = useAsync(() => api.experiment(id), [id]);
  const metrics = useAsync(() => api.metrics(id), [id]);
  const [err, setErr] = useState<string | null>(null);
  const e = exp.data;
  const active = e && ["running", "pausing"].includes(e.status);

  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => {
      api.experiment(id).then(exp.setData).catch(() => undefined);
      api.metrics(id).then(metrics.setData).catch(() => undefined);
    }, 1200);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, id]);

  // one final refresh when a run finishes
  const [prevActive, setPrevActive] = useState(false);
  useEffect(() => {
    if (prevActive && !active) metrics.reload();
    setPrevActive(!!active);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  if (exp.loading && !e) return <Spinner />;
  if (exp.error) return <ErrorNote error={exp.error} />;
  if (!e) return null;

  const act = async (fn: () => Promise<Experiment>) => { setErr(null); try { exp.setData(await fn()); } catch (x) { setErr((x as Error).message); } };

  return (
    <>
      <Link to="/experiments" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-ink"><ChevronLeft size={15} /> Experiments</Link>
      <PageHeader
        title={e.name}
        description={<span className="flex flex-wrap items-center gap-2"><MockBadge isMock={e.is_mock} /><StatusBadge status={e.status} /><span className="font-mono text-xs text-muted">{e.id}</span></span>}
        action={
          <div className="flex flex-wrap gap-2">
            {active && <Button onClick={() => act(() => api.pause(e.id))}><Pause size={14} /> Pause</Button>}
            {["paused", "interrupted", "pending", "completed_with_errors", "failed"].includes(e.status) && (
              <Button onClick={() => act(() => api.resume(e.id))}><RotateCcw size={14} /> {e.status === "pending" ? "Start" : "Resume"}</Button>
            )}
            <Link to={`/defenses?experiment=${e.id}`} className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-raised px-3 py-1.5 text-sm hover:border-accent/60"><BarChart3 size={15} /> Charts</Link>
            <ExportMenu id={e.id} />
          </div>
        }
      />
      <ErrorNote error={err} />
      {e.is_mock && (
        <div className="mb-6 rounded-lg border border-serious/40 bg-serious/10 px-4 py-3 text-sm text-[#ffc9b3]">
          <b>Simulated results.</b> This experiment used the deterministic mock provider. Its numbers come from scripted rules and constants and say nothing about real model behaviour.
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Progress" className="lg:col-span-2">
          <Progress value={e.progress} failed={e.total_runs ? e.failed_runs / e.total_runs : 0} />
          <div className="mt-3 grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
            <div><div className="text-xs text-muted">Completed</div><div className="text-lg font-semibold tabular-nums">{e.completed_runs.toLocaleString()}</div></div>
            <div><div className="text-xs text-muted">Planned</div><div className="text-lg font-semibold tabular-nums">{e.total_runs.toLocaleString()}</div></div>
            <div><div className="text-xs text-muted">Failed (retried on resume)</div><div className="text-lg font-semibold tabular-nums">{e.failed_runs}</div></div>
            <div><div className="text-xs text-muted">Progress</div><div className="text-lg font-semibold tabular-nums">{pct(e.progress, 1)}</div></div>
          </div>
          {e.error && <div className="mt-3"><ErrorNote error={e.error} /></div>}
        </Card>
        <Card title="Configuration">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs">
            <dt className="text-muted">Dataset</dt><dd className="font-mono">{e.config.dataset_id}</dd>
            <dt className="text-muted">Models</dt><dd className="font-mono">{e.config.models.join(", ")}</dd>
            <dt className="text-muted">Defenses</dt><dd>{e.config.defenses.map((d) => DEFENSE_LABEL[d]).join(", ")}</dd>
            <dt className="text-muted">Cases</dt><dd>{e.config.case_count} × {e.config.variants.join(" + ")}</dd>
            <dt className="text-muted">Temperature</dt><dd>{e.config.temperature}</dd>
            <dt className="text-muted">Max tokens</dt><dd>{e.config.max_tokens}</dd>
            <dt className="text-muted">Created</dt><dd>{fmtTime(e.created_at)}</dd>
            <dt className="text-muted">Finished</dt><dd>{fmtTime(e.finished_at)}</dd>
          </dl>
        </Card>
      </div>

      <div className="mt-6">
        <Card title="Metrics by model × defense" subtitle="Counts in parentheses. Hover any rate to see its 95% Wilson interval.">
          {metrics.data ? <MetricsTable rows={metrics.data.metrics} /> : <Spinner />}
        </Card>
      </div>
      <div className="mt-6"><ResultsTable exp={e} /></div>
    </>
  );
}

export function ExportMenu({ id }: { id: string }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {(["results", "metrics"] as const).flatMap((k) => (["csv", "json"] as const).map((f) => (
        <a key={k + f} href={api.exportUrl(id, k, f)}
          className="inline-flex items-center gap-1 rounded-lg border border-line-strong bg-raised px-2.5 py-1.5 text-xs hover:border-accent/60">
          <Download size={13} /> {k} .{f}
        </a>
      )))}
    </div>
  );
}

function ResultsTable({ exp }: { exp: Experiment }) {
  const [variant, setVariant] = useState("");
  const [model, setModel] = useState("");
  const [defense, setDefense] = useState("");
  const [attack, setAttack] = useState("");
  const [outcome, setOutcome] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const res = useAsync(() => api.results(exp.id, { variant, model, defense, attack_type: attack, outcome, offset, limit: PAGE }),
    [exp.id, variant, model, defense, attack, outcome, offset, exp.completed_runs]);
  const r = <T,>(fn: (v: T) => void) => (v: T) => { fn(v); setOffset(0); };
  return (
    <Card title="Individual results" subtitle="Click a row to see the prompt, raw model response, tool decisions and tripwire details.">
      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Select value={variant} onChange={r(setVariant)} options={[{ value: "", label: "All variants" }, { value: "clean", label: "clean" }, { value: "modified", label: "modified" }]} />
        <Select value={model} onChange={r(setModel)} options={[{ value: "", label: "All models" }, ...exp.config.models.map((m) => ({ value: m, label: m }))]} />
        <Select value={defense} onChange={r(setDefense)} options={[{ value: "", label: "All defenses" }, ...exp.config.defenses.map((d) => ({ value: d, label: DEFENSE_LABEL[d] }))]} />
        <Select value={attack} onChange={r(setAttack)} options={[{ value: "", label: "All attack types" }, ...Object.entries(ATTACK_LABEL).map(([v, l]) => ({ value: v, label: l }))]} />
        <Select value={outcome} onChange={r(setOutcome)} options={[{ value: "", label: "Any outcome" }, { value: "attack_success", label: "Attack succeeded (system)" },
          { value: "attack_blocked", label: "Attack blocked (system)" }, { value: "incorrect", label: "Incorrect verdict" }, { value: "tripwire", label: "Tripwire fired" }, { value: "error", label: "Errors" }]} />
      </div>
      <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[960px] text-sm">
          <thead>
            <tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
              <th className="py-2 pr-3">Case</th><th className="pr-3">Variant</th><th className="pr-3">Model</th><th className="pr-3">Defense</th><th className="pr-3">Truth</th>
              <th className="pr-3">Final verdict</th><th className="pr-3">Attack</th><th className="pr-3">Model-level</th><th className="pr-3">System</th><th className="pr-3">Tripwire</th><th className="pr-3 text-right">Latency</th>
            </tr>
          </thead>
          <tbody>
            {res.data?.items.map((x) => (
              <tr key={x.id} className="cursor-pointer border-b border-line/60 hover:bg-raised/50" onClick={() => setOpen(x.id)}>
                <td className="whitespace-nowrap py-2 pr-3 font-mono text-xs text-accent">{x.case_id}</td>
                <td className="pr-3 text-ink-2">{x.variant}</td>
                <td className="pr-3 font-mono text-xs">{x.model}</td>
                <td className="pr-3 text-ink-2">{DEFENSE_LABEL[x.defense]}</td>
                <td className="pr-3"><VerdictBadge verdict={x.label} /></td>
                <td className="pr-3">{x.error ? <Badge tone="crit">error</Badge> : <VerdictBadge verdict={x.verdict_final} />}</td>
                <td className="pr-3 text-xs text-ink-2">{x.attack_type ? ATTACK_LABEL[x.attack_type] : "—"}</td>
                <td className="pr-3">{x.attack_success_raw === null ? <span className="text-muted">—</span> : x.attack_success_raw ? <Badge tone="crit">success</Badge> : <Badge tone="good">failed</Badge>}</td>
                <td className="pr-3">{x.attack_success_final === null ? <span className="text-muted">—</span> : x.attack_success_final ? <Badge tone="crit">success</Badge> : <Badge tone="good">blocked</Badge>}</td>
                <td className="pr-3">{x.tripwire_fired ? <Badge tone="crit">fired</Badge> : <span className="text-muted">—</span>}</td>
                <td className="pr-3 text-right tabular-nums text-ink-2">{x.latency_ms !== null ? `${x.latency_ms.toFixed(0)} ms` : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {res.loading && !res.data && <Spinner />}
      {res.data && (
        <div className="mt-4 flex items-center justify-between text-sm text-muted">
          <span>{res.data.total === 0 ? "No results" : `${offset + 1}–${Math.min(offset + PAGE, res.data.total)} of ${res.data.total.toLocaleString()}`}</span>
          <div className="flex gap-2">
            <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} aria-label="Previous page"><ChevronLeft size={15} /></Button>
            <Button disabled={offset + PAGE >= res.data.total} onClick={() => setOffset(offset + PAGE)} aria-label="Next page"><ChevronRight size={15} /></Button>
          </div>
        </div>
      )}
      <ResultModal id={open} onClose={() => setOpen(null)} />
    </Card>
  );
}
