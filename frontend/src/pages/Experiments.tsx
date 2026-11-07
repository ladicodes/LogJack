import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Pause, Play, Plus, RotateCcw, Trash2, Eye } from "lucide-react";
import { api, ATTACK_LABEL, DEFENSE_LABEL, DEFENSE_ORDER, fmtTime, pct, type Experiment } from "../api";
import { Badge, Button, Card, Check, Empty, ErrorNote, Field, MockBadge, PageHeader, Progress, Select, Spinner, StatusBadge, inputCls, useAsync } from "../components/ui";

const ACTIVE = ["running", "pausing"];

export function usePolledExperiments() {
  const state = useAsync(() => api.experiments(), []);
  const anyActive = state.data?.some((e) => ACTIVE.includes(e.status));
  useEffect(() => {
    if (!anyActive) return;
    const t = setInterval(() => api.experiments().then(state.setData).catch(() => undefined), 1000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anyActive]);
  return state;
}

export default function Experiments() {
  const list = usePolledExperiments();
  const [showForm, setShowForm] = useState(true);
  return (
    <>
      <PageHeader
        title="Experiments"
        description="Run every selected case under each model × defense, for the clean and modified versions with identical settings. Each result is saved as soon as it completes, so an interrupted run can be resumed without repeating finished work."
        action={<Button onClick={() => setShowForm((s) => !s)}><Plus size={15} /> {showForm ? "Hide form" : "New experiment"}</Button>}
      />
      {showForm && <NewExperiment onCreated={() => list.reload()} />}
      <div className="mt-6">
        <Card title="All experiments" subtitle="Mock and real-LLM experiments are kept separate and labelled.">
          {list.loading && !list.data && <Spinner />}
          <ErrorNote error={list.error} />
          {list.data?.length === 0 && <Empty title="No experiments yet">Use the form above to start one. A mock run finishes in seconds.</Empty>}
          <ul className="space-y-3">
            {list.data?.map((e) => <ExperimentRow key={e.id} e={e} onChange={() => list.reload()} />)}
          </ul>
        </Card>
      </div>
    </>
  );
}

function ExperimentRow({ e, onChange }: { e: Experiment; onChange: () => void }) {
  const [err, setErr] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => { setErr(null); try { await fn(); onChange(); } catch (x) { setErr((x as Error).message); } };
  const canResume = ["paused", "interrupted", "pending", "completed_with_errors", "failed"].includes(e.status);
  return (
    <li className="rounded-lg border border-line bg-panel/60 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <Link to={`/experiments/${e.id}`} className="font-medium text-ink hover:text-accent">{e.name}</Link>
          <div className="mt-0.5 text-xs text-muted">
            <span className="font-mono">{e.id}</span> · {e.config.models.join(", ")} · {e.config.defenses.map((d) => DEFENSE_LABEL[d] ?? d).join(", ")} · {e.config.case_count} cases × {e.config.variants.join("+")} · {fmtTime(e.created_at)}
          </div>
        </div>
        <MockBadge isMock={e.is_mock} />
        <StatusBadge status={e.status} />
        <div className="flex gap-1.5">
          {ACTIVE.includes(e.status) && <Button onClick={() => act(() => api.pause(e.id))} title="Pause"><Pause size={14} /> Pause</Button>}
          {canResume && (
            <Button onClick={() => act(() => api.resume(e.id))} title={e.status === "pending" ? "Start" : "Resume"}>
              {e.status === "pending" ? <Play size={14} /> : <RotateCcw size={14} />} {e.status === "pending" ? "Start" : "Resume"}
            </Button>
          )}
          <Link to={`/experiments/${e.id}`} className="inline-flex items-center gap-1 rounded-lg border border-line-strong bg-raised px-3 py-1.5 text-sm hover:border-accent/60"><Eye size={14} /> View</Link>
          <Button variant="danger" title="Delete" aria-label="Delete experiment"
            onClick={() => window.confirm(`Delete "${e.name}" and all its results?`) && act(() => api.remove(e.id))}><Trash2 size={14} /></Button>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <Progress value={e.progress} failed={e.total_runs ? e.failed_runs / e.total_runs : 0} />
        <span className="w-44 shrink-0 text-right text-xs tabular-nums text-muted">
          {e.completed_runs.toLocaleString()}/{e.total_runs.toLocaleString()} ({pct(e.progress, 0)}){e.failed_runs ? ` · ${e.failed_runs} failed` : ""}
        </span>
      </div>
      {e.error && <div className="mt-2"><ErrorNote error={e.error} /></div>}
      <ErrorNote error={err} />
    </li>
  );
}

function NewExperiment({ onCreated }: { onCreated: () => void }) {
  const navigate = useNavigate();
  const catalog = useAsync(() => api.models(), []);
  const datasets = useAsync(() => api.datasets(), []);
  const [name, setName] = useState("");
  const [datasetId, setDatasetId] = useState("logjack-v1");
  const [models, setModels] = useState<string[]>(["mock:naive", "mock:cautious"]);
  const [custom, setCustom] = useState("");
  const [defenses, setDefenses] = useState<string[]>([...DEFENSE_ORDER]);
  const [variants, setVariants] = useState<string[]>(["clean", "modified"]);
  const [attackTypes, setAttackTypes] = useState<string[]>([]);
  const [logTypes, setLogTypes] = useState<string[]>([]);
  const [limit, setLimit] = useState("");
  const [seed, setSeed] = useState("42");
  const [concurrency, setConcurrency] = useState("4");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const toggle = (arr: string[], set: (v: string[]) => void, v: string) => set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  const isMock = (m: string) => m.startsWith("mock:");
  const mixed = models.length > 0 && new Set(models.map(isMock)).size > 1;
  const caseCount = useMemo(() => {
    const ds = datasets.data?.find((d) => d.id === datasetId);
    const total = ds?.case_count ?? 200;
    return limit ? Math.min(Number(limit), total) : total;
  }, [datasets.data, datasetId, limit]);
  const runs = caseCount * variants.length * models.length * defenses.length;
  const filtered = attackTypes.length > 0 || logTypes.length > 0;

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const e = await api.createExperiment({
        name, dataset_id: datasetId, models, defenses, variants,
        attack_types: attackTypes.length ? attackTypes : null, log_types: logTypes.length ? logTypes : null,
        limit: limit ? Number(limit) : null, sample_seed: Number(seed) || 42, concurrency: Number(concurrency) || 4,
      });
      onCreated();
      navigate(`/experiments/${e.id}`);
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };

  return (
    <Card title="New experiment" subtitle="Temperature, max tokens and endpoints come from backend/.env and are saved with each experiment.">
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-4">
          <Field label="Name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Baseline vs combined, gpt-4o-mini" /></Field>
          <Field label="Dataset">
            <Select value={datasetId} onChange={setDatasetId}
              options={(datasets.data ?? [{ id: "logjack-v1", name: "LogJack synthetic v1", case_count: 200 }]).map((d) => ({ value: d.id, label: `${d.name} (${d.case_count})` }))} />
          </Field>
          <div className="grid grid-cols-3 gap-3">
            <Field label="Case limit" hint="blank = all"><input className={inputCls} inputMode="numeric" value={limit} onChange={(e) => setLimit(e.target.value.replace(/\D/g, ""))} placeholder="all" /></Field>
            <Field label="Sample seed"><input className={inputCls} inputMode="numeric" value={seed} onChange={(e) => setSeed(e.target.value.replace(/\D/g, ""))} /></Field>
            <Field label="Parallel"><input className={inputCls} inputMode="numeric" value={concurrency} onChange={(e) => setConcurrency(e.target.value.replace(/\D/g, ""))} /></Field>
          </div>
          <Field label="Variants">
            <div className="grid grid-cols-2 gap-2">
              {["clean", "modified"].map((v) => <Check key={v} label={v} checked={variants.includes(v)} onChange={() => toggle(variants, setVariants, v)} />)}
            </div>
          </Field>
        </div>

        <div className="space-y-4">
          <Field label="Models">
            <div className="space-y-3">
              {catalog.loading && <Spinner />}
              {catalog.data?.map((p) => (
                <div key={p.provider}>
                  <div className="mb-1.5 flex items-center gap-2 text-xs text-muted">
                    <span className="font-semibold uppercase tracking-wider text-ink-2">{p.provider}</span>
                    {p.is_mock ? <Badge tone="serious">simulated</Badge> : p.configured ? <Badge tone="good">configured</Badge> : <Badge>not configured</Badge>}
                  </div>
                  {p.models.length === 0 ? (
                    <p className="text-xs text-muted">{p.provider === "ollama" ? "Ollama not reachable or no models pulled." : "Set an API key in backend/.env to enable."}</p>
                  ) : (
                    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
                      {p.models.map((m) => (
                        <Check key={m} label={<span className="font-mono text-xs">{m}</span>} checked={models.includes(m)}
                          disabled={!p.configured && !p.is_mock} onChange={() => toggle(models, setModels, m)} />
                      ))}
                    </div>
                  )}
                </div>
              ))}
              <div className="flex gap-2">
                <input className={`${inputCls} font-mono text-xs`} value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="custom, e.g. ollama:qwen2.5:7b" />
                <Button onClick={() => { if (custom.includes(":") && !models.includes(custom)) setModels([...models, custom.trim()]); setCustom(""); }}>Add</Button>
              </div>
              {models.filter((m) => !catalog.data?.some((p) => p.models.includes(m))).map((m) => (
                <Check key={m} label={<span className="font-mono text-xs">{m}</span>} checked onChange={() => toggle(models, setModels, m)} />
              ))}
            </div>
          </Field>
          {mixed && <ErrorNote error="Mock and real models can't be mixed in one experiment, so simulated results stay separate from real LLM measurements. Create two experiments." />}
        </div>

        <div className="space-y-4">
          <Field label="Defense configurations">
            <div className="space-y-2">
              {DEFENSE_ORDER.map((d) => <Check key={d} label={DEFENSE_LABEL[d]} checked={defenses.includes(d)} onChange={() => toggle(defenses, setDefenses, d)} />)}
            </div>
          </Field>
          <details className="rounded-lg border border-line p-3 text-sm">
            <summary className="cursor-pointer text-ink-2">Filters (optional)</summary>
            <div className="mt-3 space-y-3">
              <div className="grid grid-cols-2 gap-2">
                {["nginx", "ssh", "dns", "ids"].map((t) => <Check key={t} label={t} checked={logTypes.includes(t)} onChange={() => toggle(logTypes, setLogTypes, t)} />)}
              </div>
              <div className="space-y-2">
                {Object.entries(ATTACK_LABEL).map(([k, l]) => <Check key={k} label={l} checked={attackTypes.includes(k)} onChange={() => toggle(attackTypes, setAttackTypes, k)} />)}
              </div>
            </div>
          </details>
          <div className="rounded-lg border border-line bg-panel p-3 text-sm">
            <div className="text-xs uppercase tracking-wider text-muted">Planned runs</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums">{filtered ? "≤ " : ""}{runs.toLocaleString()}</div>
            <div className="text-xs text-muted">{caseCount} cases × {variants.length} variants × {models.length} models × {defenses.length} defenses</div>
            {!models.every(isMock) && runs > 0 && <div className="mt-2 text-xs text-warn">Real-LLM runs call your configured API and may incur cost.</div>}
          </div>
          <Button variant="primary" className="w-full" disabled={busy || mixed || !models.length || !defenses.length || !variants.length} onClick={submit}>
            <Play size={15} /> Start experiment
          </Button>
          <ErrorNote error={err} />
        </div>
      </div>
    </Card>
  );
}
