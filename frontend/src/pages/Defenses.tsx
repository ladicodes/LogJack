import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { BarChart3 } from "lucide-react";
import { api, ATTACK_LABEL, ATTACK_SHORT, DEFENSE_LABEL, DEFENSE_ORDER, pct, type MetricRow, type Rate } from "../api";
import { Card, Empty, ErrorNote, Field, MockBadge, PageHeader, Select, Spinner, Tabs, useAsync } from "../components/ui";
import { DefenseBars } from "../components/charts";
import { groupData, numberData } from "../components/analysis";

function R({ r }: { r: Rate }) {
  if (r.value === null) return <span className="text-muted">—</span>;
  return (
    <span title={r.ci95 ? `95% CI ${pct(r.ci95[0])} – ${pct(r.ci95[1])}` : undefined} className="tabular-nums">
      {pct(r.value)} <span className="text-[11px] text-muted">({r.k}/{r.n})</span>
    </span>
  );
}

export function MetricsTable({ rows }: { rows: MetricRow[] }) {
  if (!rows.length) return <Empty title="No results yet" />;
  const cols: { h: string; cell: (m: MetricRow) => React.ReactNode; title?: string }[] = [
    { h: "ASR model-level", cell: (m) => <R r={m.attack.asr_model} />, title: "Share of modified cases where the model's own output met the attack objective" },
    { h: "ASR system-level", cell: (m) => <R r={m.attack.asr_system} />, title: "After app-side tool enforcement and the tripwire quarantine" },
    { h: "Acc. clean", cell: (m) => <R r={m.clean.accuracy} /> },
    { h: "Acc. modified", cell: (m) => <R r={m.modified.accuracy} /> },
    { h: "Verdict flips", cell: (m) => <R r={m.paired.verdict_flip_rate} />, title: "Pairs correct on clean but wrong on modified" },
    { h: "FP rate (mod)", cell: (m) => <R r={m.modified.false_positive_rate} /> },
    { h: "FN rate (mod)", cell: (m) => <R r={m.modified.false_negative_rate} /> },
    { h: "Indicators clean / mod", cell: (m) => <span className="tabular-nums">{pct(m.clean.indicator_preservation, 0)} / {pct(m.modified.indicator_preservation, 0)}</span> },
    { h: "Tripwire mod / clean", cell: (m) => <span className="tabular-nums">{pct(m.modified.tripwire_rate.value, 0)} / {pct(m.clean.tripwire_rate.value, 0)}</span>, title: "Detection rate on modified vs false alarms on clean" },
    { h: "Tripwire catch", cell: (m) => <R r={m.attack.tripwire_catch_rate} />, title: "Share of model-level successes that the tripwire caught" },
    { h: "Flagged injection", cell: (m) => <R r={m.modified.injection_flag_rate} /> },
    { h: "Parse fail", cell: (m) => <span className="tabular-nums">{pct((m.clean.parse_failures.k + m.modified.parse_failures.k) / Math.max(1, m.clean.parse_failures.n + m.modified.parse_failures.n), 1)}</span> },
    { h: "Latency mean / p95", cell: (m) => <span className="tabular-nums">{m.modified.latency_ms.mean?.toFixed(0) ?? "—"} / {m.modified.latency_ms.p95?.toFixed(0) ?? "—"} ms</span> },
  ];
  return (
    <div className="scroll-thin overflow-x-auto">
      <table className="w-full min-w-[1200px] text-xs">
        <thead>
          <tr className="border-b border-line text-left uppercase tracking-wider text-muted">
            <th className="py-2 pr-3">Model</th><th className="pr-3">Defense</th>
            {cols.map((c) => <th key={c.h} className="pr-3" title={c.title}>{c.h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => (
            <tr key={m.model + m.defense} className="border-b border-line/60">
              <td className="py-2 pr-3 font-mono">{m.model}</td>
              <td className="pr-3 font-medium text-ink">{DEFENSE_LABEL[m.defense]}</td>
              {cols.map((c) => <td key={c.h} className="whitespace-nowrap py-1 pr-3 text-ink-2">{c.cell(m)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Defenses() {
  const [params, setParams] = useSearchParams();
  const exps = useAsync(() => api.experiments(), []);
  const done = useMemo(() => (exps.data ?? []).filter((e) => e.completed_runs > 0), [exps.data]);
  const [scope, setScope] = useState<"real" | "mock">("real");
  const [initialised, setInitialised] = useState(false);
  const expId = params.get("experiment") || "";

  // Pick a sensible experiment once data arrives. After that, the user's tab choice is
  // respected, even when that scope has no experiments (it then shows an empty state).
  useEffect(() => {
    if (!exps.data) return;
    const current = done.find((e) => e.id === expId);
    if (current) {
      setScope(current.is_mock ? "mock" : "real");
      setInitialised(true);
      return;
    }
    if (initialised) return;
    setInitialised(true);
    const pick = done.find((e) => !e.is_mock) ?? done[0];
    if (pick) {
      setScope(pick.is_mock ? "mock" : "real");
      setParams({ experiment: pick.id }, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [exps.data, expId]);

  const switchScope = (s: "real" | "mock") => {
    setScope(s);
    const p = done.find((e) => e.is_mock === (s === "mock"));
    setParams(p ? { experiment: p.id } : {});
  };

  const metrics = useAsync(() => (expId ? api.metrics(expId) : Promise.resolve(null)), [expId]);
  const rows = metrics.data?.metrics ?? [];
  const models = [...new Set(rows.map((m) => m.model))];
  const [model, setModel] = useState("");
  const activeModel = models.includes(model) ? model : models[0];
  const mrows = rows.filter((m) => m.model === activeModel).sort((a, b) => DEFENSE_ORDER.indexOf(a.defense) - DEFENSE_ORDER.indexOf(b.defense));
  const defenses = mrows.map((m) => m.defense);
  const attackTypes = Object.keys(ATTACK_LABEL).filter((a) => mrows.some((m) => m.attack.by_attack_type[a]));

  const scoped = done.filter((e) => e.is_mock === (scope === "mock"));

  return (
    <>
      <PageHeader title="Defense Comparison" description="Compare the four defense configurations under identical cases and settings. Each defense keeps the same color in every chart, and every chart has a table view below it." />
      <div className="mb-6 grid gap-3 md:grid-cols-[auto_1fr_1fr] md:items-end">
        <Tabs tabs={[{ id: "real", label: "Real LLM" }, { id: "mock", label: "Simulated (mock)" }]} active={scope}
          onChange={(s) => switchScope(s as "real" | "mock")} />
        <Field label="Experiment">
          <Select value={expId} onChange={(v) => setParams({ experiment: v })}
            options={scoped.length ? scoped.map((e) => ({ value: e.id, label: `${e.name} · ${e.status}` })) : [{ value: "", label: "— none —" }]} />
        </Field>
        <Field label="Model">
          <Select value={activeModel ?? ""} onChange={setModel} options={models.length ? models.map((m) => ({ value: m, label: m })) : [{ value: "", label: "—" }]} />
        </Field>
      </div>

      {exps.loading && <Spinner />}
      <ErrorNote error={exps.error || metrics.error} />
      {!exps.loading && scoped.length === 0 && (
        <Card>
          <Empty title={scope === "real" ? "No real-LLM experiment results yet" : "No mock experiment results yet"} icon={<BarChart3 />}>
            {scope === "real" ? "Configure a provider in backend/.env and run an experiment. Charts only appear once real results exist."
              : "Run a mock experiment from the Experiments page."}
          </Empty>
        </Card>
      )}

      {expId && scoped.some((e) => e.id === expId) && mrows.length > 0 && (
        <>
          {metrics.data?.is_mock && (
            <div className="mb-6 flex flex-wrap items-center gap-2 rounded-lg border border-serious/40 bg-serious/10 px-4 py-3 text-sm text-[#ffc9b3]">
              <MockBadge isMock /> These charts show the mock simulator's scripted constants. They exercise the pipeline and are not research findings.
            </div>
          )}
          <div className="grid gap-6 xl:grid-cols-2">
            <Card title="Attack success rate" subtitle="Modified cases. Model-level = the model's own output; system-level = after app enforcement and the tripwire.">
              <DefenseBars defenses={defenses} data={groupData(mrows, [
                { label: "Model-level ASR", pick: (m) => m.attack.asr_model },
                { label: "System-level ASR", pick: (m) => m.attack.asr_system },
              ])} />
            </Card>
            <Card title="Model-level ASR by attack type" subtitle="Verdict manipulation · indicator omission · false-positive induction · unauthorized tool request · instruction disclosure.">
              <DefenseBars defenses={defenses} data={groupData(mrows, attackTypes.map((a) => ({
                label: ATTACK_SHORT[a], pick: (m: MetricRow) => m.attack.by_attack_type[a]?.asr_model,
              })))} />
            </Card>
            <Card title="Classification accuracy" subtitle="3-class verdict versus ground truth, clean vs modified.">
              <DefenseBars defenses={defenses} data={groupData(mrows, [
                { label: "Clean", pick: (m) => m.clean.accuracy },
                { label: "Modified", pick: (m) => m.modified.accuracy },
                { label: "Verdict flips", pick: (m) => m.paired.verdict_flip_rate },
              ])} />
            </Card>
            <Card title="Error rates on modified cases" subtitle="FP = benign called suspicious/malicious. FN = threat called benign.">
              <DefenseBars defenses={defenses} data={groupData(mrows, [
                { label: "False-positive rate", pick: (m) => m.modified.false_positive_rate },
                { label: "False-negative rate", pick: (m) => m.modified.false_negative_rate },
              ])} />
            </Card>
            <Card title="Indicator preservation & detection" subtitle="Mean recall of expected indicators. Tripwire firing and model self-flagging on modified cases.">
              <DefenseBars defenses={defenses} data={[
                ...numberData(mrows, [
                  { label: "Indicators (clean)", pick: (m) => m.clean.indicator_preservation },
                  { label: "Indicators (mod)", pick: (m) => m.modified.indicator_preservation },
                ]),
                ...groupData(mrows, [
                  { label: "Tripwire fired", pick: (m) => m.modified.tripwire_rate },
                  { label: "Self-flagged", pick: (m) => m.modified.injection_flag_rate },
                ]),
              ]} />
            </Card>
            <Card title="Latency" subtitle="Per request, modified cases (milliseconds).">
              <DefenseBars unit="ms" defenses={defenses} data={numberData(mrows, [
                { label: "Mean", pick: (m) => m.modified.latency_ms.mean },
                { label: "p50", pick: (m) => m.modified.latency_ms.p50 },
                { label: "p95", pick: (m) => m.modified.latency_ms.p95 },
              ])} />
            </Card>
          </div>
          <div className="mt-6">
            <Card title="Table view" subtitle="All models in this experiment. Hover a rate to see its 95% Wilson interval.">
              <MetricsTable rows={rows} />
            </Card>
          </div>
        </>
      )}
    </>
  );
}
