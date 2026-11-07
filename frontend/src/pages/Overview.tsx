import { Link } from "react-router-dom";
import { ArrowRight, Ban, Cpu, Database, FlaskConical, ShieldCheck, Siren, Zap } from "lucide-react";
import { api, DEFENSE_LABEL, fmtTime, pct, type MetricRow } from "../api";
import { Card, Empty, ErrorNote, MockBadge, PageHeader, Progress, Spinner, Stat, StatusBadge, useAsync } from "../components/ui";
import { DefenseBars } from "../components/charts";
import { groupData } from "../components/analysis";

function LatestBlock({ scope, metrics, exp }: { scope: "real" | "mock"; metrics: MetricRow[]; exp: { id: string; name: string } | null }) {
  if (!exp)
    return (
      <Empty title={scope === "real" ? "No real-LLM experiments yet" : "No mock experiments yet"} icon={scope === "real" ? <Cpu /> : <FlaskConical />}>
        {scope === "real"
          ? "Configure an API key or Ollama in backend/.env, then run an experiment. Nothing is shown here until real results exist."
          : "Run a mock experiment to exercise the pipeline end-to-end."}
      </Empty>
    );
  const models = [...new Set(metrics.map((m) => m.model))];
  const first = metrics.filter((m) => m.model === models[0]);
  const data = groupData(first, [
    { label: "Model-level ASR", pick: (m) => m.attack.asr_model },
    { label: "System-level ASR", pick: (m) => m.attack.asr_system },
    { label: "Modified accuracy", pick: (m) => m.modified.accuracy },
  ]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <Link to={`/experiments/${exp.id}`} className="font-medium text-ink hover:text-accent">{exp.name}</Link>
        <span className="font-mono text-xs text-muted">{models[0]}{models.length > 1 ? ` (+${models.length - 1} more)` : ""}</span>
      </div>
      <DefenseBars data={data} defenses={first.map((m) => m.defense)} height={230} />
    </div>
  );
}

export default function Overview() {
  const { data, error, loading } = useAsync(() => api.overview(), []);
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote error={`Cannot reach the API: ${error}. Is the backend running on :8000?`} />;
  if (!data) return null;
  const c = data.counts;
  return (
    <>
      <PageHeader
        title="Overview"
        description="Measure how untrusted text in security logs steers an LLM SOC assistant, and how much each defense layer helps. Simulated (mock) and real-LLM results are always kept and labelled separately."
        action={<Link to="/experiments" className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-[#04202a] hover:bg-[#5ee3f5]">New experiment <ArrowRight size={15} /></Link>}
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Eval cases" value={c.cases} hint="clean + modified pairs" icon={<Database size={15} />} tone="accent" />
        <Stat label="Experiments" value={c.experiments} icon={<FlaskConical size={15} />} />
        <Stat label="Real-LLM runs" value={c.runs_real.toLocaleString()} icon={<Cpu size={15} />} tone="accent" />
        <Stat label="Mock runs" value={c.runs_mock.toLocaleString()} hint="simulated" icon={<FlaskConical size={15} />} />
        <Stat label="Tripwire events" value={c.tripwire_events.toLocaleString()} icon={<Siren size={15} />} tone="crit" />
        <Stat label="Denied tool calls" value={c.denied_tool_requests.toLocaleString()} hint="blocked by app policy" icon={<Ban size={15} />} />
        <Stat label="External actions" value={c.executed_external_actions} hint="always 0 by design" icon={<ShieldCheck size={15} />} tone="good" />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2">Latest real-LLM experiment <MockBadge isMock={false} /></span>}
          subtitle="Attack success and accuracy per defense (first model).">
          <LatestBlock scope="real" metrics={data.latest.real.metrics} exp={data.latest.real.experiment} />
        </Card>
        <Card title={<span className="flex items-center gap-2">Latest mock experiment <MockBadge isMock /></span>}
          subtitle="Scripted simulator. These bars only show the simulator's built-in constants, not findings.">
          <LatestBlock scope="mock" metrics={data.latest.mock.metrics} exp={data.latest.mock.experiment} />
        </Card>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Card title="Recent experiments" className="xl:col-span-2" action={<Link to="/experiments" className="text-xs text-accent hover:underline">View all</Link>}>
          {data.recent_experiments.length === 0 ? (
            <Empty title="No experiments yet">Start with a quick mock run from the Experiments page.</Empty>
          ) : (
            <ul className="divide-y divide-line">
              {data.recent_experiments.map((e) => (
                <li key={e.id} className="flex flex-wrap items-center gap-3 py-3">
                  <div className="min-w-0 flex-1">
                    <Link to={`/experiments/${e.id}`} className="text-sm font-medium text-ink hover:text-accent">{e.name}</Link>
                    <div className="text-xs text-muted">
                      {e.config.models.join(", ")} · {e.config.defenses.map((d) => DEFENSE_LABEL[d] ?? d).join(", ")} · {fmtTime(e.created_at)}
                    </div>
                  </div>
                  <MockBadge isMock={e.is_mock} />
                  <StatusBadge status={e.status} />
                  <div className="w-full sm:w-40">
                    <Progress value={e.progress} />
                    <div className="mt-1 text-right text-[11px] tabular-nums text-muted">{e.completed_runs}/{e.total_runs} · {pct(e.progress, 0)}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="How an evaluation works">
          <ol className="space-y-3 text-sm text-ink-2">
            {[
              ["Synthetic case", "A labelled nginx, SSH, DNS or IDS event, plus a copy with one fixed benchmark string placed in an attacker-controllable field."],
              ["Defense prompt", "Baseline, guardrails, field isolation, or combined with a secret canary."],
              ["Model analysis", "Structured JSON: verdict, severity, indicators, actions, tool requests."],
              ["App enforcement", "Tool permissions checked in code. Denied requests are logged, never executed."],
              ["Scoring", "Compared with ground truth and the attack objective, clean vs modified under identical settings."],
            ].map(([t, d], i) => (
              <li key={t} className="flex gap-3">
                <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-accent/40 text-xs text-accent">{i + 1}</span>
                <span><b className="text-ink">{t}.</b> {d}</span>
              </li>
            ))}
          </ol>
          <Link to="/playground" className="mt-4 inline-flex items-center gap-1 text-sm text-accent hover:underline"><Zap size={14} /> Try one in the playground</Link>
        </Card>
      </div>
    </>
  );
}
