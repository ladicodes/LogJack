import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { Columns3, Play, Shuffle, Timer } from "lucide-react";
import { api, ATTACK_LABEL, DEFENSE_LABEL, DEFENSE_ORDER, type AnalysisResult, type Case } from "../api";
import { Badge, Button, Card, Empty, ErrorNote, Field, MockBadge, PageHeader, Select, Spinner, VerdictBadge, inputCls, useAsync } from "../components/ui";
import { OutputSummary, RawTabs, ToolDecisions, TripwireBanner } from "../components/analysis";

const LOG_TYPES = [
  { value: "auto", label: "Auto-detect" },
  { value: "nginx", label: "Nginx access" },
  { value: "ssh", label: "SSH (auth.log)" },
  { value: "dns", label: "DNS query log" },
  { value: "ids", label: "IDS (Suricata EVE)" },
];

export default function Playground() {
  const loc = useLocation() as { state?: { caseId?: string; variant?: "clean" | "modified"; datasetId?: string } };
  const catalog = useAsync(() => api.models(), []);
  const [datasetId] = useState(loc.state?.datasetId || "logjack-v1");
  const caseList = useAsync(() => api.cases(datasetId, { limit: 500 }), [datasetId]);

  const [log, setLog] = useState("");
  const [logType, setLogType] = useState("auto");
  const [model, setModel] = useState("mock:naive");
  const [defense, setDefense] = useState("baseline");
  const [loaded, setLoaded] = useState<{ c: Case; variant: "clean" | "modified" } | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [compare, setCompare] = useState<AnalysisResult[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const models = useMemo(() => {
    const opts: { value: string; label: string }[] = [];
    catalog.data?.forEach((p) =>
      p.models.forEach((m) => opts.push({ value: m, label: `${m}${p.is_mock ? " (simulated)" : ""}${p.configured ? "" : " — not configured"}` })));
    return opts.length ? opts : [{ value: "mock:naive", label: "mock:naive (simulated)" }];
  }, [catalog.data]);

  const loadCase = (c: Case, variant: "clean" | "modified") => {
    setLoaded({ c, variant });
    setLog(c[variant].raw);
    setLogType(c.log_type);
    setResult(null);
    setCompare(null);
  };

  useEffect(() => {
    if (!caseList.data || !loc.state?.caseId) return;
    const c = caseList.data.items.find((x) => x.case_id === loc.state!.caseId);
    if (c) loadCase(c, loc.state.variant || "modified");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseList.data]);

  const body = (d: string) => ({
    log, log_type: logType, model, defense: d,
    ...(loaded && log === loaded.c[loaded.variant].raw ? { dataset_id: datasetId, case_id: loaded.c.case_id, variant: loaded.variant } : {}),
  });

  const run = async () => {
    setBusy(true); setError(null); setCompare(null);
    try { setResult(await api.analyze(body(defense))); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const runAll = async () => {
    setBusy(true); setError(null); setResult(null);
    try { setCompare(await Promise.all(DEFENSE_ORDER.map((d) => api.analyze(body(d))))); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const random = () => {
    const items = caseList.data?.items;
    if (items?.length) loadCase(items[Math.floor(Math.random() * items.length)], "modified");
  };

  const caseOpts = [{ value: "", label: "— paste your own log —" },
    ...(caseList.data?.items.map((c) => ({ value: c.case_id, label: `${c.case_id} · ${c.log_type} · ${c.label} · ${c.scenario}` })) ?? [])];

  return (
    <>
      <PageHeader title="SOC Playground" description="Analyze one log event with any model and defense. Load a dataset case to compare its clean and modified versions, or paste your own synthetic log." />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Card title="Input">
          <div className="space-y-4">
            <Field label="Dataset case">
              <div className="flex gap-2">
                <Select value={loaded?.c.case_id || ""} options={caseOpts} className="min-w-0 flex-1"
                  onChange={(id) => {
                    const c = caseList.data?.items.find((x) => x.case_id === id);
                    if (c) loadCase(c, loaded?.variant || "modified"); else { setLoaded(null); }
                  }} />
                <Button onClick={random} title="Random case" aria-label="Random case"><Shuffle size={15} /></Button>
              </div>
            </Field>
            {loaded && (
              <div className="rounded-lg border border-line bg-panel p-3 text-xs">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="text-muted">Ground truth</span> <VerdictBadge verdict={loaded.c.label} />
                  <Badge>{loaded.c.severity}</Badge>
                  <Badge tone="serious">{ATTACK_LABEL[loaded.c.modified.injection.attack_type]}</Badge>
                </div>
                <div className="flex gap-2">
                  {(["clean", "modified"] as const).map((v) => (
                    <Button key={v} variant={loaded.variant === v ? "primary" : "secondary"} className="text-xs" onClick={() => loadCase(loaded.c, v)}>
                      {v === "clean" ? "Clean log" : "Modified log"}
                    </Button>
                  ))}
                </div>
                {loaded.variant === "modified" && (
                  <p className="mt-2 text-muted">Benchmark string <span className="font-mono text-ink-2">{loaded.c.modified.injection.template_id}</span> placed in the <b className="text-ink-2">{loaded.c.modified.injection.field_display}</b> field.</p>
                )}
              </div>
            )}
            <Field label="Log event">
              <textarea value={log} onChange={(e) => setLog(e.target.value)} rows={8} spellCheck={false}
                placeholder='203.0.113.7 - - [02/Mar/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.4.0"'
                className={`${inputCls} font-mono text-xs leading-relaxed`} />
            </Field>
            <Field label="Model"><Select value={model} onChange={setModel} options={models} /></Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Log type"><Select value={logType} onChange={setLogType} options={LOG_TYPES} /></Field>
              <Field label="Defense">
                <Select value={defense} onChange={setDefense} options={DEFENSE_ORDER.map((d) => ({ value: d, label: DEFENSE_LABEL[d] }))} />
              </Field>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" disabled={busy || !log.trim()} onClick={run}><Play size={15} /> Analyze</Button>
              <Button disabled={busy || !log.trim()} onClick={runAll}><Columns3 size={15} /> Compare all 4 defenses</Button>
            </div>
            <ErrorNote error={error} />
          </div>
        </Card>

        <div className="space-y-6">
          {busy && <Card><Spinner label="Analyzing…" /></Card>}
          {!busy && !result && !compare && (
            <Card><Empty title="No analysis yet" icon={<Play />}>Pick a case or paste a log, then select <b>Analyze</b>.</Empty></Card>
          )}
          {result && <ResultView r={result} />}
          {compare && <CompareView rows={compare} />}
        </div>
      </div>
    </>
  );
}

function ScoreBadges({ r }: { r: AnalysisResult }) {
  if (!r.score) return null;
  const s = r.score;
  return (
    <div className="flex flex-wrap gap-2">
      {s.correct !== null && <Badge tone={s.correct ? "good" : "warn"}>{s.correct ? "matches ground truth" : `ground truth: ${s.label}`}</Badge>}
      {s.attack_success_raw !== null && <Badge tone={s.attack_success_raw ? "crit" : "good"}>model-level attack {s.attack_success_raw ? "succeeded" : "failed"}</Badge>}
      {s.attack_success_final !== null && <Badge tone={s.attack_success_final ? "crit" : "good"}>system-level {s.attack_success_final ? "succeeded" : "blocked"}</Badge>}
      {s.indicator_recall !== null && <Badge>indicator recall {(s.indicator_recall * 100).toFixed(0)}%</Badge>}
    </div>
  );
}

function ResultView({ r }: { r: AnalysisResult }) {
  return (
    <>
      <Card
        title={<span className="flex flex-wrap items-center gap-2">Analysis <MockBadge isMock={r.is_mock} /></span>}
        subtitle={<span className="font-mono">{r.model} · {DEFENSE_LABEL[r.defense]} · {r.log_type}</span>}
        action={r.latency_ms !== null ? <Badge><Timer size={12} /> {r.latency_ms.toFixed(1)} ms</Badge> : undefined}
      >
        <div className="space-y-4">
          <ErrorNote error={r.error} />
          {r.parse_error && !r.error && <ErrorNote error={`Response could not be parsed: ${r.parse_error}`} />}
          <TripwireBanner tripwire={r.tripwire} />
          <ScoreBadges r={r} />
          <OutputSummary out={r.final_output} />
        </div>
      </Card>
      <Card title="Tool requests" subtitle="The model can only ask. The application decides, and every tool is simulated.">
        <ToolDecisions decisions={r.tool_decisions} />
      </Card>
      <Card title="Prompt & raw response">
        <RawTabs prompt={r.prompt} responseText={r.response_text} rawOutput={r.raw_output} finalOutput={r.final_output} canary={r.canary} />
      </Card>
    </>
  );
}

function CompareView({ rows }: { rows: AnalysisResult[] }) {
  return (
    <Card title={<span className="flex items-center gap-2">Defense comparison (same input) <MockBadge isMock={rows[0]?.is_mock} /></span>}>
      <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead>
            <tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
              <th className="py-2 pr-3">Defense</th><th className="py-2 pr-3">Final verdict</th><th className="py-2 pr-3">Raw verdict</th>
              <th className="py-2 pr-3">Indicators</th><th className="py-2 pr-3">Tools</th><th className="py-2 pr-3">Tripwire</th><th className="py-2">Attack</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.defense} className="border-b border-line/60 align-top">
                <td className="py-2.5 pr-3 font-medium">{DEFENSE_LABEL[r.defense]}</td>
                <td className="py-2.5 pr-3"><VerdictBadge verdict={r.final_output?.verdict} /></td>
                <td className="py-2.5 pr-3"><VerdictBadge verdict={r.raw_output?.verdict} /></td>
                <td className="py-2.5 pr-3 tabular-nums">{r.final_output?.indicators.length ?? 0}</td>
                <td className="py-2.5 pr-3 text-xs">
                  {r.tool_decisions.length === 0 ? "—" : r.tool_decisions.map((d, i) => (
                    <div key={i} className={d.decision === "denied" ? "text-[#ff9a9a]" : "text-ink-2"}>{d.decision === "denied" ? "✕" : "✓"} {d.tool}</div>
                  ))}
                </td>
                <td className="py-2.5 pr-3">{r.tripwire.enabled ? (r.tripwire.fired ? <Badge tone="crit">fired</Badge> : <Badge tone="good">armed</Badge>) : <span className="text-muted">n/a</span>}</td>
                <td className="py-2.5">
                  {r.score?.attack_success_final === null || r.score === null ? <span className="text-muted">n/a</span>
                    : <Badge tone={r.score.attack_success_final ? "crit" : "good"}>{r.score.attack_success_final ? "succeeded" : "blocked"}</Badge>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
