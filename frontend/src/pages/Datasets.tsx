import { useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, Download, FileUp, Search, Terminal } from "lucide-react";
import { api, ATTACK_LABEL, DEFENSE_LABEL, type Case } from "../api";
import { Badge, Button, Card, Chip, Empty, ErrorNote, Field, MockBadge, Modal, PageHeader, Select, Spinner, VerdictBadge, inputCls, useAsync } from "../components/ui";
import { ResultModal } from "../components/analysis";

const PAGE = 25;

function dnsEncode(text: string): string {
  const slug = text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const labels: string[] = [];
  let cur = "";
  for (const w of slug.split("-")) {
    const cand = cur ? `${cur}-${w}` : w;
    if (cand.length > 63) { labels.push(cur); cur = w.slice(0, 63); } else cur = cand;
  }
  if (cur) labels.push(cur);
  return labels.join(".");
}

function pyQuote(s: string) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/** Highlight the injected benchmark text however it was encoded into the field. */
export function highlightInjection(raw: string, injected: string): ReactNode {
  const candidates = [injected, pyQuote(injected), dnsEncode(injected)];
  for (const cand of candidates) {
    const i = cand ? raw.indexOf(cand) : -1;
    if (i >= 0) {
      return (
        <>
          {raw.slice(0, i)}
          <mark className="inj">{cand}</mark>
          {highlightInjection(raw.slice(i + cand.length), injected)}
        </>
      );
    }
  }
  return raw;
}

export default function Datasets() {
  const navigate = useNavigate();
  const datasets = useAsync(() => api.datasets(), []);
  const [datasetId, setDatasetId] = useState("logjack-v1");
  const [logType, setLogType] = useState("");
  const [label, setLabel] = useState("");
  const [attack, setAttack] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);

  const stats = useAsync(() => api.datasetStats(datasetId), [datasetId]);
  const page = useAsync(() => api.cases(datasetId, { log_type: logType, label, attack_type: attack, q, offset, limit: PAGE }),
    [datasetId, logType, label, attack, q, offset]);

  const reset = <T,>(fn: (v: T) => void) => (v: T) => { fn(v); setOffset(0); };
  const ds = datasets.data?.find((d) => d.id === datasetId);

  return (
    <>
      <PageHeader
        title="Dataset Explorer"
        description="Labelled synthetic security-log cases. Each case has a clean version and a modified version that contains one fixed, reviewable benchmark string in an attacker-controllable field."
        action={
          <div className="flex flex-wrap gap-2">
            <a href={api.datasetDownloadUrl(datasetId)} className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-raised px-3 py-1.5 text-sm hover:border-accent/60">
              <Download size={15} /> JSONL
            </a>
            <Button onClick={() => setImportOpen(true)}><FileUp size={15} /> Import</Button>
          </div>
        }
      />

      <div className="mb-6 grid gap-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Card>
          <Field label="Dataset">
            <Select value={datasetId} onChange={reset(setDatasetId)}
              options={(datasets.data ?? [{ id: "logjack-v1", name: "LogJack synthetic v1" }]).map((d) => ({ value: d.id, label: `${d.name} (${d.id})` }))} />
          </Field>
          {ds && (
            <div className="mt-3 space-y-1 text-xs text-muted">
              <p>{ds.description}</p>
              <p>Source: <span className="text-ink-2">{ds.source}</span> · {ds.case_count} cases · sha256 <span className="font-mono text-ink-2">{ds.sha256?.slice(0, 16)}…</span></p>
            </div>
          )}
        </Card>
        <Card>
          {stats.data ? (
            <div className="grid grid-cols-2 gap-4 text-xs sm:grid-cols-4">
              {(["by_log_type", "by_label", "by_attack_type", "by_injection_field"] as const).map((k) => (
                <div key={k}>
                  <div className="mb-1.5 font-medium uppercase tracking-wider text-muted">{k.replace("by_", "").replace(/_/g, " ")}</div>
                  <ul className="space-y-0.5">
                    {Object.entries(stats.data![k] || {}).map(([name, n]) => (
                      <li key={name} className="flex justify-between gap-2 text-ink-2">
                        <span className="truncate">{ATTACK_LABEL[name] ?? name}</span><span className="tabular-nums text-ink">{n}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          ) : <Spinner />}
        </Card>
      </div>

      <Card>
        <div className="mb-4 grid gap-3 md:grid-cols-4">
          <div className="relative">
            <Search size={15} className="pointer-events-none absolute left-3 top-2.5 text-muted" />
            <input value={q} onChange={(e) => reset(setQ)(e.target.value)} placeholder="Search id, IP, domain…" className={`${inputCls} pl-9`} />
          </div>
          <Select value={logType} onChange={reset(setLogType)} options={[{ value: "", label: "All log types" }, ...["nginx", "ssh", "dns", "ids"].map((v) => ({ value: v, label: v }))]} />
          <Select value={label} onChange={reset(setLabel)} options={[{ value: "", label: "All labels" }, ...["benign", "suspicious", "malicious"].map((v) => ({ value: v, label: v }))]} />
          <Select value={attack} onChange={reset(setAttack)} options={[{ value: "", label: "All attack types" }, ...Object.entries(ATTACK_LABEL).map(([v, l]) => ({ value: v, label: l }))]} />
        </div>
        <ErrorNote error={page.error} />
        <div className="scroll-thin overflow-x-auto">
          <table className="w-full min-w-[820px] text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
                <th className="py-2 pr-3">Case</th><th className="py-2 pr-3">Type</th><th className="py-2 pr-3">Scenario</th><th className="py-2 pr-3">Label</th>
                <th className="py-2 pr-3">Severity</th><th className="py-2 pr-3">Benchmark attack</th><th className="py-2">Injected field</th>
              </tr>
            </thead>
            <tbody>
              {page.data?.items.map((c) => (
                <tr key={c.case_id} onClick={() => setSelected(c.case_id)} className="cursor-pointer border-b border-line/60 hover:bg-raised/50">
                  <td className="py-2.5 pr-3 font-mono text-xs text-accent">{c.case_id}</td>
                  <td className="py-2.5 pr-3"><Badge>{c.log_type}</Badge></td>
                  <td className="py-2.5 pr-3 text-ink-2">{c.scenario.replace(/_/g, " ")}</td>
                  <td className="py-2.5 pr-3"><VerdictBadge verdict={c.label} /></td>
                  <td className="py-2.5 pr-3 text-ink-2">{c.severity}</td>
                  <td className="py-2.5 pr-3 text-ink-2">{ATTACK_LABEL[c.modified.injection.attack_type]}</td>
                  <td className="py-2.5 text-ink-2">{c.modified.injection.field_display ?? c.modified.injection.field}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {page.loading && !page.data && <Spinner />}
        {page.data && page.data.total === 0 && <Empty title="No cases match these filters" />}
        {page.data && page.data.total > 0 && (
          <div className="mt-4 flex items-center justify-between text-sm text-muted">
            <span>{offset + 1}–{Math.min(offset + PAGE, page.data.total)} of {page.data.total}</span>
            <div className="flex gap-2">
              <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} aria-label="Previous page"><ChevronLeft size={15} /></Button>
              <Button disabled={offset + PAGE >= page.data.total} onClick={() => setOffset(offset + PAGE)} aria-label="Next page"><ChevronRight size={15} /></Button>
            </div>
          </div>
        )}
      </Card>

      <CaseModal datasetId={datasetId} caseId={selected} onClose={() => setSelected(null)}
        onPlay={(c, variant) => navigate("/playground", { state: { caseId: c.case_id, variant, datasetId } })} />
      <ImportModal open={importOpen} onClose={() => setImportOpen(false)} onDone={(id) => { datasets.reload(); setDatasetId(id); setImportOpen(false); }} />
    </>
  );
}

function CaseModal({ datasetId, caseId, onClose, onPlay }: {
  datasetId: string; caseId: string | null; onClose: () => void; onPlay: (c: Case, v: "clean" | "modified") => void;
}) {
  const { data, loading, error } = useAsync(() => (caseId ? api.caseDetail(datasetId, caseId) : Promise.resolve(null)), [datasetId, caseId]);
  const [resultId, setResultId] = useState<number | null>(null);
  const c = data?.case;
  const inj = c?.modified.injection;
  const modifiedHighlighted = useMemo(() => (c && inj ? highlightInjection(c.modified.raw, inj.injected_text) : null), [c, inj]);
  return (
    <>
      <Modal open={caseId !== null && resultId === null} onClose={onClose} wide
        title={<span className="flex flex-wrap items-center gap-2 font-mono">{caseId} {c && <VerdictBadge verdict={c.label} />}</span>}>
        {loading && <Spinner />}
        <ErrorNote error={error} />
        {c && inj && (
          <div className="space-y-5">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-1 text-sm">
                <div className="text-xs uppercase tracking-wider text-muted">Ground truth</div>
                <div className="flex flex-wrap gap-2"><VerdictBadge verdict={c.label} /><Badge>{c.severity}</Badge><Badge>{c.category.replace(/_/g, " ")}</Badge></div>
                <p className="text-ink-2">{c.description}</p>
              </div>
              <div className="text-sm">
                <div className="mb-1 text-xs uppercase tracking-wider text-muted">Expected indicators</div>
                <div className="flex flex-wrap gap-1.5">{c.expected_indicators.length ? c.expected_indicators.map((i) => <Chip key={i}>{i}</Chip>) : <span className="text-muted">none (benign)</span>}</div>
              </div>
              <div className="space-y-1 text-sm">
                <div className="text-xs uppercase tracking-wider text-muted">Benchmark placement</div>
                <div className="flex flex-wrap gap-2"><Badge tone="serious">{ATTACK_LABEL[inj.attack_type]}</Badge><Badge>{inj.template_id}</Badge><Badge>{inj.field_display ?? inj.field}</Badge></div>
                <p className="text-xs text-muted">Objective: <span className="font-mono text-ink-2">{JSON.stringify(inj.objective)}</span></p>
              </div>
            </div>
            <div className="grid gap-4 lg:grid-cols-2">
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted">Clean log</span>
                  <Button className="text-xs" onClick={() => onPlay(c, "clean")}><Terminal size={13} /> Analyze</Button>
                </div>
                <pre className="scroll-thin max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-panel p-3 font-mono text-xs leading-relaxed text-ink-2">{c.clean.raw}</pre>
              </div>
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted">Modified log <span className="normal-case text-serious">(benchmark text highlighted)</span></span>
                  <Button className="text-xs" onClick={() => onPlay(c, "modified")}><Terminal size={13} /> Analyze</Button>
                </div>
                <pre className="scroll-thin max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-serious/30 bg-panel p-3 font-mono text-xs leading-relaxed text-ink-2">{modifiedHighlighted}</pre>
              </div>
            </div>
            <div>
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Recorded results for this case ({data!.results.length})</div>
              {data!.results.length === 0 ? <p className="text-sm text-muted">No runs yet.</p> : (
                <div className="scroll-thin max-h-64 overflow-auto">
                  <table className="w-full min-w-[640px] text-xs">
                    <thead><tr className="text-left uppercase tracking-wider text-muted"><th className="py-1.5 pr-2">Variant</th><th className="pr-2">Model</th><th className="pr-2">Defense</th><th className="pr-2">Verdict</th><th className="pr-2">Attack</th><th className="pr-2">Tripwire</th><th /></tr></thead>
                    <tbody>
                      {data!.results.map((r) => (
                        <tr key={r.id} className="cursor-pointer border-t border-line/60 hover:bg-raised/50" onClick={() => setResultId(r.id)}>
                          <td className="py-1.5 pr-2">{r.variant}</td><td className="pr-2 font-mono">{r.model}</td><td className="pr-2">{DEFENSE_LABEL[r.defense]}</td>
                          <td className="pr-2"><VerdictBadge verdict={r.verdict_final} /></td>
                          <td className="pr-2">{r.attack_success_final === null ? "—" : r.attack_success_final ? "succeeded" : "blocked"}</td>
                          <td className="pr-2">{r.tripwire_fired ? "fired" : "—"}</td>
                          <td><MockBadge isMock={r.is_mock} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </Modal>
      <ResultModal id={resultId} onClose={() => setResultId(null)} />
    </>
  );
}

function ImportModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (datasetId: string) => void }) {
  const dsFile = useRef<HTMLInputElement>(null);
  const bFile = useRef<HTMLInputElement>(null);
  const [name, setName] = useState("My dataset");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const go = async (kind: "dataset" | "benchmark") => {
    const f = (kind === "dataset" ? dsFile : bFile).current?.files?.[0];
    if (!f) { setErr("Choose a file first."); return; }
    setBusy(true); setErr(null); setMsg(null);
    try {
      if (kind === "dataset") { const d = await api.importDataset(f, name); setMsg(`Imported ${d.case_count} cases as ${d.id}.`); onDone(d.id); }
      else { const r = await api.importBenchmark(f); setMsg(`Benchmark ${r.benchmark_id} (${r.templates} templates) → dataset ${r.dataset.id}.`); onDone(r.dataset.id); }
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Modal open={open} onClose={onClose} title="Import">
      <div className="space-y-6 text-sm">
        <section className="space-y-3">
          <h3 className="font-semibold">Dataset (JSONL)</h3>
          <p className="text-muted">One case per line, using the same schema as <span className="font-mono">logjack-v1.jsonl</span>. Every line is validated, and errors are reported by line number.</p>
          <Field label="Name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <input ref={dsFile} type="file" accept=".jsonl,.ndjson,.json" className="block text-xs text-ink-2 file:mr-3 file:rounded-md file:border-0 file:bg-raised file:px-3 file:py-1.5 file:text-ink" />
          <Button variant="primary" disabled={busy} onClick={() => go("dataset")}><FileUp size={15} /> Import dataset</Button>
        </section>
        <section className="space-y-3 border-t border-line pt-5">
          <h3 className="font-semibold">Prompt-injection benchmark (JSON)</h3>
          <p className="text-muted">A fixed, human-reviewed template file in the format of <span className="font-mono">logjack-pi-bench-v1.json</span>. LogJack validates it and places each template verbatim into the built-in clean cases. It never generates or mutates payloads.</p>
          <input ref={bFile} type="file" accept=".json" className="block text-xs text-ink-2 file:mr-3 file:rounded-md file:border-0 file:bg-raised file:px-3 file:py-1.5 file:text-ink" />
          <Button disabled={busy} onClick={() => go("benchmark")}><FileUp size={15} /> Import benchmark</Button>
        </section>
        {msg && <div className="rounded-lg border border-good/40 bg-good/10 px-3 py-2 text-[#9be89b]">{msg}</div>}
        <ErrorNote error={err} />
      </div>
    </Modal>
  );
}
