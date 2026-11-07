import { useState } from "react";
import { Ban, CheckCircle2, ShieldAlert, ShieldCheck, Siren, Timer } from "lucide-react";
import { api, DEFENSE_LABEL, pct, type AnalysisOutput, type ToolDecision, type Tripwire, type MetricRow, ATTACK_LABEL } from "../api";
import { Badge, Chip, ErrorNote, MockBadge, Modal, Pre, Spinner, Tabs, VerdictBadge, useAsync } from "./ui";
import type { GroupDatum } from "./charts";

export function ToolDecisions({ decisions }: { decisions: ToolDecision[] }) {
  if (!decisions.length) return <p className="text-sm text-muted">No tool requests.</p>;
  return (
    <ul className="space-y-2">
      {decisions.map((d, i) => (
        <li key={i} className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-panel px-3 py-2 text-sm">
          {d.decision === "denied" ? (
            <Badge tone="crit"><Ban size={12} /> denied</Badge>
          ) : (
            <Badge tone="good"><CheckCircle2 size={12} /> allowed · simulated</Badge>
          )}
          <span className="font-mono text-ink">{d.tool}</span>
          <span className="font-mono text-xs text-muted">{JSON.stringify(d.arguments)}</span>
          <span className="w-full text-xs text-muted">{d.reason} Executed externally: <b className="text-ink-2">no</b>.</span>
        </li>
      ))}
    </ul>
  );
}

export function TripwireBanner({ tripwire }: { tripwire: Tripwire }) {
  if (!tripwire.enabled) return null;
  return tripwire.fired ? (
    <div className="flex items-start gap-2 rounded-lg border border-crit/50 bg-crit/10 px-3 py-2 text-sm text-[#ffb3b3]">
      <Siren size={16} className="mt-0.5 shrink-0" />
      <div>
        <b>Tripwire fired</b>: {tripwire.reasons.join(", ")}. Output quarantined and routed to human review.
      </div>
    </div>
  ) : (
    <div className="flex items-center gap-2 rounded-lg border border-good/30 bg-good/5 px-3 py-2 text-sm text-[#9be89b]">
      <ShieldCheck size={16} /> Canary tripwire armed. No canary leak or forbidden tool request.
    </div>
  );
}

export function OutputSummary({ out }: { out: AnalysisOutput | null }) {
  if (!out) return <p className="text-sm text-muted">No parsed output.</p>;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={out.verdict} />
        {out.severity && <Badge>severity: {out.severity}</Badge>}
        {out.confidence !== null && out.confidence !== undefined && <Badge>confidence {out.confidence.toFixed(2)}</Badge>}
        {out.embedded_instructions_detected && <Badge tone="warn"><ShieldAlert size={12} /> embedded instructions flagged</Badge>}
        {out.requires_human_review && <Badge tone="crit">human review required</Badge>}
      </div>
      <div>
        <div className="mb-1 text-xs uppercase tracking-wider text-muted">Summary</div>
        <p className="text-sm text-ink-2">{out.summary || "—"}</p>
      </div>
      <div>
        <div className="mb-1.5 text-xs uppercase tracking-wider text-muted">Indicators ({out.indicators.length})</div>
        <div className="flex flex-wrap gap-1.5">
          {out.indicators.length ? out.indicators.map((i, k) => <Chip key={k}>{i}</Chip>) : <span className="text-sm text-muted">none</span>}
        </div>
      </div>
      <div>
        <div className="mb-1 text-xs uppercase tracking-wider text-muted">Recommended actions</div>
        <ul className="list-inside list-disc text-sm text-ink-2">
          {out.recommended_actions.length ? out.recommended_actions.map((a, k) => <li key={k}>{a}</li>) : <li>—</li>}
        </ul>
      </div>
    </div>
  );
}

export function RawTabs({ prompt, responseText, rawOutput, finalOutput, canary }: {
  prompt: { system: string; user: string }; responseText: string; rawOutput: unknown; finalOutput: unknown; canary?: string | null;
}) {
  const [tab, setTab] = useState("response");
  return (
    <div className="space-y-3">
      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { id: "response", label: "Model response" },
          { id: "final", label: "Final output (JSON)" },
          { id: "raw", label: "Parsed raw output" },
          { id: "system", label: "System prompt" },
          { id: "user", label: "User prompt" },
        ]}
      />
      {tab === "response" && <Pre>{responseText || "(empty)"}</Pre>}
      {tab === "final" && <Pre>{JSON.stringify(finalOutput, null, 2)}</Pre>}
      {tab === "raw" && <Pre>{JSON.stringify(rawOutput, null, 2)}</Pre>}
      {tab === "system" && (
        <>
          {canary && <p className="text-xs text-muted">Canary for this run: <span className="font-mono text-ink-2">{canary}</span></p>}
          <Pre>{prompt.system}</Pre>
        </>
      )}
      {tab === "user" && <Pre>{prompt.user}</Pre>}
    </div>
  );
}

export function ResultModal({ id, onClose }: { id: number | null; onClose: () => void }) {
  const { data, error, loading } = useAsync(() => (id ? api.result(id) : Promise.resolve(null)), [id]);
  return (
    <Modal open={id !== null} onClose={onClose} wide
      title={data ? <span className="flex flex-wrap items-center gap-2">Result #{data.id} <MockBadge isMock={data.is_mock} />
        <span className="font-mono text-xs text-muted">{data.case_id} · {data.variant} · {data.model} · {DEFENSE_LABEL[data.defense] ?? data.defense}</span></span> : "Result"}>
      {loading && <Spinner />}
      <ErrorNote error={error} />
      {data && (
        <div className="space-y-5">
          <ErrorNote error={data.error} />
          <div className="flex flex-wrap gap-2 text-xs">
            {data.label && <Badge>ground truth: {data.label}</Badge>}
            {data.attack_type && <Badge tone="serious">{ATTACK_LABEL[data.attack_type] ?? data.attack_type}</Badge>}
            {data.attack_success_raw !== null && (
              <Badge tone={data.attack_success_raw ? "crit" : "good"}>model-level attack {data.attack_success_raw ? "succeeded" : "failed"}</Badge>
            )}
            {data.attack_success_final !== null && (
              <Badge tone={data.attack_success_final ? "crit" : "good"}>system-level attack {data.attack_success_final ? "succeeded" : "blocked"}</Badge>
            )}
            {data.correct !== null && <Badge tone={data.correct ? "good" : "warn"}>{data.correct ? "correct" : "incorrect"} verdict</Badge>}
            {data.indicator_recall !== null && <Badge>indicator recall {pct(data.indicator_recall, 0)}</Badge>}
            {data.latency_ms !== null && <Badge><Timer size={12} /> {data.latency_ms.toFixed(1)} ms</Badge>}
          </div>
          {data.detail && (
            <>
              <TripwireBanner tripwire={data.detail.tripwire} />
              <div className="grid gap-5 lg:grid-cols-2">
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Final output (after enforcement)</h3>
                  <OutputSummary out={data.detail.final_output} />
                </div>
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Tool requests</h3>
                  <ToolDecisions decisions={data.detail.tool_decisions} />
                </div>
              </div>
              <RawTabs prompt={data.detail.prompt} responseText={data.detail.response_text} rawOutput={data.detail.raw_output}
                finalOutput={data.detail.final_output} canary={data.detail.canary} />
            </>
          )}
        </div>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------- metric -> chart data helpers

type RatePick = (m: MetricRow) => { value: number | null; k: number; n: number } | null | undefined;

export function groupData(rows: MetricRow[], groups: { label: string; pick: RatePick }[]): GroupDatum[] {
  return groups.map((g) => {
    const d: GroupDatum = { group: g.label };
    rows.forEach((m) => {
      const r = g.pick(m);
      d[m.defense] = r?.value ?? null;
      if (r) d[`${m.defense}__kn`] = { k: r.k, n: r.n };
    });
    return d;
  });
}

export function numberData(rows: MetricRow[], groups: { label: string; pick: (m: MetricRow) => number | null }[]): GroupDatum[] {
  return groups.map((g) => {
    const d: GroupDatum = { group: g.label };
    rows.forEach((m) => (d[m.defense] = g.pick(m)));
    return d;
  });
}

export function ciText(r: { value: number | null; ci95: [number, number] | null; k: number; n: number }) {
  if (r.value === null) return "—";
  return `${pct(r.value)} (${r.k}/${r.n})`;
}
