import { useState } from "react";
import { Link } from "react-router-dom";
import { Ban, Siren } from "lucide-react";
import { api, DEFENSE_LABEL, fmtTime } from "../api";
import { Badge, Card, Empty, ErrorNote, MockBadge, PageHeader, Select, Spinner, Stat, useAsync } from "../components/ui";
import { ResultModal } from "../components/analysis";

export default function Tripwires() {
  const [scope, setScope] = useState("");
  const isMock = scope === "" ? undefined : scope === "mock";
  const trips = useAsync(() => api.tripwires({ is_mock: isMock }), [scope]);
  const denied = useAsync(() => api.toolEvents({ decision: "denied" }), []);
  const [open, setOpen] = useState<number | null>(null);
  const deniedRows = (denied.data ?? []).filter((d) => isMock === undefined || Boolean(d.is_mock) === isMock);

  const reasons: Record<string, number> = {};
  trips.data?.forEach((t) => t.reasons.forEach((r) => (reasons[r] = (reasons[r] || 0) + 1)));

  return (
    <>
      <PageHeader
        title="Tripwire Events"
        description="The combined defense hides a secret canary in its system prompt. If the canary shows up in the output, or the model requests a forbidden tool, the tripwire fires and the output is quarantined. Every denied tool request is recorded here under all defenses. None is ever executed."
        action={<Select value={scope} onChange={setScope} options={[{ value: "", label: "Real + simulated" }, { value: "real", label: "Real LLM only" }, { value: "mock", label: "Simulated only" }]} />}
      />
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Tripwire events" value={trips.data?.length ?? "—"} icon={<Siren size={15} />} tone="crit" hint="latest 200 shown" />
        <Stat label="Canary leaks" value={reasons.canary_leak ?? 0} />
        <Stat label="Forbidden tool requests" value={reasons.forbidden_tool_request ?? 0} hint="caught by tripwire" />
        <Stat label="Denied tool calls" value={deniedRows.length} icon={<Ban size={15} />} hint="all defenses, latest 200" />
      </div>

      <Card title="Tripwire history">
        {trips.loading && <Spinner />}
        <ErrorNote error={trips.error} />
        {trips.data?.length === 0 && <Empty title="No tripwire events" icon={<Siren />}>Run an experiment or playground analysis with the <b>Combined + tripwire</b> defense.</Empty>}
        {!!trips.data?.length && (
          <div className="scroll-thin overflow-x-auto">
            <table className="w-full min-w-[860px] text-sm">
              <thead><tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
                <th className="py-2 pr-3">Time</th><th className="pr-3">Source</th><th className="pr-3">Case</th><th className="pr-3">Model</th><th className="pr-3">Reasons</th><th className="pr-3">Details</th><th />
              </tr></thead>
              <tbody>
                {trips.data.map((t) => (
                  <tr key={t.id} className="cursor-pointer border-b border-line/60 hover:bg-raised/50" onClick={() => setOpen(t.result_id)}>
                    <td className="py-2 pr-3 text-xs text-ink-2">{fmtTime(t.created_at)}</td>
                    <td className="pr-3 text-xs">{t.experiment_id ? <Link onClick={(e) => e.stopPropagation()} className="font-mono text-accent hover:underline" to={`/experiments/${t.experiment_id}`}>{t.experiment_id}</Link> : <span className="text-muted">playground</span>}</td>
                    <td className="pr-3 font-mono text-xs">{t.case_id ?? "—"} <span className="text-muted">{t.variant}</span></td>
                    <td className="pr-3 font-mono text-xs">{t.model}</td>
                    <td className="pr-3"><div className="flex flex-wrap gap-1">{t.reasons.map((r) => <Badge key={r} tone="crit">{r.replace(/_/g, " ")}</Badge>)}</div></td>
                    <td className="pr-3 font-mono text-xs text-muted">{t.details.forbidden_tools ? (t.details.forbidden_tools as string[]).join(", ") : t.details.canary_leak ? "canary in output" : ""}</td>
                    <td><MockBadge isMock={t.is_mock} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="mt-6">
        <Card title="Denied tool requests (all defenses)" subtitle="The application's permission policy denied these. They were recorded and never executed.">
          {denied.loading && <Spinner />}
          {deniedRows.length === 0 && !denied.loading && <Empty title="No denied tool requests yet" />}
          {deniedRows.length > 0 && (
            <div className="scroll-thin max-h-[480px] overflow-auto">
              <table className="w-full min-w-[860px] text-sm">
                <thead><tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
                  <th className="py-2 pr-3">Time</th><th className="pr-3">Tool</th><th className="pr-3">Arguments</th><th className="pr-3">Defense</th><th className="pr-3">Model</th><th className="pr-3">Case</th><th className="pr-3">Executed</th><th />
                </tr></thead>
                <tbody>
                  {deniedRows.map((d) => (
                    <tr key={d.id} className="cursor-pointer border-b border-line/60 hover:bg-raised/50" onClick={() => setOpen(d.result_id)}>
                      <td className="py-2 pr-3 text-xs text-ink-2">{fmtTime(d.created_at)}</td>
                      <td className="pr-3 font-mono text-xs text-[#ff9a9a]">{d.tool}</td>
                      <td className="pr-3 font-mono text-xs text-muted">{JSON.stringify(d.arguments)}</td>
                      <td className="pr-3 text-xs">{DEFENSE_LABEL[d.defense]}</td>
                      <td className="pr-3 font-mono text-xs">{d.model}</td>
                      <td className="pr-3 font-mono text-xs">{d.case_id ?? "—"}</td>
                      <td className="pr-3"><Badge tone="good">no</Badge></td>
                      <td><MockBadge isMock={d.is_mock} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
      <ResultModal id={open} onClose={() => setOpen(null)} />
    </>
  );
}
