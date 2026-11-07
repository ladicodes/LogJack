import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { DEFENSE_COLOR, DEFENSE_LABEL, DEFENSE_ORDER } from "../api";

export interface GroupDatum {
  group: string;
  // per defense: value in [0,1] (or ms when unit = "ms"), plus k/n for tooltips
  [defense: string]: string | number | null | { k: number; n: number } | undefined;
}

interface TooltipPayload {
  dataKey: string;
  value: number | null;
  color: string;
  payload: GroupDatum;
}

function ChartTooltip({ active, payload, label, unit }: { active?: boolean; payload?: TooltipPayload[]; label?: string; unit: "pct" | "ms" }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-line-strong bg-[#0b1118]/95 px-3 py-2 text-xs shadow-xl">
      <div className="mb-1.5 font-semibold text-ink">{label}</div>
      {payload.map((p) => {
        const meta = p.payload[`${p.dataKey}__kn`] as { k: number; n: number } | undefined;
        return (
          <div key={p.dataKey} className="flex items-center justify-between gap-4 py-0.5">
            <span className="flex items-center gap-1.5 text-ink-2">
              <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: p.color }} />
              {DEFENSE_LABEL[p.dataKey] ?? p.dataKey}
            </span>
            <span className="tabular-nums text-ink">
              {p.value === null || p.value === undefined ? "—" : unit === "pct" ? `${(p.value * 100).toFixed(1)}%` : `${p.value.toFixed(1)} ms`}
              {meta && <span className="ml-1 text-muted">({meta.k}/{meta.n})</span>}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/** Grouped bars: x = metric/category group, one bar per defense (fixed color per defense). */
export function DefenseBars({ data, defenses, unit = "pct", height = 260 }: {
  data: GroupDatum[]; defenses: string[]; unit?: "pct" | "ms"; height?: number;
}) {
  const ordered = DEFENSE_ORDER.filter((d) => defenses.includes(d));
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -8 }} barGap={2} barCategoryGap="22%">
          <CartesianGrid vertical={false} strokeDasharray="0" />
          <XAxis dataKey="group" tickLine={false} axisLine={{ stroke: "var(--color-line-strong)" }} interval={0} tick={{ fontSize: 11 }} />
          <YAxis
            tickLine={false}
            axisLine={false}
            width={48}
            domain={unit === "pct" ? [0, 1] : [0, "auto"]}
            tickFormatter={(v: number) => (unit === "pct" ? `${Math.round(v * 100)}%` : `${v}`)}
          />
          <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} content={<ChartTooltip unit={unit} />} />
          <Legend
            iconType="square"
            iconSize={10}
            wrapperStyle={{ fontSize: 12, paddingTop: 8 }}
            formatter={(v: string) => <span style={{ color: "var(--color-ink-2)" }}>{DEFENSE_LABEL[v] ?? v}</span>}
          />
          {ordered.map((d) => (
            <Bar key={d} dataKey={d} name={d} fill={DEFENSE_COLOR[d]} radius={[4, 4, 0, 0]} maxBarSize={30}
              stroke="var(--color-card)" strokeWidth={1} isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
