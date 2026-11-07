// Typed client for the LogJack FastAPI backend (proxied at /api in dev, same-origin in prod).

export type Verdict = "benign" | "suspicious" | "malicious";
export type LogType = "nginx" | "ssh" | "dns" | "ids";

export interface Rate {
  value: number | null;
  k: number;
  n: number;
  ci95: [number, number] | null;
}

export interface Injection {
  benchmark_id: string;
  template_id: string;
  attack_type: string;
  field: string;
  field_display?: string;
  objective: Record<string, string>;
  injected_text: string;
}

export interface Case {
  case_id: string;
  dataset_id: string;
  log_type: LogType;
  scenario: string;
  category: string;
  label: Verdict;
  severity: string;
  description: string;
  expected_indicators: string[];
  primary_indicator: string;
  clean: { raw: string; fields: Record<string, unknown> };
  modified: { raw: string; fields: Record<string, unknown>; injection: Injection };
}

export interface Dataset {
  id: string;
  name: string;
  description: string;
  source: string;
  sha256: string;
  case_count: number;
  created_at: string;
}

export interface Defense {
  id: string;
  name: string;
  description: string;
  guardrails: boolean;
  isolation: boolean;
  canary_tripwire: boolean;
}

export interface ProviderCatalog {
  provider: string;
  is_mock: boolean;
  configured: boolean;
  models: string[];
}

export interface AnalysisOutput {
  verdict: Verdict | null;
  severity: string | null;
  indicators: string[];
  summary: string;
  recommended_actions: string[];
  tool_requests: { tool: string; arguments?: Record<string, unknown> }[];
  embedded_instructions_detected: boolean;
  confidence: number | null;
  requires_human_review?: boolean;
}

export interface ToolDecision {
  tool: string;
  arguments: Record<string, unknown>;
  decision: "allowed_simulated" | "denied";
  reason: string;
  simulated_result: Record<string, unknown> | null;
  executed_externally: boolean;
  violation: boolean;
}

export interface Tripwire {
  enabled: boolean;
  fired: boolean;
  reasons: string[];
  details: Record<string, unknown>;
}

export interface Score {
  label: string;
  verdict_raw: string | null;
  verdict_final: string | null;
  correct: boolean | null;
  attack_success_raw: boolean | null;
  attack_success_final: boolean | null;
  indicator_recall: number | null;
  attack_type: string | null;
}

export interface AnalysisResult {
  model: string;
  provider: string;
  is_mock: boolean;
  defense: string;
  log_type: string;
  prompt: { system: string; user: string };
  canary: string | null;
  response_text: string;
  latency_ms: number | null;
  error: string | null;
  parse_ok: boolean;
  parse_error: string | null;
  raw_output: AnalysisOutput | null;
  final_output: AnalysisOutput | null;
  tool_decisions: ToolDecision[];
  tripwire: Tripwire;
  disclosure_raw: boolean;
  disclosure_final: boolean;
  score: Score | null;
  result_id: number;
}

export interface Experiment {
  id: string;
  name: string;
  status: string;
  is_mock: boolean;
  config: {
    dataset_id: string;
    models: string[];
    defenses: string[];
    variants: string[];
    case_count: number;
    concurrency: number;
    limit: number | null;
    sample_seed: number;
    temperature: number;
    max_tokens: number;
    log_types: string[] | null;
    attack_types: string[] | null;
  };
  total_runs: number;
  completed_runs: number;
  failed_runs: number;
  progress: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface VariantBlock {
  runs: number;
  errors: number;
  parse_failures: Rate;
  accuracy: Rate;
  false_positive_rate: Rate;
  false_negative_rate: Rate;
  false_positives: number;
  false_negatives: number;
  indicator_preservation: number | null;
  indicator_cases: number;
  injection_flag_rate: Rate;
  tripwire_rate: Rate;
  tool_violation_attempt_rate: Rate;
  latency_ms: { mean: number | null; p50: number | null; p95: number | null };
}

export interface MetricRow {
  model: string;
  defense: string;
  is_mock: boolean;
  clean: VariantBlock;
  modified: VariantBlock;
  attack: {
    asr_model: Rate;
    asr_system: Rate;
    tripwire_catch_rate: Rate;
    by_attack_type: Record<string, { asr_model: Rate; asr_system: Rate }>;
  };
  paired: { pairs: number; verdict_flip_rate: Rate; indicator_recall_delta: number | null };
}

export interface ResultRow {
  id: number;
  experiment_id: string | null;
  dataset_id: string | null;
  case_id: string | null;
  variant: string;
  model: string;
  provider: string;
  defense: string;
  is_mock: number;
  log_type: string;
  label: string | null;
  attack_type: string | null;
  verdict_raw: string | null;
  verdict_final: string | null;
  severity_final: string | null;
  correct: number | null;
  attack_success_raw: number | null;
  attack_success_final: number | null;
  indicator_recall: number | null;
  tripwire_fired: number;
  tool_violation_attempted: number;
  injection_flagged: number;
  parse_ok: number;
  latency_ms: number | null;
  error: string | null;
  created_at: string;
}

export interface ResultDetail extends ResultRow {
  detail: {
    prompt: { system: string; user: string };
    response_text: string;
    raw_output: AnalysisOutput | null;
    final_output: AnalysisOutput | null;
    tool_decisions: ToolDecision[];
    tripwire: Tripwire;
    parse_error: string | null;
    canary: string | null;
  } | null;
}

export interface TripwireEvent {
  id: number;
  result_id: number;
  experiment_id: string | null;
  case_id: string | null;
  variant: string;
  model: string;
  defense: string;
  is_mock: number;
  reasons: string[];
  details: Record<string, unknown>;
  created_at: string;
}

export interface ToolEvent {
  id: number;
  result_id: number;
  experiment_id: string | null;
  case_id: string | null;
  model: string;
  defense: string;
  is_mock: number;
  tool: string;
  arguments: Record<string, unknown>;
  decision: string;
  reason: string;
  executed_externally: number;
  created_at: string;
}

export interface Overview {
  counts: Record<string, number>;
  latest: Record<"real" | "mock", { experiment: Experiment | null; metrics: MetricRow[] }>;
  recent_experiments: Experiment[];
}

export interface Findings {
  scope: "real" | "mock";
  experiment: { id: string; name: string; status: string; total_runs: number } | null;
  statements: { model: string; defense: string; kind: string; text: string }[];
  notice: string;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      const d = body.detail;
      if (typeof d === "string") msg = d;
      else if (d?.message) msg = `${d.message}: ${(d.errors || []).slice(0, 5).join("; ")}`;
      else if (Array.isArray(d)) msg = d.map((e: { msg: string }) => e.msg).join("; ");
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  });
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const api = {
  overview: () => request<Overview>("/api/overview"),
  models: () => request<ProviderCatalog[]>("/api/models"),
  defenses: () => request<Defense[]>("/api/defenses"),
  datasets: () => request<Dataset[]>("/api/datasets"),
  datasetStats: (id: string) => request<Record<string, Record<string, number>>>(`/api/datasets/${encodeURIComponent(id)}/stats`),
  cases: (id: string, params: Record<string, string | number | undefined>) =>
    request<{ items: Case[]; total: number }>(`/api/datasets/${encodeURIComponent(id)}/cases${qs(params)}`),
  caseDetail: (id: string, caseId: string) =>
    request<{ case: Case; results: ResultRow[] }>(`/api/datasets/${encodeURIComponent(id)}/cases/${encodeURIComponent(caseId)}`),
  importDataset: (file: File, name: string) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("name", name);
    return request<Dataset>("/api/datasets/import", { method: "POST", body: fd });
  },
  importBenchmark: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return request<{ benchmark_id: string; templates: number; dataset: Dataset }>("/api/benchmarks/import", { method: "POST", body: fd });
  },
  benchmarks: () => request<{ id: string; version: string; description: string; template_count: number }[]>("/api/benchmarks"),
  analyze: (body: Record<string, unknown>) => request<AnalysisResult>("/api/analyze", json(body)),
  experiments: () => request<Experiment[]>("/api/experiments"),
  experiment: (id: string) => request<Experiment>(`/api/experiments/${id}`),
  createExperiment: (body: Record<string, unknown>) => request<Experiment>("/api/experiments", json(body)),
  resume: (id: string) => request<Experiment>(`/api/experiments/${id}/resume`, { method: "POST" }),
  pause: (id: string) => request<Experiment>(`/api/experiments/${id}/pause`, { method: "POST" }),
  remove: (id: string) => request<{ status: string }>(`/api/experiments/${id}`, { method: "DELETE" }),
  metrics: (id: string) => request<{ metrics: MetricRow[]; is_mock: boolean; status: string }>(`/api/experiments/${id}/metrics`),
  results: (id: string, params: Record<string, string | number | undefined>) =>
    request<{ items: ResultRow[]; total: number }>(`/api/experiments/${id}/results${qs(params)}`),
  result: (id: number) => request<ResultDetail>(`/api/results/${id}`),
  tripwires: (params: Record<string, string | boolean | undefined> = {}) => request<TripwireEvent[]>(`/api/tripwires${qs(params)}`),
  toolEvents: (params: Record<string, string | undefined> = {}) => request<ToolEvent[]>(`/api/tool-events${qs(params)}`),
  findings: (params: Record<string, string | undefined>) => request<Findings>(`/api/findings${qs(params)}`),
  exportUrl: (id: string, kind: "results" | "metrics", format: "csv" | "json") =>
    `/api/experiments/${id}/export?kind=${kind}&format=${format}`,
  datasetDownloadUrl: (id: string) => `/api/datasets/${encodeURIComponent(id)}/download`,
};

export const DEFENSE_ORDER = ["baseline", "guardrails", "isolation", "combined"];
export const DEFENSE_LABEL: Record<string, string> = {
  baseline: "Baseline",
  guardrails: "Guardrails",
  isolation: "Isolation",
  combined: "Combined + tripwire",
};
// Fixed slot per defense entity - color follows the defense, never its rank.
export const DEFENSE_COLOR: Record<string, string> = {
  baseline: "var(--color-s1)",
  guardrails: "var(--color-s2)",
  isolation: "var(--color-s3)",
  combined: "var(--color-s4)",
};
export const ATTACK_LABEL: Record<string, string> = {
  verdict_manipulation: "Verdict manipulation",
  indicator_omission: "Indicator omission",
  false_positive: "False-positive induction",
  unauthorized_action: "Unauthorized action",
  prompt_disclosure: "Instruction disclosure",
};

export const ATTACK_SHORT: Record<string, string> = {
  verdict_manipulation: "Verdict",
  indicator_omission: "Omission",
  false_positive: "False pos.",
  unauthorized_action: "Tool abuse",
  prompt_disclosure: "Disclosure",
};

export const pct =(v: number | null | undefined, digits = 1) =>
  v === null || v === undefined ? "—" : `${(v * 100).toFixed(digits)}%`;
export const fmtTime = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");
