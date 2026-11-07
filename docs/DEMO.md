# 5-minute demo script

Setup: backend on :8000 and frontend on :5173 (see the README). No API keys are needed.

1. **Overview** (http://localhost:5173). Point out the separate *real* and *simulated* panels and
   the "External actions: 0" tile. Nothing is ever executed.

2. **Dataset Explorer.** Filter `log type = ssh`, `attack type = Unauthorized action`, then open
   a case. Show ground truth, the expected indicators, and the clean and modified logs side by
   side, with the benchmark sentence highlighted inside the SSH username.
   Click **Analyze** on the modified log.

3. **SOC Playground.** The case is pre-loaded.
   * Model `mock:naive`, defense **Baseline**, then **Analyze**. Depending on the case, the model
     may request `whitelist_ip`. The tool panel shows it **denied** by application policy.
   * Click **Compare all 4 defenses**. One table shows the final and raw verdicts, tool
     decisions, tripwire state and attack outcome for each defense.
   * Open **Prompt & raw response**, then **User prompt** for the combined run, to show the
     nonce-tagged untrusted-data boundaries and the canary in the system prompt.

4. **Experiments.** Keep `mock:naive` and `mock:cautious`, all four defenses and both variants,
   and set *Case limit* = 40. Start the run and watch the progress bar. Click **Pause**, then
   **Resume**, and note that completed runs are not repeated.

5. **Defense Comparison.** Walk through the ASR (model- vs system-level), ASR by attack type,
   accuracy and flips, FP/FN, indicators/tripwire and latency charts, then the table view.
   Point out the banner: these are mock numbers that reflect scripted constants, not findings.

6. **Tripwire Events.** Show canary-leak and forbidden-tool events, and the denied-tool log,
   whose *Executed* column is always "no".

7. **Findings & Exports.** Switch to **Real LLM**: it says no real experiments exist yet, so
   nothing is reported. Switch to **Simulated** to see generated statements with counts and
   CI-overlap notes. Download `metrics.csv`, whose file name is tagged `MOCK`.

8. *(Optional, with a key or Ollama)*: add `LOGJACK_OPENAI_API_KEY`, or start Ollama, restart
   the backend, and repeat step 4 with a real model. Real results appear in the "Real LLM" panels.
