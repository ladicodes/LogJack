import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertOctagon, RotateCcw } from "lucide-react";

interface Props {
  children: ReactNode;
  /** When this changes (e.g. the route), the boundary clears its error. */
  resetKey?: string;
}
interface State {
  error: Error | null;
  resetKey?: string;
}

/** Keeps one broken page from blanking the whole app: shows the error and lets the user recover. */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, resetKey: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    if (props.resetKey !== state.resetKey) return { error: null, resetKey: props.resetKey };
    return null;
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("LogJack page error:", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="rounded-xl border border-crit/40 bg-crit/10 p-6">
        <div className="flex items-center gap-2 text-base font-semibold text-[#ffb3b3]">
          <AlertOctagon size={18} /> This page hit an error
        </div>
        <p className="mt-2 text-sm text-ink-2">The rest of the app still works. Use the sidebar to switch pages, or retry this one.</p>
        <pre className="mt-3 max-h-40 overflow-auto rounded-lg border border-line bg-panel p-3 font-mono text-xs text-ink-2">
          {this.state.error.message}
        </pre>
        <button
          onClick={() => this.setState({ error: null })}
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-raised px-3 py-1.5 text-sm text-ink hover:border-accent/60"
        >
          <RotateCcw size={14} /> Retry
        </button>
      </div>
    );
  }
}
