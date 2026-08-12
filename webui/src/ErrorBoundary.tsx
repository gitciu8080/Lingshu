import { Component, ErrorInfo, ReactNode } from "react";

export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Lingshu UI render failed", error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <main className="ui-error-page">
        <section>
          <b>界面数据渲染异常</b>
          <p>{this.state.error.message || "未知前端错误"}</p>
          <button
            onClick={() => {
              localStorage.removeItem("lingshu_token");
              location.reload();
            }}
          >
            清理登录状态并重新进入
          </button>
        </section>
      </main>
    );
  }
}
