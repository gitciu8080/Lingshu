import { useEffect, useState } from "react";
import { ArrowLeft, ArrowRight, Bot, Check, Coins, KeyRound, ListChecks, Rocket, Sparkles, UserCog, Wrench } from "lucide-react";
import { toast } from "sonner";
import { api, auth } from "./api";

// 首次登录全屏引导向导：欢迎 → 界面导览 → 设置中心 → 添加第一个模型 → 开始第一个会话。
// 进度存 localStorage（lingshu_onboarding_step），跳去设置页后回来可续步；
// 完成或跳过时调用 PUT /auth/onboarded 持久化标记，并写本地完成标记兜底。
const STEP_KEY = "lingshu_onboarding_step";
const DONE_KEY = "lingshu_onboarding_done";

export function onboardingDone(): void {
  localStorage.setItem(DONE_KEY, "1");
  localStorage.removeItem(STEP_KEY);
}

export function onboardingResumeStep(): number {
  const raw = Number(localStorage.getItem(STEP_KEY) || "0");
  return Number.isFinite(raw) && raw >= 0 && raw <= 4 ? raw : 0;
}

function StepDots({ total, current }: { total: number; current: number }) {
  return (
    <div className="ob-dots">
      {Array.from({ length: total }, (_, i) => (
        <i key={i} className={i === current ? "on" : i < current ? "done" : ""} />
      ))}
    </div>
  );
}

// 控制台布局示意（纯 CSS 模拟 + 编号标注）
function LayoutMock({ hot }: { hot: number }) {
  const cell = (n: number, label: string, cls: string) => (
    <div className={`ob-mock-cell ${cls} ${hot === n ? "hot" : ""}`}>
      <i>{n}</i>
      <span>{label}</span>
    </div>
  );
  return (
    <div className="ob-mock">
      <div className="ob-mock-top">
        <span className="ob-mock-brand">LINGSHU</span>
        <span className="ob-mock-chip">{hot === 4 ? "⚡ FAST" : "STANDARD"}</span>
        <span className="ob-mock-chip">⊕ ⚙ 🛠 👤</span>
      </div>
      <div className="ob-mock-body">
        {cell(1, "会话列表", "side")}
        <div className="ob-mock-center">
          {cell(2, "任务事件流", "feed")}
          {cell(5, "命令条 / 审批交互", "cmd")}
        </div>
        {cell(3, "情报面板", "side")}
      </div>
    </div>
  );
}

function SettingsMock({ hot }: { hot: number }) {
  const items: [number, string, string, typeof Bot][] = [
    [1, "大模型供应商", "添加你的 API 与模型", KeyRound],
    [2, "Agent 模型分工", "八个角色各用哪个模型", Bot],
    [3, "用量统计", "Token 消耗明细", Coins],
    [4, "账号安全", "改密 / 资料", UserCog],
  ];
  return (
    <div className="ob-cards">
      {items.map(([n, title, desc, Icon]) => (
        <div key={title} className={`ob-card ${hot === n ? "hot" : ""}`}>
          <Icon size={16} />
          <b>{title}</b>
          <small>{desc}</small>
        </div>
      ))}
    </div>
  );
}

export default function OnboardingWizard({
  onClose,
  onStartFirstMission,
}: {
  onClose: () => void;
  onStartFirstMission: () => void;
}) {
  const [step, setStep] = useState(() => onboardingResumeStep());
  const [providerCount, setProviderCount] = useState<number | null>(null);

  useEffect(() => {
    if (step >= 3) {
      api.modelProviders()
        .then((data) => setProviderCount(data.providers?.length ?? 0))
        .catch(() => setProviderCount(0));
    }
  }, [step]);

  const persistStep = (next: number) => {
    setStep(next);
    localStorage.setItem(STEP_KEY, String(next));
  };

  const finish = () => {
    onboardingDone();
    api.markOnboarded().catch(() => undefined);
    onClose();
  };

  const skip = () => { toast.success("已跳过引导，可随时在用户设置中重新了解各功能"); finish(); };

  const goSettings = () => { persistStep(3); window.location.href = "/settings"; };

  const steps = [
    // 0 欢迎
    <div key="welcome" className="ob-welcome">
      <Sparkles size={34} className="ob-spark" />
      <h2>欢迎使用灵枢</h2>
      <p>
        灵枢是一个<b>具备自主决策能力的网络安全智能体平台</b>：你下达授权目标，
        智能体团队自主完成侦察、分析、利用与报告的完整闭环。
      </p>
      <div className="ob-duo">
        <div><b>标准模式</b><small>完整渗透工作流：侦察 → 规划 → 审批 → 攻击 → 报告</small></div>
        <div><b>快速模式 ⚡</b><small>单指挥官调度专家并行解题，主打 CTF 夺旗速度</small></div>
      </div>
      <small className="ob-note">全程约 1 分钟 · 可随时跳过</small>
    </div>,
    // 1 界面导览
    <div key="ui" className="ob-body">
      <h2>认识控制台</h2>
      <LayoutMock hot={0} />
      <ul className="ob-list">
        <li><i>1</i><b>会话列表</b>：所有任务会话，点击切换，⚡FAST 徽章表示快速模式任务</li>
        <li><i>2</i><b>任务事件流</b>：智能体对话、工具调用与思考过程实时流式渲染</li>
        <li><i>3</i><b>情报面板</b>：当前任务的计划进度、雷达与 Flag 状态</li>
        <li><i>4</i><b>模式切换</b>：顶栏 STANDARD/FAST 徽章，切换新建任务的默认模式</li>
        <li><i>5</i><b>命令条</b>：向运行中的任务插话补充情报；利用审批也在这里弹出</li>
      </ul>
    </div>,
    // 2 设置中心
    <div key="settings" className="ob-body">
      <h2>用户设置中心</h2>
      <p className="ob-lead">顶栏 <UserCog size={14} style={{ verticalAlign: -2 }} /> 按钮进入，这里管理你的模型资源与账号。</p>
      <SettingsMock hot={1} />
      <ul className="ob-list compact">
        <li><b>大模型供应商</b>：添加你自己的 LLM API（密钥加密保存，仅自己可见）</li>
        <li><b>Agent 模型分工</b>：让八个智能体角色各用你指定的模型</li>
        <li><b>用量统计</b>：查看每次调用的 Token 消耗</li>
      </ul>
    </div>,
    // 3 添加第一个模型
    <div key="model" className="ob-body">
      <h2>添加你的第一个模型</h2>
      <p className="ob-lead">
        智能体由大模型驱动。添加一个供应商（如 DeepSeek / 智谱 / OpenAI 兼容网关）并启用至少一个模型后，
        才能开始第一个任务。
      </p>
      {providerCount === null ? (
        <p className="ob-note">检测可用模型中…</p>
      ) : providerCount > 0 ? (
        <div className="ob-ok"><Check size={16} /> 已检测到 {providerCount} 个可用供应商配置，可以直接开始。</div>
      ) : (
        <div className="ob-warn">尚未检测到可用模型 — 点击下方按钮，按五步向导添加（选供应商 → 填密钥 → 选模型 → 保存）。</div>
      )}
      <div className="ob-actions">
        <button type="button" className="ob-btn primary" onClick={goSettings}>
          <KeyRound size={15} /> 前往添加模型
        </button>
        <small>添加完成后回到本页，向导会从这一步继续</small>
      </div>
    </div>,
    // 4 开始第一个会话
    <div key="mission" className="ob-body">
      <h2>开始第一个任务</h2>
      <p className="ob-lead">点击左侧「新建测试任务」按钮，三步启动智能体团队：</p>
      <ul className="ob-list">
        <li><i>1</i> 选择运行模式：<b>标准模式</b>（完整流程，利用前需你批准）或<b>快速模式 ⚡</b>（跳过流程直奔夺旗）</li>
        <li><i>2</i> 填写<b>授权目标</b>（IP / 主机名）或上传附件，描述任务目标</li>
        <li><i>3</i> 点击「启动任务」——事件流将实时呈现智能体的每一步；标准模式在进入利用阶段前会弹出审批，由你决定放行方案</li>
      </ul>
      <div className="ob-actions">
        <button
          type="button"
          className="ob-btn primary"
          onClick={() => {
            if (providerCount === 0) { toast.error("请先添加一个模型供应商"); persistStep(3); return; }
            finish();
            onStartFirstMission();
          }}
        >
          <Rocket size={15} /> 立即创建第一个任务
        </button>
      </div>
      <small className="ob-note">
        <Wrench size={12} style={{ verticalAlign: -2 }} /> 提示：顶栏扳手可查看系统工具状态；所有攻击操作受授权范围与审批闸门约束。
      </small>
    </div>,
  ];

  return (
    <div className="ob-overlay" role="dialog" aria-modal="true">
      <div className="ob-modal">
        <header>
          <ListChecks size={18} />
          <b>初次使用引导</b>
          <StepDots total={5} current={step} />
          <button type="button" className="ob-skip" onClick={skip}>跳过引导</button>
        </header>
        <div className="ob-content">{steps[step]}</div>
        <footer>
          <button
            type="button"
            className="ob-btn ghost"
            disabled={step === 0}
            onClick={() => persistStep(Math.max(0, step - 1))}
          ><ArrowLeft size={14} /> 上一步</button>
          <span className="ob-step-label">{step + 1} / 5</span>
          {step < 4 ? (
            <button type="button" className="ob-btn primary" onClick={() => persistStep(step + 1)}>
              下一步 <ArrowRight size={14} />
            </button>
          ) : (
            <button type="button" className="ob-btn primary" onClick={finish}>
              <Check size={15} /> 完成引导
            </button>
          )}
        </footer>
      </div>
    </div>
  );
}
