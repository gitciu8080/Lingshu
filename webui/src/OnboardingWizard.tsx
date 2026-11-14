import { useEffect, useState } from "react";
import {
  ArrowLeft, ArrowRight, Bot, BookOpen, Check, Coins, Crosshair, Database,
  FileText, KeyRound, LayoutDashboard, ListChecks, Network, Rocket, Settings,
  ShieldAlert, Sparkles, UserCog, Wrench,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "./api";

// 首次登录全屏引导向导（导航栏架构版）：
// 欢迎 → 认识导航栏 → 控制台 → 设置中心 → 添加第一个模型 → 开始第一个任务。
// 进度存 localStorage（lingshu_onboarding_step），去设置页后回来可续步；
// 完成或跳过时调用 PUT /auth/onboarded 持久化标记，并写本地完成标记兜底。
const STEP_KEY = "lingshu_onboarding_step";
const DONE_KEY = "lingshu_onboarding_done";
const STEP_TOTAL = 6;

export function onboardingDone(): void {
  localStorage.setItem(DONE_KEY, "1");
  localStorage.removeItem(STEP_KEY);
}

export function onboardingResumeStep(): number {
  const raw = Number(localStorage.getItem(STEP_KEY) || "0");
  return Number.isFinite(raw) && raw >= 0 && raw <= STEP_TOTAL - 1 ? raw : 0;
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

// 导航栏示意（对齐 NavRail 十视图；图标-only 收起态 + 编号热点）
function NavRailMock({ hot }: { hot: number[] }) {
  const items: [number, typeof LayoutDashboard][] = [
    [1, LayoutDashboard],
    [2, Crosshair],
    [3, Database],
    [3, ShieldAlert],
    [3, Network],
    [4, FileText],
    [5, UserCog],
    [5, Settings],
    [5, Wrench],
    [5, BookOpen],
  ];
  return (
    <div className="ob-rail-bar" aria-hidden>
      <span className="ob-rail-logo">灵</span>
      {items.map(([n, Icon], i) => (
        <span key={i} className={hot.includes(n) ? "hot" : ""}>
          <Icon size={12} />
          <i>{hot.includes(n) ? n : ""}</i>
        </span>
      ))}
      <span className="ob-rail-foot"><Settings size={11} /><ArrowRight size={11} style={{ transform: "rotate(90deg)" }} /></span>
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
        <span className="ob-mock-chip">左侧导航栏切换十大功能视图</span>
      </div>
      <div className="ob-mock-body">
        {cell(1, "会话列表 + 新建任务", "side")}
        <div className="ob-mock-center">
          {cell(2, "任务事件流", "feed")}
          {cell(4, "命令条 / 审批交互", "cmd")}
        </div>
        {cell(3, "任务情报面板", "side")}
      </div>
    </div>
  );
}

function SettingsMock({ hot }: { hot: number }) {
  const items: [number, string, string, typeof Bot][] = [
    [1, "大模型供应商", "添加你的 API 与模型", KeyRound],
    [2, "Agent 模型分工", "八个角色各用哪个模型", Bot],
    [3, "资产测绘引擎", "FOFA / Hunter 等 Key", Network],
    [4, "Token 用量 / 账号", "消耗明细与改密", Coins],
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
  onOpenSettings,
}: {
  onClose: () => void;
  onStartFirstMission: () => void;
  onOpenSettings: () => void;
}) {
  const [step, setStep] = useState(() => onboardingResumeStep());
  const [providerCount, setProviderCount] = useState<number | null>(null);

  useEffect(() => {
    if (step >= 4) {
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

  const skip = () => { toast.success("已跳过引导，可随时从左侧导航栏了解各功能"); finish(); };

  const goSettings = () => { persistStep(4); onOpenSettings(); };

  const steps = [
    // 0 欢迎
    <div key="welcome" className="ob-welcome">
      <Sparkles size={34} className="ob-spark" />
      <h2>欢迎使用灵枢</h2>
      <p>
        灵枢是一个<b>具备自主决策能力的网络安全智能体平台</b>：你下达授权目标，
        智能体团队自主完成测绘、侦察、分析、利用与报告的完整闭环。
      </p>
      <div className="ob-duo">
        <div><b>标准模式</b><small>完整渗透工作流：侦察 → 规划 → 审批 → 攻击 → 报告</small></div>
        <div><b>快速模式 ⚡</b><small>单指挥官调度专家并行解题，主打 CTF 夺旗速度</small></div>
      </div>
      <small className="ob-note">支持 CTF / 授权渗透 / 应急响应 / 等保测评等任务模式 · 全程约 1 分钟 · 可随时跳过</small>
    </div>,
    // 1 认识导航栏
    <div key="nav" className="ob-body ob-body-rail">
      <h2>认识导航栏</h2>
      <p className="ob-lead">左侧导航栏汇聚全部功能视图（收起只留图标，悬停看名称）：</p>
      <div className="ob-rail">
        <NavRailMock hot={[2, 4, 5]} />
        <ul className="ob-list">
          <li><i>1</i><b>仪表板</b>：全局任务态势、成功率与 Token 用量总览</li>
          <li><i>2</i><b>控制台</b>：任务会话与智能体实时活动的主战场</li>
          <li><i>3</i><b>资产三视图</b>：资产管理 / 威胁建模 / 资产测绘，从台账到攻击面</li>
          <li><i>4</i><b>发现与报告</b>：任务报告在线查看，PDF / Markdown / 证据 / 产物一键下载</li>
          <li><i>5</i><b>配置四件套</b>：Agent 设置、用户与系统设置、系统工具状态、本地知识库</li>
        </ul>
      </div>
    </div>,
    // 2 控制台
    <div key="ui" className="ob-body">
      <h2>控制台</h2>
      <p className="ob-lead">导航栏进入「控制台」——这里是任务执行的主战场：</p>
      <LayoutMock hot={0} />
      <ul className="ob-list">
        <li><i>1</i><b>会话列表</b>：所有任务会话，点击切换；「新建测试任务」按钮也在这里</li>
        <li><i>2</i><b>任务事件流</b>：智能体对话、工具调用与思考过程实时流式渲染</li>
        <li><i>3</i><b>任务情报面板</b>：当前任务的计划进度、证据与产物（点击可下载）</li>
        <li><i>4</i><b>命令条</b>：向运行中的任务插话补充情报；利用审批也在这里弹出</li>
      </ul>
    </div>,
    // 3 设置中心
    <div key="settings" className="ob-body">
      <h2>设置中心</h2>
      <p className="ob-lead">导航栏底部两组配置入口，管理你的模型资源、测绘引擎与账号。</p>
      <SettingsMock hot={1} />
      <ul className="ob-list compact">
        <li><b>用户与系统设置</b>：大模型供应商 / Token 用量 / 资产测绘引擎 / 账号安全（横向子导航切换）</li>
        <li><b>Agent 设置</b>：让八个智能体角色各用你指定的模型与思考强度</li>
      </ul>
    </div>,
    // 4 添加第一个模型
    <div key="model" className="ob-body">
      <h2>添加你的第一个模型</h2>
      <p className="ob-lead">
        智能体由大模型驱动。添加一个供应商（如 DeepSeek / 智谱 / OpenAI 兼容网关 / 本地 llama.cpp）并启用至少一个模型后，
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
        <small>添加完成后回到控制台，向导会从这一步继续</small>
      </div>
    </div>,
    // 5 开始第一个会话
    <div key="mission" className="ob-body">
      <h2>开始第一个任务</h2>
      <p className="ob-lead">点击左侧「新建测试任务」按钮，弹窗里三步启动智能体团队：</p>
      <ul className="ob-list">
        <li><i>1</i> 选择<b>运行模式</b>：标准模式（完整流程，利用前需你批准）或快速模式 ⚡（跳过流程直奔夺旗）</li>
        <li><i>2</i> 填写<b>授权目标</b>（IP / 主机名）或上传附件，按需选择任务模式（CTF / 授权渗透 / 应急响应 / 等保测评）</li>
        <li><i>3</i> 点击「启动任务」——事件流将实时呈现智能体的每一步；标准模式在进入利用阶段前会弹出审批，由你决定放行方案</li>
      </ul>
      <div className="ob-actions">
        <button
          type="button"
          className="ob-btn primary"
          onClick={() => {
            if (providerCount === 0) { toast.error("请先添加一个模型供应商"); persistStep(4); return; }
            finish();
            onStartFirstMission();
          }}
        >
          <Rocket size={15} /> 立即创建第一个任务
        </button>
      </div>
      <small className="ob-note">
        <Wrench size={12} style={{ verticalAlign: -2 }} /> 提示：导航栏「系统工具状态」可查看攻防工具就绪情况；所有攻击操作受授权范围与审批闸门约束。
      </small>
    </div>,
  ];

  return (
    <div className="ob-overlay" role="dialog" aria-modal="true">
      <div className="ob-modal">
        <header>
          <ListChecks size={18} />
          <b>初次使用引导</b>
          <StepDots total={STEP_TOTAL} current={step} />
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
          <span className="ob-step-label">{step + 1} / {STEP_TOTAL}</span>
          {step < STEP_TOTAL - 1 ? (
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
