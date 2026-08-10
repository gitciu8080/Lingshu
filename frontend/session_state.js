/**
 * session_state.js — 灵枢多会话状态管理模块
 * 
 * 核心职责：
 * - JWT 认证与鉴权请求封装
 * - 会话生命周期管理（创建/切换/取消/删除）
 * - SSE 流式连接管理（fetch + ReadableStream，Bearer Token 认证）
 * - 会话列表轮询
 * - 工具函数（时间格式化、HTML 转义、阶段映射）
 * 
 * 注意：本文件不直接操作聊天界面 DOM，
 * UI 渲染由 index.html 中的回调函数处理。
 */

// ══════════════════════════════════════
//  LingShuState — 核心状态管理类
// ══════════════════════════════════════
class LingShuState {
  constructor() {
    this.token = '';
    this.sessions = [];
    this.currentSessionId = null;
    this.currentPhase = '';
    this.lastMessageSeq = 0;
    this.isAutoScroll = true;
    this.activeAgentBubbles = {}; // agent_name → DOM 元素引用

    this._sseAbortController = null;
    this._sseRetryCount = 0;
    this._sessionPollTimer = null;

    // UI 回调（由 index.html 设置）
    this.onRenderUserMessage = null;
    this.onRenderAgentMessage = null;
    this.onRenderSystemMessage = null;
    this.onRenderPhaseDivider = null;
    this.onUpdatePhaseTag = null;
    this.onSetInputState = null;
    this.onLoadSessionsDone = null;
    this.onScrollToBottom = null;
    this.onUpdatePanelHeader = null;
    this.onSessionListRender = null;
    this.onHighlightSession = null;
    this.onClearChat = null;
    this.onHideLogin = null;
    this.onShowLogin = null;

    // 工具调用记录面板回调
    this.onToolCallStart = null;      // (data) => void — 工具调用开始
    this.onToolCallDelta = null;      // (data) => void — 工具参数增量

    // 人工审批回调
    this.onApprovalRequired = null;    // (event) => void — 弹出审批模态框
    this.onApprovalResolved = null;    // (event) => void — 关闭模态框 + 显示结果

    // 作战计划清单回调
    this.onPlanUpdated = null;         // (items, phase) => void — 全量替换清单

    // 靶机信息回调
    this.onTargetInfo = null;          // (data) => void — 更新靶机信息面板
  }

  // ══════════════════════════════════════
  //  认证
  // ══════════════════════════════════════
  static get AUTH_KEY() { return 'lingshu_token'; }

  getAuthToken() {
    return localStorage.getItem(LingShuState.AUTH_KEY);
  }

  setAuthToken(t) {
    localStorage.setItem(LingShuState.AUTH_KEY, t);
    this.token = t;
  }

  clearAuthToken() {
    localStorage.removeItem(LingShuState.AUTH_KEY);
    this.token = '';
  }

  /** 统一请求封装：自动携带 Bearer Token，401 时清除令牌并跳回登录页 */
  async authFetch(url, options = {}) {
    const t = this.getAuthToken();
    const headers = Object.assign({}, options.headers);
    if (t) headers['Authorization'] = 'Bearer ' + t;
    const resp = await fetch(url, Object.assign({}, options, { headers }));
    if (resp.status === 401) {
      this.clearAuthToken();
      this.onShowLogin?.();
      throw new Error('认证已过期');
    }
    return resp;
  }

  /** 检查登录状态，成功则调用 onHideLogin 并启动轮询 */
  async checkAuth() {
    const t = this.getAuthToken();
    if (!t) { this.onShowLogin?.(); return; }
    this.token = t;
    try {
      const resp = await fetch('/auth/me', {
        headers: { 'Authorization': 'Bearer ' + t }
      });
      if (!resp.ok) { this.clearAuthToken(); this.onShowLogin?.(); return; }
      const user = await resp.json();
      this.onHideLogin?.(user);
      await this.loadSessions();
      this.startSessionPolling();
      // 页面加载/刷新后自动选中第一个会话并加载历史
      if (this.sessions.length > 0 && !this.currentSessionId) {
        const firstId = this.sessions[0].id;
        // doSwitchSession 由 index.html 定义为全局函数
        if (typeof doSwitchSession === 'function') {
          doSwitchSession(firstId);
        }
      }
    } catch {
      this.clearAuthToken();
      this.onShowLogin?.();
    }
  }

  async handleLogout() {
    try { await this.authFetch('/auth/logout', { method: 'POST' }); } catch {}
    this.clearAuthToken();
    this.stopSessionPolling();
    this.closeSSE();
    window.location.reload();
  }

  // ══════════════════════════════════════
  //  会话管理
  // ══════════════════════════════════════
  /** 拉取会话列表并触发渲染 */
  async loadSessions() {
    if (!this.getAuthToken()) return;
    try {
      const resp = await this.authFetch('/api/sessions?limit=50');
      if (!resp.ok) return;
      const data = await resp.json();
      this.sessions = data.sessions || [];
      this.onSessionListRender?.(this.sessions);
    } catch {}
  }

  /** 切换到指定会话：关 SSE → 清面板 → 加载消息 → 建 SSE */
  async switchSession(id, { loadMessages, connectSSE: doConnect }) {
    if (id === this.currentSessionId) return;
    this.closeSSE();
    this.currentSessionId = id;
    this.lastMessageSeq = 0;
    this.currentPhase = '';
    this.activeAgentBubbles = {};
    this._streamBubbles = {};
    this.onHighlightSession?.(id);
    this.onClearChat?.();

    // 加载会话详情更新标题栏
    let sessionDetail = null;
    try {
      const resp = await this.authFetch(`/api/session/${id}`);
      if (resp.ok) {
        sessionDetail = await resp.json();
        this.onUpdatePanelHeader?.(sessionDetail);
      }
    } catch {}

    // 加载历史消息
    await loadMessages(id);

    // 刷新会话列表获取最新状态（防止 is_live 过期）
    await this.loadSessions();

    // 使用会话详情或刷新后的列表判断是否活跃
    const session = this.sessions.find(s => s.id === id);
    const isLive = session ? session.is_live === true : sessionDetail?.is_live === true;
    if (isLive) {
      this.connectSSE(id);
      this.onSetInputState?.(true);
    } else {
      this.onSetInputState?.(false, '会话已结束，请新建会话');
    }
  }

  /** 创建并启动新会话 */
  async startNewSession(target, goal, model, provider, sourceSessionId = null) {
    const body = { target, goal, model, provider };
    if (sourceSessionId) body.source_session_id = sourceSessionId;
    const resp = await this.authFetch('/api/session/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || '启动失败');
    await this.loadSessions();
    return data.session_id;
  }

  /** 发送用户消息 */
  async sendMessage(content) {
    if (!this.currentSessionId) return;
    await this.authFetch(`/api/session/${this.currentSessionId}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
  }

  /** 取消运行中的会话 */
  async cancelSession(id) {
    if (!id) return;
    await this.authFetch(`/api/session/${id}/cancel`, { method: 'POST' });
    this.onRenderSystemMessage?.('已发送取消请求...');
    // 短暂延迟后刷新列表和标题栏，等待后端状态更新
    setTimeout(() => {
      this.loadSessions();
      if (this.currentSessionId === id) {
        this.onSetInputState?.(false, '会话已取消，请新建会话');
        this.onUpdatePhaseTag?.('cancelled');
      }
    }, 500);
  }

  /** 删除会话 */
  async deleteSession(id) {
    await this.authFetch(`/api/session/${id}`, { method: 'DELETE' });
    if (this.currentSessionId === id) {
      this.closeSSE();
      this.currentSessionId = null;
      this.onClearChat?.(true); // true = 重置为空状态
    }
    await this.loadSessions();
  }

  // ══════════════════════════════════════
  //  SSE 连接管理（fetch + ReadableStream）
  // ══════════════════════════════════════

  /** 建立 SSE 连接（含指数退避重连） */
  connectSSE(sessionId) {
    this.closeSSE();
    this._sseAbortController = new AbortController();
    this._sseRetryCount = 0;
    this._sseActiveSessionId = sessionId;
    this._doConnectSSE(sessionId, this._sseAbortController.signal);
  }

  async _doConnectSSE(sessionId, signal, isRetry = false) {
    try {
      if (!isRetry) {
        this._sseRetryCount = 0;
      }
      const resp = await this.authFetch(
        `/api/session/${sessionId}/stream?after_seq=${this.lastMessageSeq}`,
        { signal },
      );
      if (!resp.ok) {
        // 404 表示会话已结束，不重连
        if (resp.status === 404) return;
        throw new Error(`SSE 连接失败: ${resp.status}`);
      }
      this._sseRetryCount = 0; // 连接成功，重置计数
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const event = JSON.parse(line.slice(6));
              this.handleSSEEvent(event);
            } catch {}
          }
        }
      }
      // done=true：正常关闭（服务端结束流）
    } catch (e) {
      if (e.name === 'AbortError') return; // 主动关闭，不重连
      // 刷新后再判断会话是否仍活跃，避免本地缓存过期导致放弃重连。
      await this.loadSessions();
      const session = this.sessions.find(s => s.id === sessionId);
      const isLive = session && session.is_live === true;
      if (!isLive) return; // 会话已结束，不重连
      // 指数退避重连（最多 5 次）
      if (this._sseRetryCount < 5 && this._sseActiveSessionId === sessionId) {
        this._sseRetryCount++;
        const delay = Math.min(1000 * Math.pow(2, this._sseRetryCount - 1), 16000);
        this.onRenderSystemMessage?.(`⚠️ SSE 连接断开，${delay/1000}s 后第 ${this._sseRetryCount} 次重连...`);
        await new Promise(r => setTimeout(r, delay));
        if (this._sseActiveSessionId === sessionId && !signal.aborted) {
          this._doConnectSSE(sessionId, signal, true);
        }
      } else if (this._sseActiveSessionId === sessionId) {
        this.onRenderSystemMessage?.('❌ SSE 重连次数耗尽，请刷新页面或切换会话。');
      }
    }
  }

  /** 关闭当前 SSE 连接 */
  closeSSE() {
    this._sseActiveSessionId = null;
    this._sseRetryCount = 0;
    if (this._sseAbortController) {
      this._sseAbortController.abort();
      this._sseAbortController = null;
    }
  }

  /** SSE 事件路由 */
  handleSSEEvent(event) {
    // 防串扰：仅处理当前选中会话的事件，防止切换会话或旧 SSE 残留
    if (event.session_id && this.currentSessionId && event.session_id !== this.currentSessionId) {
      return;
    }
    if (event.seq && event.seq <= this.lastMessageSeq) {
      return;
    }
    if (event.seq) {
      this.lastMessageSeq = event.seq;
    }
    // 流式气泡累积映射：agent → { bubble, contentEl }
    if (!this._streamBubbles) this._streamBubbles = {};

    switch (event.type) {
      case 'user_message':
        this.onRenderUserMessage?.(event.content || '');
        break;

      case 'mission_start':
        this.onRenderSystemMessage?.(`🚀 目标: ${event.target || ''} | 任务: ${event.goal || ''}`);
        this.currentPhase = 'planning';
        this.onUpdatePhaseTag?.('planning');
        this.onTargetInfo?.(event);
        break;

      case 'text_start': {
        // 创建空 Agent 气泡，保存引用供 delta 追加
        const ref = this.onRenderAgentMessage?.(event.agent, '', '') || {};
        this._streamBubbles[event.agent] = ref;
        this.activeAgentBubbles[event.agent] = ref;
        break;
      }

      case 'text_delta':
        // 追加到已有气泡（用 textContent 追加，避免 HTML 注入）
        {
          const ref = this._streamBubbles[event.agent];
          if (ref && ref.contentEl) {
            ref.contentEl.textContent += event.delta || event.content || '';
            this.onScrollToBottom?.();
          }
        }
        break;

      case 'text_end': {
        // 用全文替换（经 Markdown 渲染），清除引用
        const ref = this._streamBubbles[event.agent] || this.activeAgentBubbles[event.agent];
        if (ref && ref.contentEl && event.full_text) {
          ref.contentEl.innerHTML = mdRender(event.full_text);
          this.onScrollToBottom?.();
        } else if (event.full_text) {
          this.onRenderAgentMessage?.(event.agent || 'system', event.full_text);
        }
        delete this._streamBubbles[event.agent];
        delete this.activeAgentBubbles[event.agent];
        break;
      }

      case 'thinking_start': {
        const ref = this.onRenderAgentMessage?.(event.agent, '', 'thinking') || {};
        this._streamBubbles['think_' + event.agent] = ref;
        break;
      }

      case 'thinking_delta':
        {
          const ref = this._streamBubbles['think_' + event.agent];
          if (ref && ref.contentEl) {
            ref.contentEl.textContent += event.delta || event.content || '';
            this.onScrollToBottom?.();
          }
        }
        break;

      case 'thinking_end':
        {
          const key = 'think_' + event.agent;
          const ref = this._streamBubbles[key] || this.activeAgentBubbles[event.agent];
          if (ref && ref.contentEl && event.full_text) {
            ref.contentEl.innerHTML = '<details class="thinking-collapsible" open><summary>🧠 思考过程 (点击折叠)</summary><div class="thinking-body">' + mdRender(event.full_text) + '</div></details>';
            this.onScrollToBottom?.();
          } else if (event.full_text) {
            const ref = this.onRenderAgentMessage?.(event.agent || 'system', '', 'thinking') || {};
            if (ref.contentEl) {
              ref.contentEl.innerHTML = '<details class="thinking-collapsible" open><summary>🧠 思考过程 (点击折叠)</summary><div class="thinking-body">' + mdRender(event.full_text) + '</div></details>';
            }
          }
          delete this._streamBubbles[key];
          delete this.activeAgentBubbles[event.agent];
        }
        break;

      case 'stream_snapshot': {
        const isThinking = event.stream_type === 'thinking';
        const key = isThinking ? 'think_' + event.agent : event.agent;
        let ref = this._streamBubbles[key] || this.activeAgentBubbles[event.agent];
        if (!ref || !ref.contentEl) {
          ref = this.onRenderAgentMessage?.(
            event.agent || 'system', '', isThinking ? 'thinking' : '',
          ) || {};
          this._streamBubbles[key] = ref;
        }
        if (ref.contentEl) {
          ref.contentEl.textContent = event.full_text || '';
          this.onScrollToBottom?.();
        }
        break;
      }

      case 'tool_call_start':
        // 工具调用开始 → 右侧面板展示
        this.onToolCallStart?.({ tool_call_id: event.tool_call_id, tool_name: event.tool_name, agent: event.agent });
        // 聊天面板简短提示
        this.onRenderSystemMessage?.(`🔧 [${event.agent || 'Agent'}] 调用工具: ${event.tool_name || '?'}`);
        break;

      case 'tool_call_delta':
        this.onToolCallDelta?.({ tool_call_id: event.tool_call_id, delta: event.delta || '' });
        break;

      case 'tool_call_end':
        // 工具调用结束
        break;

      case 'target_info':
        this.onTargetInfo?.(event);
        break;

      case 'phase_change':
        this.onRenderPhaseDivider?.(event.phase);
        this.currentPhase = event.phase;
        this.onUpdatePhaseTag?.(event.phase);
        // 靶机信息刷新
        this.onTargetInfo?.(event);
        break;

      case 'message': {
        const msgText = event.content || event.message || '';
        this.onRenderAgentMessage?.(event.agent || 'system', msgText);
        break;
      }

      case 'error':
        this.onRenderSystemMessage?.(`❌ 错误: ${event.message || ''}`);
        break;

      case 'mission_end':
        this.onRenderSystemMessage?.(`🏁 任务结束 (${event.status || '未知'})`);
        this.loadSessions();
        this.onSetInputState?.(false, '会话已结束，请新建会话');
        this.onUpdatePhaseTag?.(event.status || 'completed');
        break;

      case 'mission_cancelled':
        this.onRenderSystemMessage?.('⏹ 任务已被取消');
        this.loadSessions();
        this.onSetInputState?.(false, '会话已取消，请新建会话');
        this.onUpdatePhaseTag?.('cancelled');
        break;

      case 'approval_required':
        this.onRenderSystemMessage?.('⚠️ 收到攻击阶段审批请求，等待操作员决策...');
        this.onApprovalRequired?.(event);
        break;

      case 'approval_resolved':
        if (event.approved) {
          this.onRenderSystemMessage?.('✅ 审批已通过，进入攻击阶段');
        } else {
          this.onRenderSystemMessage?.('❌ 审批被拒绝');
        }
        this.onApprovalResolved?.(event);
        break;

      case 'plan_updated':
        this.onPlanUpdated?.(event.items || [], event.phase || '');
        break;

      case 'flag_found':
        this.onTargetInfo?.({ ...event, flag: event.flag || event.content });
        this.onRenderSystemMessage?.(`🚩 FLAG 已找到: ${event.flag || event.content}`);
        break;
    }
  }

  /** 追加文本到 Agent 气泡（内部方法） — 已废弃，改用 onRenderAgentMessage 直接渲染 */

  // ══════════════════════════════════════
  //  会话列表轮询
  // ══════════════════════════════════════
  startSessionPolling() {
    this.stopSessionPolling();
    this._sessionPollTimer = setInterval(() => this.loadSessions(), 10000);
  }

  stopSessionPolling() {
    if (this._sessionPollTimer) {
      clearInterval(this._sessionPollTimer);
      this._sessionPollTimer = null;
    }
  }
}

// ══════════════════════════════════════
//  工具函数（纯函数，无状态）
// ══════════════════════════════════════

/** 阶段中文名映射 */
function phaseLabel(p) {
  const map = {
    planning: '规划中', recon: '侦察', analysis: '分析',
    exploitation: '利用', post_exploitation: '后利用',
    completed: '已完成', failed: '失败', cancelled: '已取消', idle: '空闲'
  };
  return map[p] || p;
}

/** 相对时间格式化 */
function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  const diff = (now - d) / 1000;
  if (diff < 60) return '刚刚';
  if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
  if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
  if (diff < 172800) return '昨天';
  return d.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' });
}

/** HTML 转义 */
function escapeHtml(text) {
  if (!text) return '';
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, c => map[c]);
}

/** Agent 名称 → CSS 颜色类 */
function resolveAgentClass(agent) {
  const a = (agent || '').toLowerCase();
  if (a.includes('brain')) return 'brain';
  if (a.includes('recon')) return 'recon';
  if (a.includes('attack')) return 'attack';
  if (a.includes('analysis')) return 'analysis';
  if (a.includes('orchestrat')) return 'orchestrator';
  return 'system';
}

/** Agent 名称 → 状态消息 Emoji 前缀 */
function agentStatusEmoji(agent) {
  const a = (agent || '').toLowerCase();
  if (a.includes('brain')) return '🧠';
  if (a.includes('recon')) return '🔍';
  if (a.includes('attack')) return '⚔️';
  if (a.includes('analysis')) return '🧪';
  if (a.includes('orchestrat')) return '🎯';
  return '🤖';
}
