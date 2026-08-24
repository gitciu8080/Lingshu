/**
 * session_state.js — 灵枢多会话状态管理模块
 * 
 * 核心职责：
 * - JWT 认证状态与统一 transport 管理
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
  constructor({ transport = null, useAgentScope = window.LINGSHU_AGENT_SERVICE_ENABLED === true } = {}) {
    this.token = '';
    this.sessions = [];
    this.currentSessionId = null;
    this.currentPhase = '';
    this.lastMessageSeq = 0;
    this.isAutoScroll = true;
    this.activeAgentBubbles = {}; // agent_name → DOM 元素引用
    this.deletedSessionIds = new Set();

    this._sseAbortController = null;
    this._sseRetryCount = 0;
    this._accountSseAbortController = null;
    this._sessionPollTimer = null;

    this.apiClient = new ApiClient({
      getToken: () => this.getAuthToken(),
      onUnauthorized: () => {
        this.clearAuthToken();
        this.onShowLogin?.();
      },
    });
    this.transport = transport || (useAgentScope
      ? new AgentScopeTransport(this.apiClient, {
          agentId: window.LINGSHU_AGENT_ID,
          sessionConfig: window.LINGSHU_AGENT_SESSION_CONFIG || {},
        })
      : new LegacyLingshuTransport(this.apiClient));
    this._agentEventReducer = new AgentEventReducer();

    // UI 回调（由 index.html 设置）
    this.onRenderUserMessage = null;
    this.onRenderAgentMessage = null;
    this.onRenderSystemMessage = null;
    this.onRenderExpertJoined = null;
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
    this.onSessionDeleted = null;

    // 工具调用记录面板回调
    this.onToolCallStart = null;      // (data) => void — 工具调用开始
    this.onToolCallDelta = null;      // (data) => void — 工具参数增量
    this.onToolCallComplete = null;   // (data) => void — 工具调用完整参数

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
    this.closeAccountSSE();
    localStorage.removeItem(LingShuState.AUTH_KEY);
    this.token = '';
  }

  /** 统一请求封装：自动携带 Bearer Token，401 时清除令牌并跳回登录页 */
  async authFetch(url, options = {}) {
    const resp = await this.apiClient.raw(url, options);
    if (resp.status === 401) {
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
      const resp = await this.apiClient.raw('/auth/me');
      if (!resp.ok) { this.clearAuthToken(); this.onShowLogin?.(); return; }
      const user = await resp.json();
      this.onHideLogin?.(user);
      this.connectAccountSSE();
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
    this.closeAccountSSE();
    window.location.reload();
  }

  // ══════════════════════════════════════
  //  会话管理
  // ══════════════════════════════════════
  /** 拉取会话列表并触发渲染 */
  async loadSessions() {
    if (!this.getAuthToken()) return;
    try {
      const data = await this.transport.listSessions(50);
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
    this._agentEventReducer.reset();
    this.onHighlightSession?.(id);
    this.onClearChat?.();

    // 加载会话详情更新标题栏
    let sessionDetail = null;
    try {
      sessionDetail = await this.transport.getSession(id);
      this.onUpdatePanelHeader?.(sessionDetail);
    } catch {}

    // 加载历史消息
    await loadMessages(id);

    // 刷新会话列表获取最新状态（防止 is_live 过期）
    await this.loadSessions();

    // 使用会话详情或刷新后的列表判断是否活跃
    const session = this.sessions.find(s => s.id === id);
    const terminalPhases = new Set(['completed', 'failed', 'cancelled']);
    const isStandardSession = this.transport.kind === 'agentscope'
      && this.transport.isAgentScopeSession(id);
    const standardMissionOpen = isStandardSession
      && sessionDetail?.is_live === true
      && !terminalPhases.has(String(sessionDetail?.phase || '').toLowerCase());
    const isLive = isStandardSession
      ? standardMissionOpen
      : (session ? session.is_live === true : sessionDetail?.is_live === true);
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
    const data = await this.transport.createSession(body);
    await this.loadSessions();
    return data.session_id;
  }

  /** 发送用户消息（运行时自动中断当前操作并注入指令） */
  async sendMessage(content) {
    if (!this.currentSessionId) return;
    const data = await this.sendSessionMessage(this.currentSessionId, content) || {};
    if (data.status === 'steering') {
      this.onRenderSystemMessage?.('⚡ 指令已中断当前操作并注入，即将继续执行……');
    }
  }

  /** 立即停止运行中的会话（后端立即生效，进程清理在后台完成） */
  async cancelSession(id) {
    if (!id) return;
    // 立即反馈：先关闭 SSE、禁用输入，不等后台清理
    this.closeSSE();
    this.onSetInputState?.(false, '会话已停止，请新建会话');
    this.onUpdatePhaseTag?.('cancelled');
    this.onApprovalResolved?.({ approved: false, cancelled: true, session_id: id });
    this.onRenderSystemMessage?.('⏹ 正在停止任务...');
    try {
      await this.transport.interrupt(id);
    } catch (e) {
      // 即使请求失败也保持停止态，避免误报运行中
      this.onRenderSystemMessage?.('已本地停止，后台清理请稍候: ' + e.message);
    }
    await this.loadSessions();
    this.onRenderSystemMessage?.('✅ 任务已停止，后台进程正在清理');
  }

  /** 删除会话 */
  async deleteSession(id) {
    this.deletedSessionIds.add(id);
    if (this.currentSessionId === id) {
      this.closeSSE();
      this.currentSessionId = null;
      this.onSessionDeleted?.(id);
      this.onClearChat?.(true); // true = 重置为空状态
    }
    try {
      await this.transport.deleteSession(id);
      await this.loadSessions();
    } catch (error) {
      if (error.status === 404) {
        await this.loadSessions();
        return;
      }
      this.deletedSessionIds.delete(id);
      throw error;
    }
  }

  getSession(id) {
    return this.transport.getSession(id);
  }

  getMessages(id, options) {
    return this.transport.getMessages(id, options);
  }

  sendSessionMessage(id, content) {
    return this.transport.sendMessage(id, content);
  }

  getPendingApproval(id) {
    return this.transport.getPendingApproval(id);
  }

  primeHistoryMessage(message) {
    if (this.transport.kind === 'agentscope') {
      this._agentEventReducer.primeHistory(message);
    }
  }

  restoreStreamSnapshots(snapshots) {
    if (!Array.isArray(snapshots)) return;
    for (const snapshot of snapshots) {
      for (const event of this._agentEventReducer.primeSnapshot(snapshot)) {
        this._handleUIEvent(event);
      }
    }
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
      for await (const frame of this.transport.stream(sessionId, {
        afterSeq: this.lastMessageSeq,
        signal,
      })) {
        this._sseRetryCount = 0; // 收到事件表示连接成功，重置计数
        if (frame.data && typeof frame.data === 'object') this.handleSSEEvent(frame.data);
      }
      // done=true：正常关闭（服务端结束流）
    } catch (e) {
      if (e.name === 'AbortError') return; // 主动关闭，不重连
      if (e.status === 404) return; // 会话已结束，不重连
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

  /** 订阅同一账户下所有任务的阶段变化，用于跨页面同步。 */
  connectAccountSSE() {
    this.closeAccountSSE();
    this._accountSseAbortController = new AbortController();
    this._doConnectAccountSSE(this._accountSseAbortController.signal);
  }

  async _doConnectAccountSSE(signal) {
    let retry = 0;
    while (!signal.aborted && this.getAuthToken()) {
      try {
        for await (const frame of this.transport.accountStream({ signal })) {
          retry = 0;
          const event = frame.data;
          if (!event || !['account_phase_change', 'account_session_title'].includes(event.type)) continue;
          const session = this.sessions.find(item => item.id === event.session_id);
          if (session && event.type === 'account_phase_change') session.phase = event.phase;
          if (session && event.type === 'account_session_title') session.title = event.title;
          this.onSessionListRender?.(this.sessions);
          if (event.type === 'account_session_title' && event.session_id === this.currentSessionId && session) {
            this.onUpdatePanelHeader?.(session);
          }
          if (event.type === 'account_phase_change' && event.session_id === this.currentSessionId && event.phase) {
            this.currentPhase = event.phase;
            this.onUpdatePhaseTag?.(event.phase);
          }
        }
      } catch (error) {
        if (error.name === 'AbortError' || error.status === 401) return;
      }
      if (signal.aborted) return;
      retry++;
      await new Promise(resolve => setTimeout(resolve, Math.min(1000 * 2 ** (retry - 1), 16000)));
    }
  }

  closeAccountSSE() {
    if (this._accountSseAbortController) {
      this._accountSseAbortController.abort();
      this._accountSseAbortController = null;
    }
  }

  /** SSE 事件路由 */
  handleSSEEvent(event) {
    if (
      this.transport.kind === 'agentscope'
      && this.transport.isAgentScopeSession(this.currentSessionId)
    ) {
      for (const adaptedEvent of this._agentEventReducer.reduce(event)) {
        this._handleUIEvent(adaptedEvent);
      }
      return;
    }
    this._handleUIEvent(event);
  }

  /** 已归一化事件到现有 UI 回调的唯一 reducer 边界。 */
  _handleUIEvent(event) {
    // 防串扰：仅处理当前选中会话的事件，防止切换会话或旧 SSE 残留
    if (event.session_id && (
      this.deletedSessionIds.has(event.session_id)
      || event.session_id !== this.currentSessionId
    )) {
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
      case 'session_deleted':
        this.deletedSessionIds.add(event.session_id);
        this.closeSSE();
        this.currentSessionId = null;
        this.onSessionDeleted?.(event.session_id);
        this.onClearChat?.(true);
        this.loadSessions();
        break;

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
        const key = event.reply_id && event.block_id ? `${event.reply_id}:${event.block_id}` : event.agent;
        this._streamBubbles[key] = ref;
        this.activeAgentBubbles[key] = ref;
        break;
      }

      case 'text_delta':
        // 追加到已有气泡（用 textContent 追加，避免 HTML 注入）
        {
          const key = event.reply_id && event.block_id ? `${event.reply_id}:${event.block_id}` : event.agent;
          const ref = this._streamBubbles[key];
          if (ref && ref.contentEl) {
            ref.contentEl.textContent += event.delta || event.content || '';
            this.onScrollToBottom?.();
          }
        }
        break;

      case 'text_end': {
        // 用全文替换（经 Markdown 渲染），清除引用
        const key = event.reply_id && event.block_id ? `${event.reply_id}:${event.block_id}` : event.agent;
        const ref = this._streamBubbles[key] || this.activeAgentBubbles[key];
        if (event.duplicate) {
          ref?.bubble?.remove();
        } else if (ref && ref.contentEl && event.full_text) {
          ref.contentEl.innerHTML = mdRender(event.full_text);
          this.onScrollToBottom?.();
        } else if (event.full_text) {
          this.onRenderAgentMessage?.(event.agent || 'system', event.full_text);
        } else if (ref && ref.bubble && !(ref.contentEl && (ref.contentEl.textContent || '').trim())) {
          // 无内容（空气泡）：移除，避免 web 端出现空消息
          ref.bubble.remove();
        }
        delete this._streamBubbles[key];
        delete this.activeAgentBubbles[key];
        break;
      }

      case 'thinking_start': {
        const html = '<details class="thinking-collapsible"><summary>🧠 思考过程 (点击展开)</summary><div class="thinking-body"></div></details>';
        const ref = this.onRenderAgentMessage?.(event.agent, html, 'thinking', false, true) || {};
        ref.contentEl = ref.bubble?.querySelector('.thinking-body') || ref.contentEl;
        const identity = event.reply_id && event.block_id ? `${event.reply_id}:${event.block_id}` : event.agent;
        this._streamBubbles['think_' + identity] = ref;
        break;
      }

      case 'thinking_delta':
        {
          const identity = event.reply_id && event.block_id ? `${event.reply_id}:${event.block_id}` : event.agent;
          const ref = this._streamBubbles['think_' + identity];
          if (ref && ref.contentEl) {
            ref.contentEl.textContent += event.delta || event.content || '';
            this.onScrollToBottom?.();
          }
        }
        break;

      case 'thinking_end':
        {
          const identity = event.reply_id && event.block_id ? `${event.reply_id}:${event.block_id}` : event.agent;
          const key = 'think_' + identity;
          const ref = this._streamBubbles[key] || this.activeAgentBubbles[identity];
          if (event.duplicate) {
            ref?.bubble?.remove();
          } else if (ref && ref.contentEl && event.full_text) {
            ref.contentEl.innerHTML = mdRender(event.full_text);
            this.onScrollToBottom?.();
          } else if (event.full_text) {
            const html = '<details class="thinking-collapsible"><summary>🧠 思考过程 (点击展开)</summary><div class="thinking-body">' + mdRender(event.full_text) + '</div></details>';
            this.onRenderAgentMessage?.(event.agent || 'system', html, 'thinking', false, true);
          } else if (ref && ref.bubble && !(ref.contentEl && (ref.contentEl.textContent || '').trim())) {
            // 空思考块（无内容）：仅移除确实为空的空气泡，避免误删同 agent 有内容的文本气泡
            ref.bubble.remove();
          }
          delete this._streamBubbles[key];
          delete this.activeAgentBubbles[identity];
        }
        break;

      case 'stream_snapshot': {
        const isThinking = event.stream_type === 'thinking';
        const key = isThinking ? 'think_' + event.agent : event.agent;
        let ref = this._streamBubbles[key] || this.activeAgentBubbles[event.agent];
        if (!ref || !ref.contentEl) {
          const html = isThinking
            ? '<details class="thinking-collapsible"><summary>🧠 思考过程 (点击展开)</summary><div class="thinking-body"></div></details>'
            : '';
          ref = this.onRenderAgentMessage?.(
            event.agent || 'system', html, isThinking ? 'thinking' : '', false, isThinking,
          ) || {};
          if (isThinking) {
            ref.contentEl = ref.bubble?.querySelector('.thinking-body') || ref.contentEl;
          }
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
        this.onToolCallComplete?.({
          tool_call_id: event.tool_call_id,
          tool_name: event.tool_name,
          agent: event.agent,
          full_args: event.full_args || '',
        });
        break;

      case 'tool_call_snapshot':
        this.onToolCallStart?.({
          tool_call_id: event.tool_call_id,
          tool_name: event.tool_name,
          agent: event.agent,
        });
        this.onToolCallComplete?.({
          tool_call_id: event.tool_call_id,
          tool_name: event.tool_name,
          agent: event.agent,
          full_args: event.full_args || '',
        });
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

      case 'session_title': {
        const session = this.sessions.find(item => item.id === this.currentSessionId);
        if (session) session.title = event.title;
        this.onSessionListRender?.(this.sessions);
        if (session) this.onUpdatePanelHeader?.(session);
        break;
      }

      case 'expert_joined':
        if (this.onRenderExpertJoined) {
          this.onRenderExpertJoined(event.expert_name || event.agent || '安全专家');
        } else {
          this.onRenderSystemMessage?.(`【专家加入会话】${event.expert_name || event.agent || '安全专家'}`);
        }
        break;

      case 'message': {
        const msgText = event.content || event.message || '';
        if (!(msgText || '').trim()) {
          // 空最终消息不渲染，避免空气泡
          break;
        }
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
    // 30s 低频全量刷新（原 10s）；新会话/切换由主动 loadSessions 触发，
    // 降低轮询请求频率，缓解 3 会话并发时的请求堆积。
    this._sessionPollTimer = setInterval(() => this.loadSessions(), 30000);
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

/** 将后端 UTC 时间转换为本地具体时间。 */
function formatTime(ts) {
  if (!ts) return '';
  const raw = String(ts).trim();
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw);
  const normalized = hasTimezone ? raw : raw.replace(' ', 'T') + 'Z';
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return raw;
  return d.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
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
  if (a.includes('brain') || a.includes('战略规划')) return 'brain';
  if (a.includes('recon') || a.includes('侦察') || a.includes('文件分析')) return 'recon';
  if (a.includes('attack') || a.includes('渗透') || a.includes('利用专家') || a.includes('安全验证')) return 'attack';
  if (a.includes('analysis') || a.includes('研判') || a.includes('密码分析') || a.includes('逆向程序')) return 'analysis';
  if (a.includes('orchestrat') || a.includes('行动指挥')) return 'orchestrator';
  return 'system';
}

/** Agent 名称 → 状态消息 Emoji 前缀 */
function agentStatusEmoji(agent) {
  const a = (agent || '').toLowerCase();
  if (a.includes('brain') || a.includes('战略规划')) return '🧠';
  if (a.includes('recon') || a.includes('侦察') || a.includes('文件分析')) return '🔍';
  if (a.includes('attack') || a.includes('渗透') || a.includes('利用专家')) return '⚔️';
  if (a.includes('逆向程序')) return '🧩';
  if (a.includes('analysis') || a.includes('研判') || a.includes('密码分析')) return '🧪';
  if (a.includes('orchestrat') || a.includes('行动指挥')) return '🎯';
  return '🤖';
}
