/** Uniform session transport implementations for the current and AgentScope APIs. */
(function (global) {
  'use strict';

  const query = (values) => {
    const params = new URLSearchParams();
    Object.entries(values).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') params.set(key, value);
    });
    const encoded = params.toString();
    return encoded ? '?' + encoded : '';
  };

  class LegacyLingshuTransport {
    constructor(client) { this.client = client; this.kind = 'legacy'; }
    listSessions(limit = 50) { return this.client.get('/api/sessions' + query({ limit })); }
    getSession(id) { return this.client.get(`/api/session/${encodeURIComponent(id)}`); }
    createSession(options) { return this.client.post('/api/session/start', options); }
    sendMessage(id, content) {
      return this.client.post(`/api/session/${encodeURIComponent(id)}/message`, { content });
    }
    getMessages(id, { afterSeq = 0, limit = 500 } = {}) {
      return this.client.get(`/api/session/${encodeURIComponent(id)}/messages` + query({ after_seq: afterSeq, limit }));
    }
    getStatus(id) { return this.getSession(id); }
    getPendingApproval(id) { return this.client.get(`/api/session/${encodeURIComponent(id)}/pending_approval`); }
    interrupt(id) { return this.client.post(`/api/session/${encodeURIComponent(id)}/cancel`); }
    deleteSession(id) { return this.client.delete(`/api/session/${encodeURIComponent(id)}`); }
    stream(id, { afterSeq = 0, signal } = {}) {
      return this.client.sse(`/api/session/${encodeURIComponent(id)}/stream` + query({ after_seq: afterSeq }), { signal });
    }
    accountStream({ signal } = {}) {
      return this.client.sse('/api/agent-service/account/stream', { signal });
    }
  }

  class AgentScopeTransport {
    constructor(client, { agentId, sessionConfig = {} } = {}) {
      this.client = client;
      this.agentId = agentId || '';
      this.sessionConfig = sessionConfig;
      this.kind = 'agentscope';
      this.sessionBackends = new Map();
    }

    async _ensureAgentId() {
      if (this.agentId) return this.agentId;
      const config = await this.client.get('/api/agent-service/config');
      this.agentId = config.agent_id || '';
      return this._requireAgentId();
    }

    _requireAgentId() {
      if (!this.agentId) throw new Error('AgentScope transport 缺少 LINGSHU_AGENT_ID');
      return this.agentId;
    }

    async listSessions(limit = 50) {
      await this._ensureAgentId();
      const [nativeData, legacyData] = await Promise.all([
        this.client.get('/agentscope/sessions/' + query({
          agent_id: this._requireAgentId(),
        })),
        this.client.get('/api/sessions' + query({ limit: Math.max(limit, 5000) })),
      ]);
      const nativeSessions = (Array.isArray(nativeData) ? nativeData : nativeData?.sessions || nativeData?.items || [])
        .map(session => ({ ...this._normalizeSession(session), backend: 'agentscope' }));
      const legacySessions = (legacyData?.sessions || []).map(session => ({ ...session, backend: 'legacy' }));
      const merged = new Map();
      legacySessions.forEach(session => merged.set(session.id, session));
      nativeSessions.forEach(session => {
        const legacy = merged.get(session.id);
        merged.set(session.id, legacy ? {
          ...legacy,
          ...session,
          title: legacy.title || session.title,
          target: legacy.target || session.target,
          backend: 'hybrid',
        } : session);
      });
      const timestamp = value => {
        const raw = String(value || '');
        const match = raw.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
        return match
          ? Date.UTC(...match.slice(1).map(Number).map((part, index) => index === 1 ? part - 1 : part))
          : 0;
      };
      const sessions = [...merged.values()]
        .sort((a, b) => timestamp(b.created_at) - timestamp(a.created_at));
      sessions.forEach(session => this.sessionBackends.set(session.id, session.backend));
      return { sessions };
    }

    _backend(id) { return this.sessionBackends.get(id) || 'unknown'; }
    isAgentScopeSession(id) { return ['agentscope', 'hybrid'].includes(this._backend(id)); }
    usesLegacyHistory(id) { return ['legacy', 'hybrid'].includes(this._backend(id)); }

    async _resolveBackend(id) {
      const known = this._backend(id);
      if (known !== 'unknown') return known;
      await this.listSessions(200);
      return this._backend(id);
    }

    async getSession(id) {
      const backend = await this._resolveBackend(id);
      if (backend === 'legacy') {
        return { ...(await this.client.get(`/api/session/${encodeURIComponent(id)}`)), backend };
      }
      const [list, status, mission] = await Promise.all([
        this.listSessions(100).catch(() => ({ sessions: [] })),
        this.getStatus(id),
        this.client.get(`/api/agent-service/sessions/${encodeURIComponent(id)}/mission`).catch(() => ({})),
      ]);
      return { ...(list.sessions.find(session => session.id === id) || { id }), ...status, ...mission, backend };
    }

    async createSession(options) {
      const prepared = await this.client.post('/api/agent-service/prepare', {
        provider: options.provider || 'deepseek',
        model: options.model || 'Min',
        source_session_id: options.source_session_id || null,
      });
      this.agentId = prepared.agent_id;
      const body = {
        ...this.sessionConfig,
        agent_id: this._requireAgentId(),
        name: '安全测试任务',
        chat_model_config: prepared.chat_model_config,
      };
      const created = await this.client.post('/agentscope/sessions/', body);
      const sessionId = created.session_id || created.id;
      await this.client.post(`/api/agent-service/sessions/${encodeURIComponent(sessionId)}/mirror`, {
        target: options.target,
        goal: options.goal || '获取 Flag',
        provider: options.provider || 'deepseek',
        model: options.model || 'Min',
      });
      this.sessionBackends.set(sessionId, 'hybrid');
      const content = options.goal || '获取 Flag';
      await this.client.post('/agentscope/chat/', {
        agent_id: this._requireAgentId(),
        session_id: sessionId,
        input: {
          name: 'user',
          role: 'user',
          content: [{ type: 'text', text: String(content) }],
          metadata: {
            lingshu: {
              target: options.target,
              goal: options.goal,
              provider: options.provider,
              model_ver: options.model,
              source_session_id: options.source_session_id || null,
              initial_context: prepared.initial_context || null,
            },
          },
        },
      });
      for (let attempt = 0; attempt < 20; attempt++) {
        const status = await this.getStatus(sessionId).catch(() => null);
        if (status?.is_live) break;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      return { ...created, session_id: sessionId };
    }

    async sendMessage(id, content) {
      if (await this._resolveBackend(id) === 'legacy') {
        return this.client.post(`/api/session/${encodeURIComponent(id)}/message`, { content });
      }
      return this.client.post(`/api/agent-service/sessions/${encodeURIComponent(id)}/input`, { content });
    }

    async getMessages(id, { before = '', afterSeq = 0, limit = 200 } = {}) {
      if (['legacy', 'hybrid'].includes(await this._resolveBackend(id))) {
        return this.client.get(`/api/session/${encodeURIComponent(id)}/messages` + query({
          after_seq: Number(afterSeq || before || 0),
          limit: Math.max(limit, 500),
        }));
      }
      const pageLimit = Math.min(Math.max(1, limit), 200);
      const data = await this.client.get(`/agentscope/sessions/${encodeURIComponent(id)}/messages` + query({
        agent_id: this._requireAgentId(), before, limit: pageLimit,
      }));
      const source = Array.isArray(data) ? data : data?.messages || data?.items || [];
      return {
        messages: source.map((message, index) => this._normalizeMessage(message, index)),
        is_running: data?.is_running === true,
        has_more: data?.has_more === true,
        before: source[0]?.id || '',
        page_limit: pageLimit,
      };
    }

    async getStatus(id) {
      if (await this._resolveBackend(id) === 'legacy') {
        return this.client.get(`/api/session/${encodeURIComponent(id)}`);
      }
      const data = await this.client.get(`/agentscope/sessions/${encodeURIComponent(id)}/status` + query({
        agent_id: this._requireAgentId(),
      }));
      const status = data?.status || data?.state || '';
      return {
        ...data,
        id,
        status,
        is_live: ['running', 'awaiting_permission', 'awaiting_external_result'].includes(String(status).toLowerCase()),
      };
    }

    getPendingApproval(id) {
      return this._resolveBackend(id).then(backend => backend === 'legacy'
        ? this.client.get(`/api/session/${encodeURIComponent(id)}/pending_approval`)
        : this.client.get(`/api/agent-service/sessions/${encodeURIComponent(id)}/pending-approval`));
    }

    async interrupt(id) {
      if (await this._resolveBackend(id) === 'legacy') {
        return this.client.post(`/api/session/${encodeURIComponent(id)}/cancel`);
      }
      return this.client.post(`/api/agent-service/sessions/${encodeURIComponent(id)}/interrupt`);
    }

    async deleteSession(id) {
      const backend = await this._resolveBackend(id);
      if (backend === 'legacy') {
        await this.client.delete(`/api/session/${encodeURIComponent(id)}`);
        this.sessionBackends.delete(id);
        return;
      }
      const result = await this.client.delete(`/api/agent-service/sessions/${encodeURIComponent(id)}`);
      this.sessionBackends.delete(id);
      return result;
    }

    stream(id, { afterSeq = 0, signal } = {}) {
      const backend = this._backend(id);
      if (backend === 'legacy') {
        return this.client.sse(`/api/session/${encodeURIComponent(id)}/stream` + query({ after_seq: afterSeq }), { signal });
      }
      return this.client.sse(`/agentscope/sessions/${encodeURIComponent(id)}/stream` + query({
        agent_id: this._requireAgentId(),
      }), { signal });
    }

    accountStream({ signal } = {}) {
      return this.client.sse('/api/agent-service/account/stream', { signal });
    }

    _normalizeSession(view) {
      const session = view.session || view;
      const status = view.status || session.status || '';
      const name = session.config?.name || session.name;
      return {
        ...session,
        ...view,
        id: session.id || session.session_id,
        title: session.title || name,
        target: session.target || name,
        is_live: view.is_running ?? session.is_live ?? status === 'running',
      };
    }

    _normalizeMessage(message, index) {
      const blocks = Array.isArray(message.content) ? message.content : [];
      const text = blocks.filter(block => block?.type === 'text').map(block => block.text || '').join('\n');
      let lastAgent = message.name;
      const nativeBlocks = blocks.map(block => {
        const decoded = this._agentFromBlockId(block?.id);
        if (decoded) lastAgent = decoded;
        return { ...block, agent: decoded || lastAgent || message.name };
      });
      return {
        ...message,
        seq: message.seq || index + 1,
        agent_name: message.name,
        content: typeof message.content === 'string' ? message.content : text,
        native_blocks: nativeBlocks,
        event_type: 'agentscope_message',
      };
    }

    _agentFromBlockId(blockId) {
      const id = String(blockId || '');
      const match = id.match(/^lingshu\.([A-Za-z0-9_-]+)\.(?:text|thinking|tool|summary)\./);
      if (match) {
        try {
          const base64 = match[1].replace(/-/g, '+').replace(/_/g, '/');
          const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
          return decodeURIComponent([...atob(padded)].map(char =>
            '%' + char.charCodeAt(0).toString(16).padStart(2, '0')
          ).join(''));
        } catch {}
      }
      const legacy = id.match(/^(?:text|thinking)-(Brain|Recon|Attack|Analysis|Reserve|Orchestrator|ScopeAuditor|ArtifactTriage|system)-/);
      return legacy ? legacy[1] : '';
    }
  }

  class AgentEventReducer {
    constructor() { this.reset(); }
    reset() {
      this.replies = new Map();
      this.blocks = new Map();
      this.tools = new Map();
      this.historySourceIds = new Set();
    }

    primeHistory(message) {
      if (message?.source_id) this.historySourceIds.add(String(message.source_id));
    }

    primeSnapshot(snapshot) {
      if (!snapshot?.reply_id || !snapshot?.block_id) return [];
      if (this.historySourceIds.has(String(snapshot.block_id))) return [];
      const kind = snapshot.stream_type === 'thinking' ? 'thinking' : 'text';
      const blockKey = `${snapshot.reply_id}:${snapshot.block_id}`;
      const block = {
        kind,
        agent: snapshot.agent_name || 'Lingshu',
        text: snapshot.content || '',
        replyId: snapshot.reply_id,
        blockId: snapshot.block_id,
        snapshotAt: snapshot.updated_at || '',
      };
      this.blocks.set(blockKey, block);
      return [
        { type: `${kind}_start`, agent: block.agent, reply_id: block.replyId, block_id: block.blockId },
        { type: `${kind}_delta`, agent: block.agent, delta: block.text, reply_id: block.replyId, block_id: block.blockId },
      ];
    }

    reduce(event) {
      if (!event || typeof event !== 'object') return [];
      const type = String(event.type || event.event || '').toUpperCase();
      const replyId = event.reply_id || event.replyId || '';
      const reply = this.replies.get(replyId) || { agent: event.name || event.agent || 'system' };
      const agent = event.agent || event.metadata?.agent || event.name || reply.agent || 'system';
      const blockId = event.block_id || event.blockId || '';
      const toolId = event.tool_call_id || event.toolCallId || blockId;
      const blockKey = `${replyId}:${blockId}`;
      const toolKey = `${replyId}:${toolId}`;
      const uiToolId = replyId ? `${replyId}:${toolId}` : toolId;

      if (type === 'REPLY_START') {
        this.replies.set(replyId, { agent });
        return [];
      }
      if (type === 'REPLY_END') {
        const output = [];
        for (const [key, block] of this.blocks) {
          if (!key.startsWith(replyId + ':')) continue;
          output.push(this._endBlock(block));
          this.blocks.delete(key);
        }
        this.replies.delete(replyId);
        if (event.finished_reason === 'error') {
          output.push({ type: 'error', message: event.error?.message || event.error || 'Agent 回复失败' });
        }
        return output.filter(Boolean);
      }
      if (type === 'TEXT_BLOCK_START' || type === 'THINKING_BLOCK_START') {
        const kind = type.startsWith('THINKING') ? 'thinking' : 'text';
        const existing = this.blocks.get(blockKey);
        if (existing?.snapshotAt && String(event.created_at || '') <= existing.snapshotAt) return [];
        if (existing) return [];
        const replayed = this.historySourceIds.has(String(blockId));
        this.blocks.set(blockKey, { kind, agent, text: '', replyId, blockId, replayed });
        if (replayed) return [];
        return [{ type: `${kind}_start`, agent, reply_id: replyId, block_id: blockId }];
      }
      if (type === 'TEXT_BLOCK_DELTA' || type === 'THINKING_BLOCK_DELTA') {
        const kind = type.startsWith('THINKING') ? 'thinking' : 'text';
        const existing = this.blocks.get(blockKey);
        if (existing?.snapshotAt && String(event.created_at || '') <= existing.snapshotAt) return [];
        const block = existing || { kind, agent, text: '', replyId, blockId };
        block.text += event.delta || '';
        this.blocks.set(blockKey, block);
        if (block.replayed) return [];
        const deltaEvent = { type: `${kind}_delta`, agent: block.agent, delta: event.delta || '', reply_id: replyId, block_id: blockId };
        return existing
          ? [deltaEvent]
          : [
              { type: `${kind}_start`, agent: block.agent, reply_id: replyId, block_id: blockId },
              deltaEvent,
            ];
      }
      if (type === 'TEXT_BLOCK_END' || type === 'THINKING_BLOCK_END') {
        const block = this.blocks.get(blockKey);
        this.blocks.delete(blockKey);
        if (block?.replayed) return [];
        return block ? [this._endBlock(block, replyId, blockId)] : [];
      }
      if (type === 'TOOL_CALL_START') {
        const tool = {
          agent,
          name: event.tool_call_name || event.tool_name || event.name || '?',
          input: '',
          output: '',
          replayed: this.historySourceIds.has(String(toolId)),
        };
        this.tools.set(toolKey, tool);
        if (tool.replayed) return [];
        return [{ type: 'tool_call_start', agent, tool_call_id: uiToolId, native_tool_call_id: toolId, tool_name: tool.name, reply_id: replyId }];
      }
      if (type === 'TOOL_CALL_DELTA') {
        const tool = this.tools.get(toolKey) || { agent, name: event.tool_call_name || '?', input: '', output: '' };
        tool.input += event.delta || '';
        this.tools.set(toolKey, tool);
        if (tool.replayed) return [];
        return [{ type: 'tool_call_delta', tool_call_id: uiToolId, native_tool_call_id: toolId, delta: event.delta || '', reply_id: replyId }];
      }
      if (type === 'TOOL_CALL_END') {
        const tool = this.tools.get(toolKey);
        if (tool?.replayed) return [];
        return tool ? [{ type: 'tool_call_end', agent: tool.agent, tool_call_id: uiToolId, native_tool_call_id: toolId, tool_name: tool.name, full_args: tool.input, reply_id: replyId }] : [];
      }
      if (type === 'TOOL_RESULT_START') {
        const tool = this.tools.get(toolKey) || { agent, name: event.tool_call_name || event.tool_name || '?', input: '', output: '' };
        tool.output = '';
        this.tools.set(toolKey, tool);
        return [];
      }
      if (type === 'TOOL_RESULT_TEXT_DELTA') {
        const tool = this.tools.get(toolKey) || { agent, name: event.tool_call_name || '?', input: '', output: '' };
        tool.output += event.delta || '';
        this.tools.set(toolKey, tool);
        if (tool.replayed) return [];
        return [];
      }
      if (type === 'TOOL_RESULT_DATA_DELTA') {
        const tool = this.tools.get(toolKey) || { agent, name: event.tool_call_name || '?', input: '', output: '' };
        const data = event.url || (event.data ? `[${event.media_type || 'data'}: base64]` : '');
        tool.output += (tool.output ? '\n' : '') + data;
        this.tools.set(toolKey, tool);
        return [];
      }
      if (type === 'TOOL_RESULT_END') {
        const tool = this.tools.get(toolKey);
        this.tools.delete(toolKey);
        if (tool?.replayed) return [];
        return tool ? [{
          type: 'tool_call_end', agent: tool.agent, tool_call_id: uiToolId, native_tool_call_id: toolId, tool_name: tool.name,
          full_args: tool.input, tool_result: tool.output, tool_result_state: event.state, reply_id: replyId,
        }] : [];
      }
      if (type === 'CUSTOM' || type === 'CUSTOM_EVENT') {
        const value = event.value && typeof event.value === 'object' ? event.value : {};
        const customType = value.type || value.legacy_type || event.name || 'custom_event';
        if (this.historySourceIds.has(String(event.id || ''))) return [];
        return [{
          ...value,
          type: customType,
          reply_id: replyId,
        }];
      }
      return [];
    }

    _endBlock(block, replyId = block.replyId || '', blockId = block.blockId || '') {
      return {
        type: `${block.kind}_end`, agent: block.agent, full_text: block.text,
        reply_id: replyId, block_id: blockId,
        duplicate: this.historySourceIds.has(String(blockId)),
      };
    }
  }

  global.LegacyLingshuTransport = LegacyLingshuTransport;
  global.AgentScopeTransport = AgentScopeTransport;
  global.AgentEventReducer = AgentEventReducer;
})(window);
