/** Browser-only HTTP client shared by the legacy and AgentScope transports. */
(function (global) {
  'use strict';

  class ApiError extends Error {
    constructor(message, { status = 0, code = '', detail = null, response = null } = {}) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.code = code;
      this.detail = detail;
      this.response = response;
    }
  }

  class ApiClient {
    constructor({ getToken = () => '', onUnauthorized = null, fetchImpl = global.fetch.bind(global) } = {}) {
      this.getToken = getToken;
      this.onUnauthorized = onUnauthorized;
      this.fetchImpl = fetchImpl;
    }

    async raw(url, options = {}) {
      const headers = new Headers(options.headers || {});
      const token = this.getToken?.();
      if (token) headers.set('Authorization', 'Bearer ' + token);
      const response = await this.fetchImpl(url, { ...options, headers });
      if (response.status === 401) this.onUnauthorized?.(response);
      return response;
    }

    async request(method, url, body, options = {}) {
      const headers = new Headers(options.headers || {});
      const init = { ...options, method, headers };
      if (body !== undefined) {
        headers.set('Content-Type', 'application/json');
        init.body = JSON.stringify(body);
      }
      const response = await this.raw(url, init);
      const contentType = response.headers.get('content-type') || '';
      const data = response.status === 204
        ? null
        : contentType.includes('application/json')
          ? await response.json().catch(() => null)
          : await response.text().catch(() => '');
      if (!response.ok) {
        const detail = data?.detail ?? data?.error ?? data;
        const message = typeof detail === 'string'
          ? detail
          : data?.message || `请求失败 (${response.status})`;
        throw new ApiError(message, {
          status: response.status,
          code: data?.code || '',
          detail,
          response,
        });
      }
      return data;
    }

    get(url, options) { return this.request('GET', url, undefined, options); }
    post(url, body, options) { return this.request('POST', url, body, options); }
    delete(url, options) { return this.request('DELETE', url, undefined, options); }

    /** Parse fetch-based SSE as an async iterator, including multiline data frames. */
    async *sse(url, { signal, headers, ...options } = {}) {
      const response = await this.raw(url, {
        ...options,
        signal,
        headers: { Accept: 'text/event-stream', ...(headers || {}) },
      });
      if (!response.ok) {
        throw new ApiError(`SSE 连接失败: ${response.status}`, {
          status: response.status,
          response,
        });
      }
      if (!response.body) throw new ApiError('SSE 响应缺少可读流', { response });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      try {
        while (true) {
          const { done, value } = await reader.read();
          buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
          const frames = buffer.split(/\r?\n\r?\n/);
          buffer = frames.pop() || '';
          for (const frame of frames) {
            const parsed = ApiClient.parseSSEFrame(frame);
            if (parsed) yield parsed;
          }
          if (done) break;
        }
        const parsed = ApiClient.parseSSEFrame(buffer);
        if (parsed) yield parsed;
      } finally {
        reader.releaseLock();
      }
    }

    static parseSSEFrame(frame) {
      if (!frame || frame.startsWith(':')) return null;
      const result = { event: 'message', id: '', retry: null, data: null };
      const dataLines = [];
      for (const line of frame.split(/\r?\n/)) {
        if (!line || line.startsWith(':')) continue;
        const separator = line.indexOf(':');
        const field = separator < 0 ? line : line.slice(0, separator);
        let value = separator < 0 ? '' : line.slice(separator + 1);
        if (value.startsWith(' ')) value = value.slice(1);
        if (field === 'data') dataLines.push(value);
        else if (field === 'event') result.event = value;
        else if (field === 'id') result.id = value;
        else if (field === 'retry' && /^\d+$/.test(value)) result.retry = Number(value);
      }
      if (!dataLines.length) return null;
      const raw = dataLines.join('\n');
      try { result.data = JSON.parse(raw); } catch { result.data = raw; }
      return result;
    }
  }

  global.ApiError = ApiError;
  global.ApiClient = ApiClient;
})(window);
