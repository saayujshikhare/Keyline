// Thin fetch wrapper around the server's JSON API.
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function createApi(base = '') {
  async function call(method, path, { token, body, signal } = {}) {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = 'Bearer ' + token;
    let res;
    try {
      res = await fetch(base + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
    } catch (e) {
      if (e?.name === 'AbortError') throw e;
      throw new ApiError(0, 'Cannot reach the server');
    }
    let data = null;
    try { data = await res.json(); } catch { /* empty or non-JSON body */ }
    if (!res.ok) throw new ApiError(res.status, data?.error || `Request failed (${res.status})`);
    return data;
  }

  return {
    createAccount: (uid, auth) => call('POST', '/api/account', { body: { uid, auth } }),
    login: (uid, auth) => call('POST', '/api/login', { body: { uid, auth } }),
    putVault: (token, vault, version) => call('PUT', '/api/vault', { token, body: { vault, version } }),
    changePassword: (token, body) => call('POST', '/api/account/password', { token, body }),
    deleteAccount: (token) => call('DELETE', '/api/account', { token }),
    createMailbox: (token, body) => call('POST', '/api/mailbox', { token, body }),
    openMailbox: (key, secret) => call('POST', '/api/mailbox/open', { body: { key, secret } }),
    deleteMailbox: (token) => call('DELETE', '/api/mailbox', { token }),
    lookup: (token, key) => call('GET', '/api/lookup/' + encodeURIComponent(key), { token }),
    send: (token, to, blob) => call('POST', '/api/send', { token, body: { to, blob } }),
    inbox: (token, wait = 0, signal) => call('GET', `/api/inbox?wait=${wait}`, { token, signal }),
    ack: (token, ids) => call('POST', '/api/ack', { token, body: { ids } }),
    logout: (token) => call('POST', '/api/logout', { token, body: {} }),
  };
}
