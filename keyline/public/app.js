// Browser UI. All protocol and crypto logic lives in client.js / crypto.js; this file only draws and listens.
// User-supplied text is only ever inserted with textContent, never as HTML.
import { createApi, ApiError } from './api.js';
import { Messenger, KeyChangedError } from './client.js';
import { formatKey } from './crypto.js';

const APP_NAME = 'Keyline';
const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

function makeStorage() {
  try {
    localStorage.setItem('__probe', '1');
    localStorage.removeItem('__probe');
    return localStorage;
  } catch {
    const mem = new Map(); // private mode: history lasts until the tab closes
    return { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v), removeItem: (k) => mem.delete(k) };
  }
}
const storage = makeStorage();

let m = null; // the Messenger for the signed-in user
let current = null; // key of the open conversation
let mode = 'login';
let toastTimer = null;

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });
const dateFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
const sameDay = (a, b) => new Date(a).toDateString() === new Date(b).toDateString();

function shortTime(at) {
  if (sameDay(at, Date.now())) return timeFmt.format(at);
  return dateFmt.format(at);
}
function dayLabel(at) {
  if (sameDay(at, Date.now())) return 'Today';
  if (sameDay(at, Date.now() - 86_400_000)) return 'Yesterday';
  return dayFmt.format(at);
}

function describe(e, context = '') {
  if (e instanceof ApiError) {
    if (e.status === 0) return "Can't reach the server. Check your connection and try again.";
    if (e.status === 429) {
      if (/mailbox is full/i.test(e.message)) return 'Their mailbox is full. Try again later.';
      return context === 'send' ? 'Too many messages too quickly. Wait a moment and try again.' : 'Too many attempts. Wait a few minutes and try again.';
    }
    if (e.status === 403 && context === 'password') return 'Your current password is wrong.';
    if (e.status === 409) return context === 'password' ? 'Your account changed on another device. Log in again and retry.' : 'That username is taken. Pick another.';
    if (e.status === 401) return context === 'send' || context === 'password' ? 'Your session ended. Log in again.' : 'Wrong username or password.';
    if (e.status === 404) return 'No user has that key. Check the digits and try again.';
  }
  return e?.message || 'Something went wrong. Try again.';
}

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
}
const announce = (text) => { $('announce').textContent = text; };
const nameOf = (key) => m?.vault.contacts[key]?.name || formatKey(key);

function show(view) {
  for (const v of ['auth', 'reveal', 'app']) $('view-' + v).hidden = v !== view;
}

// ------------------------------------------------------------------ dialog

function dialog({ title, body, actions }) {
  const dlg = $('dlg');
  $('dlg-title').textContent = title;
  $('dlg-body').replaceChildren(...body);
  $('dlg-actions').replaceChildren(
    ...actions.map((a) =>
      h('button', {
        class: 'btn ' + (a.kind || ''),
        type: 'button',
        onclick: async () => {
          if (a.onClick && (await a.onClick()) === true) return; // true = the action opened another dialog
          dlg.close();
        },
      }, a.label),
    ),
  );
  if (!dlg.open) dlg.showModal();
}

// ------------------------------------------------------------------ sign in / sign up

function setMode(next) {
  mode = next;
  $('mode-login').setAttribute('aria-pressed', String(next === 'login'));
  $('mode-register').setAttribute('aria-pressed', String(next === 'register'));
  $('confirm-wrap').hidden = $('pw-hint').hidden = next !== 'register';
  $('password').autocomplete = next === 'register' ? 'new-password' : 'current-password';
  $('auth-submit').textContent = next === 'register' ? 'Create account' : 'Log in';
  $('auth-error').textContent = '';
  $('auth-status').textContent = '';
}

function busy(on) {
  const btn = $('auth-submit');
  btn.disabled = on;
  btn.textContent = on ? (mode === 'register' ? 'Creating account…' : 'Logging in…') : mode === 'register' ? 'Create account' : 'Log in';
  $('auth-status').textContent = on ? 'This takes a few seconds. Your password is being turned into encryption keys on this device.' : '';
}

function newMessenger() {
  return new Messenger({ api: createApi(''), storage, onEvent });
}

$('mode-login').addEventListener('click', () => setMode('login'));
$('mode-register').addEventListener('click', () => setMode('register'));

$('auth-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const username = $('username').value;
  const password = $('password').value;
  $('auth-error').textContent = '';
  if (mode === 'register' && password !== $('password2').value) {
    $('auth-error').textContent = "The passwords don't match.";
    $('password2').focus();
    return;
  }
  busy(true);
  const attempt = newMessenger();
  try {
    if (mode === 'register') await attempt.register(username, password);
    else await attempt.login(username, password);
    m = attempt;
    $('password').value = $('password2').value = '';
    if (mode === 'register') showReveal();
    else enterApp();
  } catch (e) {
    $('auth-error').textContent = describe(e);
  } finally {
    busy(false);
  }
});

// The one animated moment: the digits of a new key settle into place.
function revealDigits(el, finalText) {
  el.textContent = finalText;
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const chars = [...finalText];
  const start = performance.now();
  const frame = (now) => {
    const t = now - start;
    let out = '';
    let settled = true;
    chars.forEach((c, i) => {
      if (!/\d/.test(c) || t >= 500 + i * 80) out += c;
      else { out += String(Math.floor(Math.random() * 10)); settled = false; }
    });
    el.textContent = out;
    if (!settled) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

function showReveal() {
  const text = formatKey(m.key);
  $('reveal-plate').setAttribute('aria-label', 'Your key is ' + text);
  show('reveal');
  revealDigits($('reveal-digits'), text);
  $('reveal-continue').focus();
}

async function copyKey() {
  try {
    await navigator.clipboard.writeText(formatKey(m.key));
    toast('Key copied');
  } catch {
    toast("Couldn't copy. Select the key and copy it by hand.");
  }
}
$('reveal-copy').addEventListener('click', copyKey);
$('copy-key').addEventListener('click', copyKey);
$('reveal-continue').addEventListener('click', enterApp);

// ------------------------------------------------------------------ messenger view

function enterApp() {
  show('app');
  $('view-app').classList.remove('show-chat');
  $('my-key').textContent = formatKey(m.key);
  current = null;
  renderRail();
  renderChat();
  m.startPolling();
}

function leave(message = '') {
  m?.stopPolling();
  m = null;
  current = null;
  $('contact-list').replaceChildren();
  $('log').replaceChildren();
  $('draft').value = '';
  document.title = APP_NAME;
  show('auth');
  setMode('login');
  $('auth-status').textContent = message;
  $('username').focus();
}

function onEvent(ev) {
  if (!m) return;
  switch (ev.type) {
    case 'message':
      if (ev.key === current) {
        if (ev.incoming && document.visibilityState === 'visible') m.markRead(ev.key);
        renderLog();
      } else if (ev.incoming) {
        announce(`New message from ${nameOf(ev.key)}`);
      }
      renderRail();
      break;
    case 'contacts':
      renderRail();
      if (current) renderChat();
      break;
    case 'key-changed':
      announce(`${nameOf(ev.key)}'s safety number changed`);
      renderRail();
      if (ev.key === current) renderNotice();
      break;
    case 'offline': $('offline').hidden = false; break;
    case 'online': $('offline').hidden = true; break;
    case 'session-expired': leave('Your session ended. Log in again.'); break;
    case 'replaced': leave('You signed in on another device, so this one was signed out.'); break;
  }
}

function updateTitle() {
  const n = m ? m.contacts().reduce((sum, c) => sum + m.unread(c.key), 0) : 0;
  document.title = n ? `(${n}) ${APP_NAME}` : APP_NAME;
}

function renderRail() {
  const list = $('contact-list');
  list.replaceChildren();
  const last = (c) => m.thread(c.key).at(-1);
  const when = (c) => last(c)?.at ?? c.added;
  const contacts = m.contacts().sort((a, b) => when(b) - when(a));
  $('rail-empty').hidden = contacts.length > 0;
  for (const c of contacts) {
    const msg = last(c);
    const unread = m.unread(c.key);
    const preview = m.hasPendingKeyChange(c.key)
      ? 'Safety number changed'
      : msg ? (msg.dir === 'out' ? 'You: ' : '') + msg.body
      : c.request ? 'New conversation' : 'No messages yet';
    list.append(
      h('li', {},
        h('button', { class: 'contact', type: 'button', 'aria-current': String(c.key === current), onclick: () => openChat(c.key) },
          h('span', { class: 'name', text: c.name || formatKey(c.key) }),
          h('span', { class: 'when', text: msg ? shortTime(msg.at) : '' }),
          h('span', { class: 'preview', text: preview }),
          unread ? h('span', { class: 'badge', 'aria-label': `${unread} unread`, text: String(unread) }) : null,
        ),
      ),
    );
  }
  updateTitle();
}

function openChat(key) {
  current = key;
  $('view-app').classList.add('show-chat');
  m.markRead(key);
  renderRail();
  renderChat();
  $('send-error').textContent = '';
  if (matchMedia('(min-width: 761px)').matches) $('draft').focus();
}

function renderChat() {
  const c = current && m.vault.contacts[current];
  $('chat-empty').hidden = !!c;
  $('chat-pane').hidden = !c;
  if (!c) { $('view-app').classList.remove('show-chat'); return; }
  $('chat-name').textContent = c.name || formatKey(current);
  $('chat-key').textContent = c.name ? formatKey(current) : '';
  $('chat-key').hidden = !c.name;
  renderNotice();
  renderLog(true);
}

function renderNotice() {
  const box = $('notice');
  const c = current && m.vault.contacts[current];
  box.replaceChildren();
  box.classList.remove('warn');
  if (!c) { box.hidden = true; return; }
  if (m.hasPendingKeyChange(current)) {
    box.classList.add('warn');
    box.hidden = false;
    box.append(
      h('p', { text: `${c.name || formatKey(current)}'s safety number changed. Messages from the new number are held until you check it.` }),
      h('div', { class: 'banner-row' }, h('button', { class: 'btn', type: 'button', onclick: () => openSafety(current) }, 'Review safety number')),
    );
  } else if (c.request) {
    box.hidden = false;
    const input = h('input', { 'aria-label': 'Name', placeholder: 'Name', maxlength: '40', autocomplete: 'off' });
    box.append(
      h('p', { text: "This person isn't in your contacts yet. Give them a name to keep the conversation." }),
      h('form', { class: 'banner-row', onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) m.renameContact(current, input.value); } },
        input,
        h('button', { class: 'btn', type: 'submit' }, 'Save name'),
        h('button', { class: 'btn danger-quiet', type: 'button', onclick: () => confirmBlock(current) }, 'Block')),
    );
  } else {
    box.hidden = true;
  }
}

function renderLog(forceBottom = false) {
  const log = $('log');
  const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 90;
  log.replaceChildren();
  const thread = m.thread(current);
  if (!thread.length) log.append(h('p', { class: 'empty-log', text: 'No messages yet. Say hello.' }));
  let lastAt = null;
  for (const msg of thread) {
    if (lastAt === null || !sameDay(lastAt, msg.at)) log.append(h('p', { class: 'day', text: dayLabel(msg.at) }));
    lastAt = msg.at;
    log.append(
      h('div', { class: 'msg ' + msg.dir },
        h('p', { class: 'body', text: msg.body }),
        h('time', { datetime: new Date(msg.at).toISOString(), text: timeFmt.format(msg.at) }),
      ),
    );
  }
  if (forceBottom || nearBottom) log.scrollTop = log.scrollHeight;
}

// ------------------------------------------------------------------ add a contact

$('add-key').addEventListener('input', (e) => {
  const d = e.target.value.replace(/\D/g, '').slice(0, 10);
  e.target.value = [d.slice(0, 3), d.slice(3, 6), d.slice(6)].filter(Boolean).join('-');
});

$('add-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const err = $('add-error');
  err.textContent = '';
  const btn = ev.submitter;
  btn.disabled = true;
  try {
    const key = await m.addContact($('add-key').value, $('add-name').value);
    $('add-key').value = '';
    $('add-name').value = '';
    openChat(key);
  } catch (e) {
    err.textContent = describe(e);
  } finally {
    btn.disabled = false;
  }
});

// ------------------------------------------------------------------ composing

const draft = $('draft');
const autoGrow = () => { draft.style.height = 'auto'; draft.style.height = Math.min(draft.scrollHeight, 160) + 'px'; };
draft.addEventListener('input', autoGrow);
draft.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    $('composer').requestSubmit();
  }
});

$('composer').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const text = draft.value;
  if (!text.trim() || !current) return;
  const target = current;
  $('send-error').textContent = '';
  $('send').disabled = true;
  try {
    await m.sendText(target, text);
    if (m && current === target) { draft.value = ''; autoGrow(); }
  } catch (e) {
    if (e instanceof KeyChangedError) {
      renderNotice();
      renderRail();
      openSafety(target);
    } else {
      $('send-error').textContent = describe(e, 'send');
    }
  } finally {
    $('send').disabled = false;
    if (m) draft.focus();
  }
});

// ------------------------------------------------------------------ safety number

async function openSafety(key) {
  const c = m.vault.contacts[key];
  if (!c) return;
  const name = c.name || formatKey(key);
  const pending = m.hasPendingKeyChange(key);
  const grid = (n, cls = '') => h('div', { class: 'safety ' + cls, role: 'text', 'aria-label': n.replaceAll(' ', ', ') }, n.split(' ').map((g) => h('span', { text: g })));
  try {
    const now = await m.safetyNumber(key);
    if (!pending) {
      dialog({
        title: `Safety number with ${name}`,
        body: [
          h('p', { text: `Read this number to ${name} in person or by phone. If you both see the same number, nobody has tampered with your keys.` }),
          grid(now),
        ],
        actions: [{ label: 'Done', kind: 'primary' }],
      });
      return;
    }
    const next = await m.safetyNumber(key, true);
    dialog({
      title: `${name}'s safety number changed`,
      body: [
        h('p', { text: `This happens when someone reinstalls or switches devices. It can also mean someone is intercepting your messages. Ask ${name} to read you their new number in person or by phone.` }),
        h('p', { class: 'label', text: 'New safety number' }),
        grid(next),
        h('p', { class: 'label', text: 'Previous safety number' }),
        grid(now, 'old'),
      ],
      actions: [
        { label: 'Not now' },
        {
          label: 'Trust new number',
          kind: 'primary',
          onClick: async () => {
            try { await m.acceptKeyChange(key); } catch (e) { toast(describe(e)); }
            renderRail();
            renderChat();
          },
        },
      ],
    });
  } catch (e) {
    toast(describe(e));
  }
}
$('safety-btn').addEventListener('click', () => current && openSafety(current));

// ------------------------------------------------------------------ conversation options, blocking

function afterConversationGone() {
  current = null;
  renderRail();
  renderChat();
}

function confirmRemove(key) {
  dialog({
    title: 'Delete this conversation?',
    body: [h('p', { text: `The messages are removed from this device and ${nameOf(key)} is removed from your contacts. They can still message you; block them to stop that.` })],
    actions: [
      { label: 'Cancel' },
      {
        label: 'Delete',
        kind: 'danger',
        onClick: async () => {
          try { await m.removeContact(key); } catch (e) { toast(describe(e)); return; }
          afterConversationGone();
        },
      },
    ],
  });
  return true;
}

function confirmBlock(key) {
  dialog({
    title: `Block ${nameOf(key)}?`,
    body: [
      h('p', { text: "They won't be able to reach you. Anything they send is thrown away without you seeing it, and they aren't told." }),
      h('p', { text: 'This conversation is deleted from this device. You can unblock them later from the Account menu.' }),
    ],
    actions: [
      { label: 'Cancel' },
      {
        label: 'Block',
        kind: 'danger',
        onClick: async () => {
          try { await m.blockContact(key); } catch (e) { toast(describe(e)); return; }
          afterConversationGone();
          toast('Blocked');
        },
      },
    ],
  });
  return true;
}

function openOptions(key) {
  const c = m.vault.contacts[key];
  if (!c) return;
  const input = h('input', { id: 'opt-name', placeholder: 'Name', maxlength: '40', autocomplete: 'off' });
  input.value = c.name || '';
  dialog({
    title: c.name || formatKey(key),
    body: [c.name ? h('p', { class: 'hint', text: `Key ${formatKey(key)}` }) : null, h('label', { for: 'opt-name', text: 'Name' }), input],
    actions: [
      { label: 'Delete conversation', kind: 'danger-quiet', onClick: () => confirmRemove(key) },
      { label: 'Block', kind: 'danger-quiet', onClick: () => confirmBlock(key) },
      {
        label: 'Save name',
        kind: 'primary',
        onClick: async () => {
          try { await m.renameContact(key, input.value); } catch (e) { toast(describe(e)); }
        },
      },
    ],
  });
}
$('opts-btn').addEventListener('click', () => current && openOptions(current));

function openBlocked() {
  const keys = m.blockedKeys();
  const unblock = (k) => async () => {
    try { await m.unblock(k); } catch (e) { toast(describe(e)); }
    openBlocked();
  };
  dialog({
    title: 'Blocked people',
    body: keys.length
      ? [h('ul', { class: 'plain-list' }, keys.map((k) => h('li', {}, h('span', { class: 'num', text: formatKey(k) }), h('button', { class: 'btn quiet', type: 'button', onclick: unblock(k) }, 'Unblock'))))]
      : [h('p', { text: "You haven't blocked anyone." })],
    actions: [{ label: 'Done', kind: 'primary' }],
  });
  return true;
}

function openChangePassword() {
  const field = (id, label, auto) => [h('label', { for: id, text: label }), h('input', { id, type: 'password', autocomplete: auto })];
  const err = h('p', { class: 'error', role: 'alert' });
  let working = false;
  dialog({
    title: 'Change password',
    body: [
      ...field('pw-cur', 'Current password', 'current-password'),
      ...field('pw-new', 'New password (at least 12 characters)', 'new-password'),
      ...field('pw-new2', 'Repeat new password', 'new-password'),
      err,
    ],
    actions: [
      { label: 'Cancel' },
      {
        label: 'Change password',
        kind: 'primary',
        onClick: async () => {
          if (working) return true;
          if ($('pw-new').value !== $('pw-new2').value) { err.textContent = "The new passwords don't match."; return true; }
          working = true;
          err.textContent = 'Working… this takes a few seconds.';
          try {
            await m.changePassword($('pw-cur').value, $('pw-new').value);
          } catch (e) {
            working = false;
            err.textContent = describe(e, 'password');
            return true; // keep the dialog open so they can fix it
          }
          working = false;
          toast('Password changed.');
        },
      },
    ],
  });
  return true;
}

// ------------------------------------------------------------------ account menu

function confirmDelete() {
  dialog({
    title: 'Delete your account?',
    body: [h('p', { text: "This removes your key, your login and any waiting messages from the server. Conversations saved on this device are erased too. People who have your key won't be able to reach you any more. This can't be undone." })],
    actions: [
      { label: 'Keep account' },
      {
        label: 'Delete account',
        kind: 'danger',
        onClick: async () => {
          try { await m.deleteAccount(); } catch (e) { toast(describe(e)); return; }
          leave('Your account was deleted.');
        },
      },
    ],
  });
  return true;
}

$('menu-btn').addEventListener('click', () => {
  dialog({
    title: 'Account',
    body: [
      h('p', { text: `You're using key ${formatKey(m.key)}.` }),
      h('div', { class: 'dlg-list' },
        h('button', { class: 'btn quiet', type: 'button', onclick: openChangePassword }, 'Change password'),
        h('button', { class: 'btn quiet', type: 'button', onclick: openBlocked }, `Blocked people (${m.blockedKeys().length})`),
      ),
      h('p', { class: 'hint', text: 'Conversations are saved on this device only. You can be signed in on one device at a time: logging in somewhere else signs this one out, and you will see new messages there from that point on.' }),
    ],
    actions: [
      { label: 'Delete account', kind: 'danger-quiet', onClick: confirmDelete },
      { label: 'Log out', kind: 'primary', onClick: async () => { await m.logout(); leave(); } },
    ],
  });
});

$('back').addEventListener('click', () => {
  current = null;
  renderRail();
  renderChat();
});

document.addEventListener('visibilitychange', () => {
  if (m && current && document.visibilityState === 'visible') { m.markRead(current).then(renderRail); }
});

// ------------------------------------------------------------------ start

if (!window.isSecureContext || !globalThis.crypto?.subtle) {
  $('auth-error').textContent = 'This page needs a secure connection (HTTPS) to protect your messages. Open it over HTTPS and try again.';
  $('auth-submit').disabled = true;
}
setMode('login');
