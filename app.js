/* =========================================================================
   YT Studio — Planificador privado y cifrado
   -------------------------------------------------------------------------
   Seguridad:
   - Ni el correo ni la contraseña están en el código (solo un hash PBKDF2
     irreversible = "verifier").
   - Toda tu información se guarda CIFRADA con AES-256-GCM. La clave se deriva
     de tu contraseña al iniciar sesión y solo vive en memoria; nunca se guarda.
   - Sin la contraseña correcta, los datos son ilegibles (ni siquiera desde la
     consola del navegador).
   ========================================================================= */

'use strict';

/* ---------- Configuración criptográfica (hashes, NO credenciales) ---------- */
const CFG = {
  iter: 310000,
  saltVer: '9df3874af3c8dbec4f276d5cae51d4eb',
  saltKey: '82150be2ad40a956a7afaf099c99aeb7',
  verifier: 'b78723c5af40862244b7d37edbdec5ab2f8c46728c0aea4c658723dd29d8e159',
};

const DAY_NAMES = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo'];

/* ---------- Utilidades de codificación ---------- */
const enc = new TextEncoder();
const dec = new TextDecoder();

function hexToBytes(hex) {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
  return a;
}
function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function bufToB64(buf) {
  let s = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBuf(b64) {
  const s = atob(b64);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}
function timingSafeEqual(aHex, bHex) {
  if (aHex.length !== bHex.length) return false;
  let r = 0;
  for (let i = 0; i < aHex.length; i++) r |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  return r === 0;
}

/* ---------- Derivación de claves ---------- */
async function pbkdf2(passphrase, saltBytes, bits) {
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: CFG.iter, hash: 'SHA-256' },
    baseKey, bits
  );
  return derived;
}

async function computeVerifier(email, password) {
  const bits = await pbkdf2(email + ' ' + password, hexToBytes(CFG.saltVer), 256);
  return bytesToHex(bits);
}

async function deriveAesKey(email, password) {
  const bits = await pbkdf2(email + ' ' + password, hexToBytes(CFG.saltKey), 256);
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/* ---------- Cifrado / descifrado del contenido ---------- */
async function encryptData(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return { v: 1, iv: bufToB64(iv), ct: bufToB64(ct) };
}
async function decryptData(key, payload) {
  const iv = b64ToBuf(payload.iv);
  const ct = b64ToBuf(payload.ct);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(dec.decode(pt));
}

/* ---------- Almacenamiento persistente (IndexedDB) ---------- */
const DB_NAME = 'yt_studio_vault';
const STORE = 'vault';
const RECORD_KEY = 'data';
const SYNC_KEY = 'sync';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbGet(key = RECORD_KEY) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function dbSet(payload, key = RECORD_KEY) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(payload, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function dbDel(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/* =========================================================================
   ESTADO DE LA APLICACIÓN
   ========================================================================= */
let cryptoKey = null;   // clave AES en memoria (nunca persistida)
let state = null;       // { weeks: [...] }
let saveTimer = null;

function newDay(name) {
  return {
    name,
    title: '',
    thumbnail: null,     // { name, type, dataUrl }
    script: '',
    description: '',
    tags: '',
    pinnedComment: '',
    thumbnailPrompt: '',
  };
}
function newWeek(index) {
  return {
    id: 'w_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
    name: 'Semana ' + index,
    planning: '',
    days: DAY_NAMES.map(newDay),
    collapsed: false,
  };
}
function defaultState() {
  // updatedAt=0 => un estado por defecto "sin tocar" siempre pierde frente a datos reales.
  return { weeks: [newWeek(1), newWeek(2)], meta: { updatedAt: 0, rev: 0 } };
}
function ensureMeta(s) {
  if (!s.meta) s.meta = { updatedAt: Date.now(), rev: 1 };
  return s;
}
function bumpMeta() {
  ensureMeta(state);
  state.meta.updatedAt = Date.now();
  state.meta.rev = (state.meta.rev || 0) + 1;
}

/* =========================================================================
   GUARDADO (cifrado + debounce)
   ========================================================================= */
function markSaving() {
  const el = $('#save-state');
  el.textContent = 'Guardando…';
  el.className = 'save-state saving';
}
function markSaved() {
  const el = $('#save-state');
  el.textContent = 'Guardado';
  el.className = 'save-state saved';
  setTimeout(() => { if (el.classList.contains('saved')) el.className = 'save-state'; }, 1500);
}

async function persist() {
  if (!cryptoKey || !state) return;
  try {
    const payload = await encryptData(cryptoKey, state);
    await dbSet(payload);
    markSaved();
  } catch (e) {
    console.error('Error al guardar', e);
    toast('No se pudo guardar', 'err');
  }
}
function scheduleSave() {
  bumpMeta();
  markSaving();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(persist, 500);
  scheduleRemotePush();
}

/* =========================================================================
   HELPERS DOM
   ========================================================================= */
function $(sel, root = document) { return root.querySelector(sel); }
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) if (c) node.appendChild(c);
  return node;
}

let toastTimer = null;
function toast(msg, type = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + type;
  t.hidden = false;
  requestAnimationFrame(() => t.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove('show');
    setTimeout(() => { t.hidden = true; }, 260);
  }, 2400);
}

/* =========================================================================
   RENDER
   ========================================================================= */
function renderAll() {
  const container = $('#weeks');
  container.innerHTML = '';
  state.weeks.forEach((week, i) => container.appendChild(renderWeek(week, i)));
  $('#empty-hint').hidden = state.weeks.length > 0;
  const n = state.weeks.length;
  $('#weeks-count').textContent = n === 0 ? 'Mis semanas' : `Mis semanas · ${n}`;
}

function renderWeek(week, index) {
  const nameInput = el('input', {
    class: 'week-name', type: 'text', value: week.name, 'aria-label': 'Nombre de la semana',
    oninput: e => { week.name = e.target.value; scheduleSave(); },
  });

  const toggle = el('span', { class: 'week-toggle', text: '▼' });
  const delBtn = el('button', {
    class: 'btn-ghost danger week-del', text: 'Eliminar',
    onclick: () => {
      if (confirm(`¿Eliminar "${week.name}" y todo su contenido?`)) {
        state.weeks = state.weeks.filter(w => w.id !== week.id);
        renderAll();
        scheduleSave();
        toast('Semana eliminada');
      }
    },
  });

  const head = el('div', { class: 'week-head' }, [toggle, nameInput, delBtn]);

  const planning = el('div', { class: 'planning' }, [
    planBox('Planning semanal', week.planning, v => { week.planning = v; }),
  ]);

  const days = el('div', { class: 'days' }, week.days.map((d, di) => renderDay(week, d, di)));

  const body = el('div', { class: 'week-body' }, [planning, days]);
  const wrap = el('div', { class: 'week' + (week.collapsed ? ' collapsed' : '') }, [head, body]);

  head.addEventListener('click', e => {
    if (e.target === nameInput || e.target === delBtn) return;
    week.collapsed = !week.collapsed;
    wrap.classList.toggle('collapsed', week.collapsed);
    scheduleSave();
  });

  return wrap;
}

function planBox(label, value, onChange) {
  const ta = el('textarea', {
    class: 'field-input', rows: 3, placeholder: 'Escribe aquí…',
    oninput: e => { onChange(e.target.value); scheduleSave(); },
  });
  ta.value = value || '';
  return el('div', { class: 'plan-box' }, [el('label', { text: label }), ta]);
}

function renderDay(week, day, index) {
  const chip = el('span', { class: 'day-chip', text: day.name });
  const preview = el('span', {
    class: 'day-title-preview' + (day.title ? ' has' : ''),
    text: day.title || 'Sin título',
  });
  const thumbDot = day.thumbnail ? el('span', { class: 'day-thumb-dot', title: 'Tiene miniatura' }) : null;
  const caret = el('span', { class: 'day-caret', text: '▼' });

  const head = el('div', { class: 'day-head' }, [chip, preview, thumbDot, caret].filter(Boolean));

  const body = el('div', { class: 'day-body' }, [
    dayField('Título del vídeo', day.title, v => {
      day.title = v;
      preview.textContent = v || 'Sin título';
      preview.classList.toggle('has', !!v);
    }, false),
    renderThumbBlock(week, day),
    dayField('Guion del vídeo', day.script, v => { day.script = v; }, true, 5),
    dayField('Descripción del vídeo', day.description, v => { day.description = v; }, true, 4),
    dayField('Etiquetas del vídeo', day.tags, v => { day.tags = v; }, true, 2),
    dayField('Comentario a fijar', day.pinnedComment, v => { day.pinnedComment = v; }, true, 2),
    dayField('Prompt de la miniatura', day.thumbnailPrompt, v => { day.thumbnailPrompt = v; }, true, 3),
  ]);

  const wrap = el('div', { class: 'day' }, [head, body]);
  head.addEventListener('click', () => wrap.classList.toggle('open'));
  return wrap;
}

function dayField(label, value, onChange, multiline, rows = 3) {
  let input;
  if (multiline) {
    input = el('textarea', {
      class: 'field-input', rows,
      oninput: e => { onChange(e.target.value); scheduleSave(); },
    });
    input.value = value || '';
  } else {
    input = el('input', {
      class: 'field-input', type: 'text',
      oninput: e => { onChange(e.target.value); scheduleSave(); },
    });
    input.value = value || '';
  }
  return el('div', { class: 'day-field' }, [el('label', { text: label }), input]);
}

function renderThumbBlock(week, day) {
  const preview = el('div', { class: 'thumb-preview' });
  const fileInput = el('input', { type: 'file', accept: 'image/*', hidden: true });

  function paint() {
    preview.innerHTML = '';
    if (day.thumbnail && day.thumbnail.dataUrl) {
      preview.appendChild(el('img', { src: day.thumbnail.dataUrl, alt: 'Miniatura' }));
    } else {
      preview.appendChild(el('div', { class: 'thumb-placeholder', text: 'Sin miniatura · sube una imagen' }));
    }
  }
  paint();

  fileInput.addEventListener('change', () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      day.thumbnail = { name: file.name, type: file.type, dataUrl: reader.result };
      paint();
      updateActions();
      scheduleSave();
      toast('Miniatura guardada', 'ok');
    };
    reader.onerror = () => toast('No se pudo leer la imagen', 'err');
    reader.readAsDataURL(file);
    fileInput.value = '';
  });

  const uploadBtn = el('button', { class: 'btn-mini', onclick: () => fileInput.click() });
  const downloadBtn = el('button', { class: 'btn-mini', text: '⬇ Descargar' });
  const deleteBtn = el('button', { class: 'btn-mini danger', text: '🗑 Eliminar' });

  downloadBtn.addEventListener('click', () => {
    if (!day.thumbnail) return;
    const a = el('a', { href: day.thumbnail.dataUrl, download: day.thumbnail.name || 'miniatura.png' });
    document.body.appendChild(a); a.click(); a.remove();
  });
  deleteBtn.addEventListener('click', () => {
    if (!day.thumbnail) return;
    if (confirm('¿Eliminar la miniatura de este día?')) {
      day.thumbnail = null;
      paint(); updateActions(); scheduleSave();
      toast('Miniatura eliminada');
    }
  });

  const actions = el('div', { class: 'thumb-actions' }, [uploadBtn, downloadBtn, deleteBtn]);
  function updateActions() {
    const has = !!day.thumbnail;
    uploadBtn.textContent = has ? '🔄 Cambiar' : '⬆ Subir miniatura';
    downloadBtn.style.display = has ? '' : 'none';
    deleteBtn.style.display = has ? '' : 'none';
  }
  updateActions();

  return el('div', { class: 'day-field thumb-block' }, [
    el('label', { text: 'Miniatura del día' }),
    preview, fileInput, actions,
  ]);
}

/* =========================================================================
   COPIA DE SEGURIDAD (cifrada) — para mover datos entre dispositivos
   ========================================================================= */
async function exportBackup() {
  try {
    const payload = await encryptData(cryptoKey, state);
    const blob = new Blob([JSON.stringify({ app: 'yt-studio', ...payload }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().slice(0, 10);
    const a = el('a', { href: url, download: `yt-studio-backup-${stamp}.json` });
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    toast('Copia de seguridad descargada', 'ok');
  } catch (e) {
    console.error(e); toast('No se pudo exportar', 'err');
  }
}

function importBackup(file) {
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const payload = JSON.parse(reader.result);
      if (!payload.iv || !payload.ct) throw new Error('Formato no válido');
      const data = await decryptData(cryptoKey, payload); // solo funciona con TU contraseña
      if (!data || !Array.isArray(data.weeks)) throw new Error('Contenido no válido');
      if (!confirm('Esto reemplazará tus datos actuales por los de la copia. ¿Continuar?')) return;
      state = ensureMeta(data);
      bumpMeta();
      renderAll();
      await persist();
      scheduleRemotePush();
      toast('Copia restaurada', 'ok');
    } catch (e) {
      console.error(e);
      toast('No se pudo restaurar (archivo o contraseña incorrectos)', 'err');
    }
  };
  reader.onerror = () => toast('No se pudo leer el archivo', 'err');
  reader.readAsText(file);
}

/* =========================================================================
   SINCRONIZACIÓN ENTRE DISPOSITIVOS (API de GitHub)
   -------------------------------------------------------------------------
   El "vault" (todo tu contenido) se guarda CIFRADO en un archivo del repo.
   El token de acceso se guarda cifrado en este dispositivo (nunca en el código).
   Estrategia: última escritura gana, comparando meta.updatedAt.
   ========================================================================= */
let sync = null;          // { owner, repo, branch, path, token }
let remoteSha = null;     // sha del archivo remoto (para actualizarlo)
let remotePushTimer = null;
let syncing = false;
let branchEnsured = false; // ¿comprobado/creada la rama de datos?

async function loadSyncConfig() {
  sync = null;
  remoteSha = null;
  branchEnsured = false;
  if (!cryptoKey) return;
  const enc = await dbGet(SYNC_KEY);
  if (!enc) return;
  try { sync = await decryptData(cryptoKey, enc); } catch (e) { console.error('sync cfg', e); }
}
async function saveSyncConfig() {
  if (!sync) { await dbDel(SYNC_KEY); return; }
  const payload = await encryptData(cryptoKey, sync);
  await dbSet(payload, SYNC_KEY);
}

async function ghFetch(subpath, opts = {}) {
  const url = `https://api.github.com/repos/${sync.owner}/${sync.repo}${subpath}`;
  return fetch(url, {
    ...opts,
    headers: {
      'Authorization': 'Bearer ' + sync.token,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(opts.headers || {}),
    },
  });
}

// Crea la rama de datos si aún no existe (se ramifica de la rama por defecto).
async function ensureBranch() {
  if (branchEnsured) return;
  const res = await ghFetch(`/branches/${encodeURIComponent(sync.branch)}`);
  if (res.ok) { branchEnsured = true; return; }
  if (res.status === 401 || res.status === 403) throw new Error('Token sin permisos o caducado');
  if (res.status !== 404) throw new Error('No se pudo comprobar la rama (' + res.status + ')');

  // La rama no existe: la creamos desde la rama por defecto del repo.
  const repoRes = await ghFetch('');
  if (!repoRes.ok) throw new Error('No se pudo leer el repositorio (' + repoRes.status + ')');
  const def = (await repoRes.json()).default_branch;
  const refRes = await ghFetch(`/git/ref/heads/${encodeURIComponent(def)}`);
  if (!refRes.ok) throw new Error('No se pudo leer la rama base (' + refRes.status + ')');
  const sha = (await refRes.json()).object.sha;
  const createRes = await ghFetch('/git/refs', {
    method: 'POST',
    body: JSON.stringify({ ref: 'refs/heads/' + sync.branch, sha }),
  });
  if (!createRes.ok && createRes.status !== 422) {
    throw new Error('No se pudo crear la rama de datos (' + createRes.status + ')');
  }
  branchEnsured = true;
}

// Descarga el vault remoto (o null si no existe todavía).
// (El parámetro ?t= evita la caché; no usamos cabeceras extra para no romper CORS.)
async function remotePull() {
  const res = await ghFetch(`/contents/${sync.path}?ref=${encodeURIComponent(sync.branch)}&t=${Date.now()}`);
  if (res.status === 404) { remoteSha = null; return null; }
  if (res.status === 401 || res.status === 403) throw new Error('Token sin permisos o caducado');
  if (!res.ok) throw new Error('GitHub GET ' + res.status);
  const json = await res.json();
  remoteSha = json.sha;
  const contentStr = decodeURIComponent(escape(atob((json.content || '').replace(/\n/g, ''))));
  const payload = JSON.parse(contentStr);
  return await decryptData(cryptoKey, payload);
}

// Sube el estado local al repo (crea o actualiza el archivo).
async function remotePush() {
  await ensureBranch();
  const payload = await encryptData(cryptoKey, state);
  const contentStr = JSON.stringify(payload);
  const b64 = btoa(unescape(encodeURIComponent(contentStr)));
  const body = {
    message: 'chore(vault): update ' + new Date().toISOString(),
    content: b64,
    branch: sync.branch,
  };
  if (remoteSha) body.sha = remoteSha;
  let res = await ghFetch(`/contents/${sync.path}`, { method: 'PUT', body: JSON.stringify(body) });

  // Conflicto: otro dispositivo escribió. Resolvemos por marca de tiempo.
  if (res.status === 409 || res.status === 422) {
    const remote = await remotePull(); // refresca remoteSha
    if (remote && remote.meta && remote.meta.updatedAt > (state.meta?.updatedAt || 0)) {
      state = ensureMeta(remote);
      renderAll();
      await persistLocalOnly();
      toast('Se cargó una versión más reciente de otro dispositivo', 'ok');
      return;
    }
    body.sha = remoteSha;
    res = await ghFetch(`/contents/${sync.path}`, { method: 'PUT', body: JSON.stringify(body) });
  }
  if (!res.ok) throw new Error('GitHub PUT ' + res.status);
  const json = await res.json();
  remoteSha = json.content && json.content.sha;
}

async function persistLocalOnly() {
  if (!cryptoKey || !state) return;
  const payload = await encryptData(cryptoKey, state);
  await dbSet(payload);
}

function setSyncBadge(mode) {
  const btn = $('#btn-sync');
  const label = $('#sync-label');
  btn.classList.toggle('on', !!sync && mode !== 'off');
  btn.classList.toggle('syncing', mode === 'syncing');
  if (label) label.textContent = sync ? (mode === 'syncing' ? 'Sincronizando' : 'Sincronizado') : 'Sincronizar';
}

// Decide entre estado local y remoto y los reconcilia por marca de tiempo.
// Gana el que tenga meta.updatedAt más reciente (un estado por defecto vale 0).
async function reconcile() {
  const remote = await remotePull();
  if (remote && remote.meta && remote.meta.updatedAt >= (state.meta?.updatedAt || 0)) {
    state = ensureMeta(remote);
    renderAll();
    await persistLocalOnly();
    return 'pulled';
  }
  await remotePush(); // local más reciente (o remoto vacío)
  return 'pushed';
}

// Sincroniza al entrar.
async function syncOnLogin() {
  await loadSyncConfig();
  if (!sync) { setSyncBadge('off'); return; }
  setSyncBadge('syncing');
  try {
    await reconcile();
    setSyncBadge('idle');
  } catch (e) {
    console.error('syncOnLogin', e);
    setSyncBadge('idle');
    toast('No se pudo sincronizar: ' + e.message, 'err');
  }
}

function scheduleRemotePush() {
  if (!sync) return;
  setSyncBadge('syncing');
  clearTimeout(remotePushTimer);
  remotePushTimer = setTimeout(async () => {
    if (syncing) { scheduleRemotePush(); return; }
    syncing = true;
    try { await remotePush(); setSyncBadge('idle'); }
    catch (e) { console.error('push', e); setSyncBadge('idle'); toast('Fallo al subir cambios', 'err'); }
    finally { syncing = false; }
  }, 8000);
}

async function syncNow() {
  if (!sync) return false;
  if (syncing) return true;
  syncing = true;
  setSyncBadge('syncing');
  try {
    const result = await reconcile();
    setSyncBadge('idle');
    toast(result === 'pulled' ? 'Actualizado desde la nube' : 'Cambios subidos', 'ok');
    return true;
  } catch (e) {
    console.error('syncNow', e);
    setSyncBadge('idle');
    toast('Error: ' + e.message, 'err');
    return false;
  } finally {
    syncing = false;
  }
}

/* =========================================================================
   SESIÓN
   ========================================================================= */
async function unlock(email, password) {
  const ver = await computeVerifier(email.trim(), password);
  if (!timingSafeEqual(ver, CFG.verifier)) return false;

  cryptoKey = await deriveAesKey(email.trim(), password);

  const stored = await dbGet();
  if (stored) {
    try {
      state = ensureMeta(await decryptData(cryptoKey, stored));
    } catch (e) {
      // Datos existentes que no se pueden descifrar con esta clave
      console.error('No se pudo descifrar el almacén', e);
      state = defaultState();
    }
  } else {
    state = defaultState();
    await persist();
  }
  return true;
}

function enterApp() {
  $('#lock-screen').hidden = true;
  $('#app').hidden = false;
  renderAll();
  syncOnLogin(); // en segundo plano: descarga/sube lo más reciente
}

function lockApp() {
  cryptoKey = null;
  state = null;
  sync = null;
  remoteSha = null;
  clearTimeout(saveTimer);
  clearTimeout(remotePushTimer);
  $('#app').hidden = true;
  $('#lock-screen').hidden = false;
  $('#password').value = '';
  $('#weeks').innerHTML = '';
  setSyncBadge('off');
}

/* =========================================================================
   EVENTOS
   ========================================================================= */
document.addEventListener('DOMContentLoaded', () => {
  const form = $('#login-form');
  const errEl = $('#login-error');

  $('#toggle-pw').addEventListener('click', () => {
    const pw = $('#password');
    pw.type = pw.type === 'password' ? 'text' : 'password';
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    errEl.hidden = true;
    const btn = $('#login-btn');
    btn.disabled = true;
    btn.textContent = 'Comprobando…';
    try {
      const ok = await unlock($('#email').value, $('#password').value);
      if (ok) {
        enterApp();
      } else {
        errEl.hidden = false;
        errEl.classList.remove('shake');
        void errEl.offsetWidth;
        errEl.classList.add('shake');
      }
    } catch (err) {
      console.error(err);
      errEl.textContent = 'Ha ocurrido un error. Inténtalo de nuevo.';
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Entrar';
    }
  });

  $('#btn-add-week').addEventListener('click', () => {
    state.weeks.push(newWeek(state.weeks.length + 1));
    renderAll();
    scheduleSave();
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
  });

  $('#btn-logout').addEventListener('click', () => {
    if (confirm('¿Cerrar sesión? Tus datos quedan guardados y cifrados.')) lockApp();
  });

  $('#btn-export').addEventListener('click', exportBackup);
  $('#btn-import').addEventListener('click', () => $('#import-file').click());
  $('#import-file').addEventListener('change', e => {
    const file = e.target.files && e.target.files[0];
    if (file) importBackup(file);
    e.target.value = '';
  });

  /* ---------- Modal de sincronización ---------- */
  const modal = $('#sync-modal');
  const statusEl = $('#sync-status');

  function openSyncModal() {
    $('#sync-owner').value = (sync && sync.owner) || 'jnrElias';
    $('#sync-repo').value = (sync && sync.repo) || 'RDB';
    $('#sync-branch').value = (sync && sync.branch) || 'main';
    $('#sync-path').value = (sync && sync.path) || 'datos/vault.enc.json';
    $('#sync-token').value = (sync && sync.token) || '';
    statusEl.textContent = sync ? '✓ Sincronización activa en este dispositivo.' : '';
    statusEl.className = 'sync-status' + (sync ? ' ok' : '');
    $('#sync-now').hidden = !sync;
    $('#sync-disconnect').hidden = !sync;
    $('#sync-save').textContent = sync ? 'Guardar cambios' : 'Conectar y sincronizar';
    modal.hidden = false;
  }
  function closeSyncModal() { modal.hidden = true; }

  $('#btn-sync').addEventListener('click', openSyncModal);
  modal.addEventListener('click', e => { if (e.target.dataset.close) closeSyncModal(); });

  $('#sync-save').addEventListener('click', async () => {
    const owner = $('#sync-owner').value.trim();
    const repo = $('#sync-repo').value.trim();
    const branch = $('#sync-branch').value.trim() || 'main';
    const path = $('#sync-path').value.trim() || 'datos/vault.enc.json';
    const token = $('#sync-token').value.trim();
    if (!owner || !repo || !token) {
      statusEl.textContent = 'Rellena usuario, repositorio y token.';
      statusEl.className = 'sync-status err';
      return;
    }
    statusEl.textContent = 'Conectando…';
    statusEl.className = 'sync-status';
    sync = { owner, repo, branch, path, token };
    remoteSha = null;
    branchEnsured = false;
    const ok = await syncNow();
    if (ok) {
      await saveSyncConfig();
      setSyncBadge('idle');
      statusEl.textContent = '✓ Conectado y sincronizado.';
      statusEl.className = 'sync-status ok';
      $('#sync-now').hidden = false;
      $('#sync-disconnect').hidden = false;
      $('#sync-save').textContent = 'Guardar cambios';
    } else {
      sync = null;
      statusEl.textContent = 'No se pudo conectar. Revisa el token y los permisos (Contents: Read and write).';
      statusEl.className = 'sync-status err';
    }
  });

  $('#sync-now').addEventListener('click', async () => {
    statusEl.textContent = 'Sincronizando…';
    statusEl.className = 'sync-status';
    const ok = await syncNow();
    statusEl.textContent = ok ? '✓ Sincronizado.' : 'Error al sincronizar.';
    statusEl.className = 'sync-status ' + (ok ? 'ok' : 'err');
  });

  $('#sync-disconnect').addEventListener('click', async () => {
    if (!confirm('¿Desconectar la sincronización en este dispositivo? Tus datos locales y los del repo se conservan.')) return;
    sync = null;
    remoteSha = null;
    await dbDel(SYNC_KEY);
    setSyncBadge('off');
    closeSyncModal();
    toast('Sincronización desconectada');
  });

  // Al volver a la pestaña, comprueba si hay cambios de otro dispositivo
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && sync && cryptoKey && !syncing) {
      syncNow();
    }
  });

  // Aviso si hay cambios pendientes de guardar al cerrar
  window.addEventListener('beforeunload', e => {
    if (saveTimer && cryptoKey) { persist(); }
  });
});
