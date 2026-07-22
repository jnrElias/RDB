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
async function dbGet() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(RECORD_KEY);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function dbSet(payload) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(payload, RECORD_KEY);
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
    planning1: '',
    planning2: '',
    days: DAY_NAMES.map(newDay),
    collapsed: false,
  };
}
function defaultState() {
  return { weeks: [newWeek(1), newWeek(2)] };
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
  markSaving();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(persist, 500);
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
    planBox('Planning semanal (1)', week.planning1, v => { week.planning1 = v; }),
    planBox('Planning semanal (2)', week.planning2, v => { week.planning2 = v; }),
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
      state = data;
      renderAll();
      await persist();
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
   SESIÓN
   ========================================================================= */
async function unlock(email, password) {
  const ver = await computeVerifier(email.trim(), password);
  if (!timingSafeEqual(ver, CFG.verifier)) return false;

  cryptoKey = await deriveAesKey(email.trim(), password);

  const stored = await dbGet();
  if (stored) {
    try {
      state = await decryptData(cryptoKey, stored);
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
}

function lockApp() {
  cryptoKey = null;
  state = null;
  clearTimeout(saveTimer);
  $('#app').hidden = true;
  $('#lock-screen').hidden = false;
  $('#password').value = '';
  $('#weeks').innerHTML = '';
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

  // Aviso si hay cambios pendientes de guardar al cerrar
  window.addEventListener('beforeunload', e => {
    if (saveTimer && cryptoKey) { persist(); }
  });
});
