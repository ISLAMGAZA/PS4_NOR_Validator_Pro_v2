const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const btnSend = document.getElementById('btnSend');
const fileInput = document.getElementById('fileInput');
const uploadBar = document.getElementById('uploadBar');
const norUpload = document.getElementById('norUpload');
const sysconUpload = document.getElementById('sysconUpload');

let pendingFiles = {};

// ── DRAG & DROP ──
['dragenter','dragover'].forEach(e => window.addEventListener(e, e => e.preventDefault()));
window.addEventListener('drop', e => {
  e.preventDefault();
  for (const f of e.dataTransfer.files) {
    if (f.size === 33554432) {
      pendingFiles.nor = f;
      updateUploadUI('nor', f.name, 'loaded');
      addMsg('user', `<span style="font-size:1.2em">📀</span> Uploaded NOR: <code>${f.name}</code>`);
    } else if (f.size === 524288 || f.size === 262144) {
      pendingFiles.syscon = f;
      updateUploadUI('syscon', f.name, 'loaded');
      addMsg('user', `<span style="font-size:1.2em">🧩</span> Uploaded Syscon: <code>${f.name}</code>`);
    }
  }
  if (pendingFiles.nor || pendingFiles.syscon) sendToChat('');
});

// ── CLICK TO BROWSE ──
uploadBar.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  for (const f of fileInput.files) {
    if (f.size === 33554432) {
      pendingFiles.nor = f; updateUploadUI('nor', f.name, 'loaded');
    } else if (f.size === 524288 || f.size === 262144) {
      pendingFiles.syscon = f; updateUploadUI('syscon', f.name, 'loaded');
    }
  }
  if (pendingFiles.nor || pendingFiles.syscon) sendToChat('📁 Uploaded files');
});

// ── SEND ──
async function sendToChat(msg) {
  const text = msg || chatInput.value.trim();
  if (!text && !pendingFiles.nor && !pendingFiles.syscon) return;

  if (text) addMsg('user', text);
  chatInput.value = '';
  if (pendingFiles.nor) updateUploadUI('nor', pendingFiles.nor.name, 'analyzed');
  if (pendingFiles.syscon) updateUploadUI('syscon', pendingFiles.syscon.name, 'analyzed');
  showTyping();

  const form = new FormData();
  form.append('message', text || 'Analyze');
  if (pendingFiles.nor) form.append('nor', pendingFiles.nor, pendingFiles.nor.name);
  if (pendingFiles.syscon) form.append('syscon', pendingFiles.syscon, pendingFiles.syscon.name);

  try {
    const res = await fetch('/chat', { method: 'POST', body: form });
    const data = await res.json();
    hideTyping();
    renderResponse(data.response);
    if (data.has_nor && data.has_syscon) {
      updateUploadUI('nor', data.nor_file || 'NOR', 'analyzed');
      updateUploadUI('syscon', data.syscon_file || 'Syscon', 'analyzed');
    } else if (data.has_nor && data.state === 'nor_only') {
      updateUploadUI('nor', data.nor_file || 'NOR', 'analyzed');
    }
    pendingFiles = {};
  } catch(e) {
    hideTyping();
    addMsg('ai', `<p style="color:var(--red)">❌ Error: ${e.message}</p>`);
  }
}

btnSend.addEventListener('click', () => sendToChat());
chatInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendToChat(); });

// ── HINT BUTTONS ──
document.querySelectorAll('.hint').forEach(el => {
  el.addEventListener('click', () => { chatInput.value = el.dataset.msg; sendToChat(); });
});

// ── CUSTOM EVENTS: confirm & fix buttons ──
window.addEventListener('confirm', e => {
  if (e.detail === 'yes') fileInput.click();
  else if (e.detail === 'no') sendToChat('لا');
});
window.addEventListener('fix', e => {
  applyFix(e.detail);
});

async function applyFix(variant) {
  addMsg('user', `🛠️ Apply ${variant}`);
  showTyping();
  try {
    const res = await fetch('/fix', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({variant})
    });
    const data = await res.json();
    hideTyping();
    renderResponse(data.response);
  } catch(e) {
    hideTyping();
    addMsg('ai', `<p style="color:var(--red)">❌ Fix failed: ${e.message}</p>`);
  }
}

// ── RENDER RESPONSE ──
function renderResponse(html) {
  const div = document.createElement('div');
  div.className = 'msg msg-ai';
  div.innerHTML = '<div class="msg-avatar">🤖</div><div class="msg-content">' + html + '</div>';
  chatMessages.appendChild(div);
  scrollChat();
  // Re-bind dynamic buttons
  div.querySelectorAll('.btn-fix').forEach(b => {
    b.addEventListener('click', () => applyFix(b.textContent.includes('V1') ? 'V1' : b.textContent.includes('V2') ? 'V2' : 'V3'));
  });
  div.querySelectorAll('.btn-confirm').forEach(b => {
    b.addEventListener('click', () => {
      const yes = b.classList.contains('yes');
      window.dispatchEvent(new CustomEvent('confirm', {detail: yes ? 'yes' : 'no'}));
    });
  });
  div.querySelectorAll('[onclick]').forEach(el => {
    const attr = el.getAttribute('onclick');
    if (attr) el.removeAttribute('onclick');
  });
}

function addMsg(role, content) {
  const div = document.createElement('div');
  div.className = 'msg msg-' + role;
  div.innerHTML = '<div class="msg-avatar">' + (role === 'ai' ? '🤖' : '👤') +
    '</div><div class="msg-content">' + (
      typeof content === 'string' && (content.startsWith('<') || content.includes('<br>'))
        ? content : '<p>' + content.replace(/\n/g, '<br>') + '</p>'
    ) + '</div>';
  chatMessages.appendChild(div);
  scrollChat();
}

function updateUploadUI(type, name, status) {
  const el = type === 'nor' ? norUpload : sysconUpload;
  if (!el) return;
  const statusMap = { waiting: '⏳ Waiting', loaded: '✅ ' + name, analyzed: '📊 Analyzed' };
  el.innerHTML = statusMap[status] || '⏳ Waiting';
  el.className = 'upload-status ' + status;
}
function showTyping() {
  const d = document.createElement('div'); d.className = 'msg msg-ai typing'; d.id = 'typingIndicator';
  d.innerHTML = '<div class="msg-avatar">🤖</div><div class="msg-content"><div class="typing-dots"><span></span><span></span><span></span></div> Thinking...</div>';
  chatMessages.appendChild(d); scrollChat();
}
function hideTyping() { const e = document.getElementById('typingIndicator'); if (e) e.remove(); }
function scrollChat() { document.getElementById('chatContainer').scrollTop = document.getElementById('chatContainer').scrollHeight; }
