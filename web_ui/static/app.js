const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const btnSend = document.getElementById('btnSend');
const fileInput = document.getElementById('fileInput');
const norStatus = document.getElementById('norStatus');
const sysconStatus = document.getElementById('sysconStatus');

let pendingFiles = {};

// Drag & drop on the whole page
['dragenter','dragover'].forEach(e => window.addEventListener(e, e => e.preventDefault()));
window.addEventListener('drop', e => {
  e.preventDefault();
  const files = e.dataTransfer.files;
  for (const f of files) {
    if (f.size === 33554432 || f.name.endsWith('.BIN')) {
      pendingFiles['nor'] = f;
      norStatus.textContent = '✓ ' + f.name;
      norStatus.className = 'upload-status loaded';
      addMsg('user', '📁 أرفق ملف NOR: ' + f.name);
    } else if (f.size === 524288 || f.size === 262144) {
      pendingFiles['syscon'] = f;
      sysconStatus.textContent = '✓ ' + f.name;
      sysconStatus.className = 'upload-status loaded';
      addMsg('user', '📁 أرفق ملف Syscon: ' + f.name);
    }
  }
});

// File input for click-to-browse
document.addEventListener('click', e => {
  if (e.target.closest('.upload-area')) fileInput.click();
});
fileInput.addEventListener('change', () => {
  for (const f of fileInput.files) {
    if (f.size === 33554432 || (f.size === 524288 && f.name.includes('449'))) {
      pendingFiles['nor'] = f; norStatus.textContent = '✓ ' + f.name; norStatus.className = 'upload-status loaded';
    } else if (f.size === 524288 || f.size === 262144) {
      pendingFiles['syscon'] = f; sysconStatus.textContent = '✓ ' + f.name; sysconStatus.className = 'upload-status loaded';
    }
  }
});

// Send message
async function sendMessage() {
  const msg = chatInput.value.trim();
  if (!msg && !pendingFiles.nor && !pendingFiles.syscon) return;

  if (msg) {
    addMsg('user', msg);
    chatInput.value = '';
  } else {
    addMsg('user', '📁 أرسل الملفات للتحليل');
  }

  showTyping();

  const form = new FormData();
  form.append('message', msg || 'حلل الملفات');
  if (pendingFiles.nor) form.append('nor', pendingFiles.nor, pendingFiles.nor.name);
  if (pendingFiles.syscon) form.append('syscon', pendingFiles.syscon, pendingFiles.syscon.name);

  try {
    const res = await fetch('/chat', { method: 'POST', body: form });
    const data = await res.json();
    hideTyping();
    addMsg('ai', data.response);

    if (data.has_syscon) norStatus.textContent = '✓ تم التحليل'; norStatus.className = 'upload-status done';
    if (data.syscon_analysis) sysconStatus.textContent = '✓ تم التحليل'; sysconStatus.className = 'upload-status done';

    pendingFiles = {};
  } catch(e) {
    hideTyping();
    addMsg('ai', '❌ حدث خطأ: ' + e.message);
  }
}

btnSend.addEventListener('click', sendMessage);
chatInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendMessage(); });

// Hint buttons
document.querySelectorAll('.hint').forEach(el => {
  el.addEventListener('click', () => { chatInput.value = el.dataset.msg; sendMessage(); });
});

function addMsg(role, text) {
  const div = document.createElement('div');
  div.className = 'msg msg-' + role;
  div.innerHTML = '<div class="msg-avatar">' + (role === 'ai' ? '🤖' : '👤') +
    '</div><div class="msg-content">' + text.replace(/\n/g, '<br>') + '</div>';
  chatMessages.appendChild(div);
  scrollChat();
}

function showTyping() {
  const div = document.createElement('div');
  div.className = 'msg msg-ai typing';
  div.id = 'typingIndicator';
  div.innerHTML = '<div class="msg-avatar">🤖</div><div class="msg-content">⏳ جاري التحليل...</div>';
  chatMessages.appendChild(div);
  scrollChat();
}
function hideTyping() {
  const el = document.getElementById('typingIndicator');
  if (el) el.remove();
}
function scrollChat() {
  document.getElementById('chatContainer').scrollTop =
    document.getElementById('chatContainer').scrollHeight;
}
