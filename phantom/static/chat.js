/* ==========================================================================
   Phantom Chat — vanilla JS
   Dependencies (loaded via CDN): marked.js, mermaid.js, highlight.js
   ========================================================================== */

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------
function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

let sessionId = localStorage.getItem('phantomSessionId') || uuid();
localStorage.setItem('phantomSessionId', sessionId);

let pendingImage = null;  // { base64: string, mediaType: string, filename: string }
let isStreaming = false;

// ---------------------------------------------------------------------------
// Marked configuration
// ---------------------------------------------------------------------------
if (typeof marked !== 'undefined') {
  marked.setOptions({
    breaks: true,
    gfm: true,
  });
}

// ---------------------------------------------------------------------------
// New Chat
// ---------------------------------------------------------------------------
function newChat() {
  sessionId = uuid();
  localStorage.setItem('phantomSessionId', sessionId);
  document.getElementById('messages').innerHTML = '';
  clearImage();
}

// ---------------------------------------------------------------------------
// Send Message
// ---------------------------------------------------------------------------
async function sendMessage() {
  if (isStreaming) return;

  const textarea = document.getElementById('messageInput');
  const sendBtn  = document.getElementById('sendBtn');
  const text     = textarea.value.trim();
  if (!text) return;

  const mode = document.getElementById('modeSelect').value;

  // Build request body
  const body = {
    session_id: sessionId,
    message: text,
    mode: mode,
  };

  if (pendingImage) {
    body.image_base64    = pendingImage.base64;
    body.image_media_type = pendingImage.mediaType;
  }

  // Append user message
  appendUserMessage(text, pendingImage ? pendingImage.filename : null);
  textarea.value = '';
  autoResizeTextarea(textarea);
  clearImage();

  // Disable controls
  isStreaming = true;
  sendBtn.disabled = true;
  textarea.disabled = true;

  // Create phantom bubble with streaming text
  const { bubble, streamEl } = appendPhantomStreamBubble();

  let accumulatedText = '';
  let toolIndicatorEl = null;

  try {
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (!raw) continue;

        let event;
        try { event = JSON.parse(raw); } catch { continue; }

        if (event.type === 'text') {
          accumulatedText += event.delta;
          streamEl.textContent = accumulatedText;
          scrollToBottom();
        }

        if (event.type === 'tool_call') {
          toolIndicatorEl = appendToolCall(event.name, event.input, bubble.parentElement);
          scrollToBottom();
        }

        if (event.type === 'tool_result') {
          if (toolIndicatorEl) {
            finishToolResult(toolIndicatorEl, event.name);
            toolIndicatorEl = null;
          }
        }

        if (event.type === 'done') {
          // Replace streaming text with rendered markdown
          if (accumulatedText) {
            bubble.innerHTML = renderMarkdown(accumulatedText);
            // Highlight code blocks
            bubble.querySelectorAll('pre code').forEach(el => {
              if (typeof hljs !== 'undefined') hljs.highlightElement(el);
            });
            // Render mermaid blocks
            renderMermaidInBubble(bubble);
          } else {
            bubble.textContent = '';
          }
          scrollToBottom();
        }
      }
    }
  } catch (err) {
    bubble.innerHTML = `<span style="color:var(--danger)">Error: ${escapeHtml(err.message)}</span>`;
  } finally {
    isStreaming = false;
    sendBtn.disabled = false;
    textarea.disabled = false;
    textarea.focus();
    scrollToBottom();
  }
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------
function renderMarkdown(md) {
  if (typeof marked === 'undefined') return escapeHtml(md).replace(/\n/g, '<br>');
  return marked.parse(md);
}

async function renderMermaidInBubble(bubble) {
  if (typeof mermaid === 'undefined') return;
  const codeBlocks = bubble.querySelectorAll('pre code.language-mermaid, code.language-mermaid');
  for (const block of codeBlocks) {
    const src = block.textContent;
    const id = 'mermaid-' + uuid().slice(0, 8);
    try {
      const { svg } = await mermaid.render(id, src);
      const wrapper = document.createElement('div');
      wrapper.className = 'mermaid-diagram';
      wrapper.innerHTML = svg;
      const pre = block.closest('pre') || block;
      pre.replaceWith(wrapper);
    } catch (e) {
      console.warn('Mermaid render failed:', e);
    }
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// DOM builders
// ---------------------------------------------------------------------------
function appendUserMessage(text, imageFilename) {
  const msgs = document.getElementById('messages');
  const wrapper = document.createElement('div');
  wrapper.className = 'message user';

  const role = document.createElement('div');
  role.className = 'message-role';
  role.textContent = 'You';

  const bubble = document.createElement('div');
  bubble.className = 'message-bubble';

  if (imageFilename) {
    const imgNote = document.createElement('div');
    imgNote.style.cssText = 'font-size:11px;color:var(--text-muted);margin-bottom:4px;';
    imgNote.textContent = `[Image: ${imageFilename}]`;
    bubble.appendChild(imgNote);
  }

  const textNode = document.createElement('span');
  textNode.textContent = text;
  bubble.appendChild(textNode);

  wrapper.appendChild(role);
  wrapper.appendChild(bubble);
  msgs.appendChild(wrapper);
  scrollToBottom();
}

function appendPhantomStreamBubble() {
  const msgs = document.getElementById('messages');
  const wrapper = document.createElement('div');
  wrapper.className = 'message phantom';

  const role = document.createElement('div');
  role.className = 'message-role';
  role.textContent = 'Phantom';

  const bubble = document.createElement('div');
  bubble.className = 'message-bubble';

  // Streaming text element — replaced with rendered markdown on done
  const streamEl = document.createElement('span');
  streamEl.className = 'streaming-text';
  bubble.appendChild(streamEl);

  wrapper.appendChild(role);
  wrapper.appendChild(bubble);
  msgs.appendChild(wrapper);
  scrollToBottom();

  return { wrapper, bubble, streamEl };
}

function appendToolCall(name, input, container) {
  const ind = document.createElement('div');
  ind.className = 'tool-indicator';

  const header = document.createElement('div');
  header.className = 'tool-indicator-header';
  header.innerHTML = `
    <span class="tool-icon">⚙</span>
    <span>Calling <span class="tool-call-name">${escapeHtml(name)}</span>…</span>
    <span class="tool-indicator-chevron">▾</span>
  `;
  header.addEventListener('click', () => ind.classList.toggle('open'));

  const body = document.createElement('div');
  body.className = 'tool-indicator-body';
  try {
    body.textContent = JSON.stringify(input, null, 2);
  } catch {
    body.textContent = String(input);
  }

  ind.appendChild(header);
  ind.appendChild(body);

  // Insert before last phantom message or append to messages
  const msgs = document.getElementById('messages');
  const last = msgs.lastElementChild;
  if (last) {
    msgs.insertBefore(ind, last);
  } else {
    msgs.appendChild(ind);
  }

  return ind;
}

function finishToolResult(indicatorEl, name) {
  const header = indicatorEl.querySelector('.tool-indicator-header');
  if (header) {
    header.innerHTML = `
      <span class="tool-icon tool-result-ok">✓</span>
      <span><span class="tool-call-name">${escapeHtml(name)}</span> returned</span>
      <span class="tool-indicator-chevron">▾</span>
    `;
    header.addEventListener('click', () => indicatorEl.classList.toggle('open'));
  }
}

function scrollToBottom() {
  const msgs = document.getElementById('messages');
  msgs.scrollTop = msgs.scrollHeight;
}

// ---------------------------------------------------------------------------
// Image attachment
// ---------------------------------------------------------------------------
function handleImageAttach(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = e => {
    // e.target.result is data:mediaType;base64,<data>
    const dataUrl = e.target.result;
    const comma   = dataUrl.indexOf(',');
    const meta    = dataUrl.slice(0, comma);          // e.g. "data:image/png;base64"
    const base64  = dataUrl.slice(comma + 1);
    const mediaType = meta.split(':')[1].split(';')[0]; // e.g. "image/png"

    pendingImage = { base64, mediaType, filename: file.name };

    document.getElementById('imageFilename').textContent = file.name;
    document.getElementById('imagePreview').classList.remove('hidden');
  };
  reader.readAsDataURL(file);

  // Reset input so the same file can be re-attached
  event.target.value = '';
}

function clearImage() {
  pendingImage = null;
  document.getElementById('imagePreview').classList.add('hidden');
  document.getElementById('imageFilename').textContent = '';
}

// ---------------------------------------------------------------------------
// Keyboard handling + textarea auto-resize
// ---------------------------------------------------------------------------
function handleKey(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
    return;
  }
  // Auto-resize on any key
  autoResizeTextarea(event.target);
}

function autoResizeTextarea(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 180) + 'px';
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
async function loadSessions() {
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    const { sessions } = await res.json();
    const list = document.getElementById('sessionsList');
    list.innerHTML = '';
    if (!sessions || sessions.length === 0) {
      list.innerHTML = '<div style="font-size:11px;color:var(--text-muted);padding:4px 8px;">No saved sessions.</div>';
      return;
    }
    for (const name of sessions) {
      const item = document.createElement('div');
      item.className = 'session-item';
      item.textContent = name;
      item.title = `Load session: ${name}`;
      item.addEventListener('click', () => loadSession(name));
      list.appendChild(item);
    }
  } catch (err) {
    console.warn('Could not load sessions:', err);
  }
}

async function loadSession(name) {
  try {
    const res = await fetch(`/api/sessions/${encodeURIComponent(name)}/load`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      alert(`Could not load session: ${err.error}`);
      return;
    }
    const { session_id, mode, message_count } = await res.json();
    sessionId = session_id;
    localStorage.setItem('phantomSessionId', sessionId);

    // Update mode selector
    const sel = document.getElementById('modeSelect');
    if (sel && mode) sel.value = mode;

    // Clear messages area and show a note
    const msgs = document.getElementById('messages');
    msgs.innerHTML = '';
    const note = document.createElement('div');
    note.style.cssText = 'font-size:12px;color:var(--text-muted);padding:8px 0;text-align:center;';
    note.textContent = `Session "${name}" loaded (${message_count} messages). Continue the conversation.`;
    msgs.appendChild(note);
  } catch (err) {
    alert(`Error loading session: ${err.message}`);
  }
}

async function saveCurrentSession() {
  const nameInput = document.getElementById('sessionName');
  const name = nameInput.value.trim();
  if (!name) {
    nameInput.focus();
    return;
  }
  try {
    const res = await fetch(`/api/sessions/${encodeURIComponent(name)}/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId }),
    });
    if (!res.ok) throw new Error(await res.text());
    nameInput.value = '';
    await loadSessions(); // refresh list
  } catch (err) {
    alert(`Error saving session: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Auto-resize listener on input
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  const ta = document.getElementById('messageInput');
  if (ta) {
    ta.addEventListener('input', () => autoResizeTextarea(ta));
  }
});
