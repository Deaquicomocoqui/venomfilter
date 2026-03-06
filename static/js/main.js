// ── Tab switching ────────────────────────────────────────────────────────────
function switchTab(tab, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  btn.classList.add('active');
}

// ── Loading state on submit ──────────────────────────────────────────────────
document.getElementById('analyzeForm')?.addEventListener('submit', function () {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.classList.add('active');
  const btn = this.querySelector('.btn-analyze');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Analyzing…';
  }
});

// ── Copy to clipboard ────────────────────────────────────────────────────────
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 2000);
  });
}

// ── Collapsible sections ─────────────────────────────────────────────────────
document.querySelectorAll('.section-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    if (!target) return;
    const hidden = target.style.display === 'none';
    target.style.display = hidden ? '' : 'none';
    btn.textContent = hidden ? '▲' : '▼';
  });
});
