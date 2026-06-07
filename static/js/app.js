// Lightweight enhancements for the Q Safe UI.
// Keeps the dashboard reactive without bringing in a frontend framework.

(function () {
  'use strict';

  // ---- Live status poll --------------------------------------------------
  function refreshStatus() {
    fetch('/api/status')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        document.title = `(${data.expiring_within_threshold} expiring) Q Safe · DataRevealAI`;
        const pulse = document.querySelector('.pulse');
        if (pulse) {
          pulse.style.background = data.critical_alerts.length ? 'var(--bad)' : 'var(--good)';
        }
      })
      .catch(() => {});
  }
  setInterval(refreshStatus, 120_000);

  // ---- Certificate table search -----------------------------------------
  const search = document.getElementById('cert-search');
  const table = document.getElementById('cert-table');
  if (search && table) {
    search.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      table.querySelectorAll('tbody tr').forEach((row) => {
        row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  // ---- Animate KPI numbers on first paint -------------------------------
  document.querySelectorAll('.kpi strong').forEach((node) => {
    const target = parseFloat(node.textContent);
    if (Number.isNaN(target)) return;
    const start = performance.now();
    const duration = 900;
    const initial = 0;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 4);
      node.textContent = Math.round(initial + (target - initial) * eased).toString();
      if (t < 1) requestAnimationFrame(tick);
      else node.textContent = String(target);
    };
    requestAnimationFrame(tick);
  });

  // ---- Subtle card hover lift on mouse-move -----------------------------
  document.querySelectorAll('.card').forEach((card) => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 100;
      const y = ((e.clientY - rect.top) / rect.height) * 100;
      card.style.background =
        `radial-gradient(600px circle at ${x}% ${y}%, rgba(56,189,248,.08), transparent 50%), var(--panel)`;
    });
    card.addEventListener('mouseleave', () => {
      card.style.background = '';
    });
  });
})();
