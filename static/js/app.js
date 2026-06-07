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
  
    // ---- Dashboard charts (Chart.js) ------------------------------------
    function initDashboardCharts(data) {
      if (typeof Chart === 'undefined') return;
      try {
        // Status bar: Active / Expiring / Expired
        const active = Math.max(0, data.certs - (data.expiring + data.expired));
        const ctxStatus = document.getElementById('chart-status');
        if (ctxStatus) {
          new Chart(ctxStatus.getContext('2d'), {
            type: 'bar',
            data: {
              labels: ['Active', 'Expiring', 'Expired'],
              datasets: [{
                data: [active, data.expiring, data.expired],
                backgroundColor: ['#34d399', '#f59e0b', '#ef4444'],
                borderRadius: 8,
              }],
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: false } },
              scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.03)' } }, x: { grid: { display: false } } },
            },
          });
        }

        // Severity pie
        const ctxSeverity = document.getElementById('chart-severity');
        if (ctxSeverity) {
          const sev = data.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
          new Chart(ctxSeverity.getContext('2d'), {
            type: 'doughnut',
            data: {
              labels: ['Critical', 'High', 'Medium', 'Low'],
              datasets: [{ data: [sev.critical, sev.high, sev.medium, sev.low], backgroundColor: ['#ef4444','#f43f5e','#f59e0b','#34d399'] }]
            },
            options: { cutout: '60%', plugins: { legend: { position: 'bottom' } }, maintainAspectRatio: false }
          });
        }

        // Quantum exposure gauge
        const ctxQuantum = document.getElementById('chart-quantum');
        if (ctxQuantum) {
          const total = Math.max(1, data.certs);
          const pct = Math.round((data.quantum_vulnerable / total) * 100);
          new Chart(ctxQuantum.getContext('2d'), {
            type: 'doughnut',
            data: {
              labels: ['Quantum vulnerable', 'Safe'],
              datasets: [{
                data: [pct, 100 - pct],
                backgroundColor: ['#8b5cf6', 'rgba(255,255,255,0.12)'],
                borderWidth: 0,
                hoverOffset: 4,
              }],
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              cutout: '82%',
              circumference: 180,
              rotation: -90,
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    label(context) {
                      return context.label === 'Quantum vulnerable'
                        ? `${context.formattedValue}% vulnerable`
                        : `${context.formattedValue}% safe`;
                    },
                  },
                },
              },
              animation: { duration: 1400, easing: 'easeOutQuart' },
              scales: {
                x: { display: false, stacked: true },
                y: { display: false, stacked: true },
              },
            },
            plugins: [{
              id: 'quantumCenter',
              beforeDraw(chart) {
                const { ctx, chartArea: { width, height, left, right, top, bottom } } = chart;
                ctx.save();
                const centerX = (left + right) / 2;
                const centerY = (top + bottom) / 1.05;
                ctx.fillStyle = '#e6edf7';
                ctx.font = '700 26px Inter, system-ui';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(`${pct}%`, centerX, centerY - 6);
                ctx.font = '500 12px Inter, system-ui';
                ctx.fillStyle = 'rgba(230,237,247,0.72)';
                ctx.fillText('quantum exposure', centerX, centerY + 18);
                ctx.restore();
              },
            }],
          });
        }
      } catch (err) {
        console.error('Chart init failed', err);
      }
    }

    // Auto-init if data is provided inline in the page
    document.addEventListener('DOMContentLoaded', () => {
      if (window.__DASHBOARD_DATA__) {
        initDashboardCharts(window.__DASHBOARD_DATA__);
      }
    });

  })();
