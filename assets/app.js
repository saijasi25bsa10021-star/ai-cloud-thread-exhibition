/* ==========================================================================
   G1 — Cloud Threat Intelligence Console
   All rendering is hand-rolled (no chart/UI library) so the page has zero
   external runtime dependencies and works fully offline.
   ========================================================================== */
(function () {
  'use strict';

  var DATA = (window.G1_DATA) || { logs: [], threats: [], overview: {}, accounts: [] };
  var OV = DATA.overview || {};
  var SEV_COLOR = { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)' };
  var SEV_VAR = { Critical: '--crit', High: '--high', Medium: '--med' };

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmtNum(n) { return (n || 0).toLocaleString('en-US'); }

  /* ------------------------------------------------------------------- */
  /* Navigation                                                          */
  /* ------------------------------------------------------------------- */
  var PAGE_META = {
    overview: { title: 'Overview', sub: 'Real-time cloud activity & anomaly summary' },
    alerts: { title: 'Threat Alerts', sub: 'Flagged events with AI-generated reasoning & remediation' },
    explorer: { title: 'Log Explorer', sub: 'Full raw log stream — 10,000 events' },
    admin: { title: 'Admin Console', sub: 'Account lockouts & access control' }
  };

  function initNav() {
    var items = $all('.nav-item');
    items.forEach(function (item) {
      item.addEventListener('click', function () {
        var view = item.getAttribute('data-view');
        if (!view) return;
        items.forEach(function (i) { i.classList.remove('active'); });
        item.classList.add('active');
        $all('.view').forEach(function (v) { v.classList.remove('active'); });
        var target = $('#view-' + view);
        if (target) target.classList.add('active');
        var meta = PAGE_META[view];
        if (meta) {
          $('#pageTitle').textContent = meta.title;
          $('#pageSub').textContent = meta.sub;
        }
        closeMobileSidebar();
        window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
      });
    });
  }

  function goToView(view, focusSearch) {
    var item = $('.nav-item[data-view="' + view + '"]');
    if (item) item.click();
    if (focusSearch) {
      setTimeout(function () {
        var el = view === 'explorer' ? $('#logSearch') : $('#alertSearch');
        if (el) el.focus();
      }, 50);
    }
  }

  function initMobileSidebar() {
    var sidebar = $('#sidebar');
    var overlay = $('#sidebarOverlay');
    var toggle = $('#menuToggle');
    if (!sidebar || !overlay || !toggle) return;
    toggle.addEventListener('click', function () {
      sidebar.classList.add('open');
      overlay.classList.add('show');
    });
    overlay.addEventListener('click', closeMobileSidebar);
  }
  function closeMobileSidebar() {
    var sidebar = $('#sidebar');
    var overlay = $('#sidebarOverlay');
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('show');
  }

  /* ------------------------------------------------------------------- */
  /* Clock                                                                */
  /* ------------------------------------------------------------------- */
  function initClock() {
    var el = $('#clock');
    if (!el) return;
    function tick() {
      var d = new Date();
      var opts = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
      el.textContent = d.toLocaleTimeString('en-GB', opts) + ' UTC' + (-d.getTimezoneOffset() / 60 >= 0 ? '+' : '') + '';
    }
    tick();
    setInterval(tick, 1000);
  }

  /* ------------------------------------------------------------------- */
  /* Global search (topbar) -> jumps to Log Explorer                     */
  /* ------------------------------------------------------------------- */
  function initGlobalSearch() {
    var input = $('#globalSearch');
    if (!input) return;
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && input.value.trim()) {
        var q = input.value.trim();
        goToView('explorer');
        var logSearch = $('#logSearch');
        if (logSearch) {
          logSearch.value = q;
          logSearch.dispatchEvent(new Event('input'));
        }
      }
    });
  }

  /* ------------------------------------------------------------------- */
  /* KPIs                                                                 */
  /* ------------------------------------------------------------------- */
  function renderKpis() {
    var k = OV.kpis || {};
    setText('#kpiTotal', fmtNum(k.total_logs));
    setText('#kpiThreats', fmtNum(k.threats_detected));
    setText('#kpiThreatRate', (k.threat_ratio != null ? k.threat_ratio : 0) + '%');
    setText('#kpiFailed', fmtNum(k.failed_logins));
    setText('#kpiUsers', fmtNum(k.active_users));
    setText('#navAlertBadge', fmtNum(k.threats_detected));
    setText('#navLogBadge', fmtNum(k.total_logs));
  }
  function setText(sel, val) { var el = $(sel); if (el) el.textContent = val; }

  /* ------------------------------------------------------------------- */
  /* Hourly chart — hand-rolled SVG area/line combo                      */
  /* ------------------------------------------------------------------- */
  function renderHourlyChart() {
    var host = $('#hourlyChart');
    if (!host) return;
    var data = OV.hourly || [];
    if (!data.length) { host.innerHTML = emptyNote('No hourly data'); return; }

    var W = 560, H = 190, padL = 34, padR = 10, padT = 10, padB = 24;
    var innerW = W - padL - padR, innerH = H - padT - padB;
    var maxTotal = Math.max.apply(null, data.map(function (d) { return d.total; })) || 1;

    var stepX = innerW / (data.length - 1 || 1);
    function x(i) { return padL + i * stepX; }
    function yTotal(v) { return padT + innerH - (v / maxTotal) * innerH; }
    function yThreat(v) { return padT + innerH - (v / maxTotal) * innerH; }

    var totalPath = data.map(function (d, i) { return (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ',' + yTotal(d.total).toFixed(1); }).join(' ');
    var areaPath = totalPath + ' L' + x(data.length - 1).toFixed(1) + ',' + (padT + innerH) + ' L' + x(0).toFixed(1) + ',' + (padT + innerH) + ' Z';
    var threatPath = data.map(function (d, i) { return (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ',' + yThreat(d.threats).toFixed(1); }).join(' ');

    var gridLines = '';
    for (var g = 0; g <= 3; g++) {
      var gy = padT + (innerH / 3) * g;
      gridLines += '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + (W - padR) + '" y2="' + gy.toFixed(1) + '" stroke="var(--border-soft)" stroke-width="1"/>';
    }
    var xLabels = '';
    [0, 6, 12, 18, 23].forEach(function (h) {
      if (h >= data.length) return;
      xLabels += '<text x="' + x(h).toFixed(1) + '" y="' + (H - 6) + '" font-size="9.5" fill="var(--text-faint)" text-anchor="middle" font-family="var(--font-mono)">' + h + 'h</text>';
    });

    var dots = data.map(function (d, i) {
      if (d.threats <= 0) return '';
      return '<circle cx="' + x(i).toFixed(1) + '" cy="' + yThreat(d.threats).toFixed(1) + '" r="2.4" fill="var(--crit)" />';
    }).join('');

    var svg = '' +
      '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" style="width:100%; height:190px; overflow:visible;">' +
      '<defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="var(--signal)" stop-opacity="0.22"/>' +
      '<stop offset="100%" stop-color="var(--signal)" stop-opacity="0"/></linearGradient></defs>' +
      gridLines +
      '<path d="' + areaPath + '" fill="url(#areaGrad)" stroke="none"/>' +
      '<path d="' + totalPath + '" fill="none" stroke="var(--text-faint)" stroke-width="1.5"/>' +
      '<path d="' + threatPath + '" fill="none" stroke="var(--crit)" stroke-width="2"/>' +
      dots +
      xLabels +
      '</svg>';
    host.innerHTML = svg;
  }

  function emptyNote(msg) {
    return '<div style="padding:24px 0; text-align:center; color:var(--text-faint); font-size:12.5px;">' + esc(msg) + '</div>';
  }

  /* ------------------------------------------------------------------- */
  /* Severity donut — hand-rolled SVG                                    */
  /* ------------------------------------------------------------------- */
  function renderSeverityDonut() {
    var host = $('#severityDonut');
    var legendHost = $('#severityLegend');
    if (!host) return;
    var items = (OV.severity || []).slice().sort(function (a, b) {
      var order = { Critical: 1, High: 2, Medium: 3 };
      return (order[a.name] || 9) - (order[b.name] || 9);
    });
    var total = items.reduce(function (s, d) { return s + d.value; }, 0) || 1;

    var size = 168, cx = size / 2, cy = size / 2, r = 62, sw = 20;
    var circumference = 2 * Math.PI * r;
    var offset = 0;
    var arcs = items.map(function (d) {
      var frac = d.value / total;
      var dash = frac * circumference;
      var gap = circumference - dash;
      var seg = '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" ' +
        'stroke="' + (SEV_COLOR[d.name] || 'var(--text-faint)') + '" stroke-width="' + sw + '" ' +
        'stroke-dasharray="' + dash.toFixed(1) + ' ' + gap.toFixed(1) + '" ' +
        'stroke-dashoffset="' + (-offset).toFixed(1) + '" ' +
        'transform="rotate(-90 ' + cx + ' ' + cy + ')" stroke-linecap="butt"/>';
      offset += dash;
      return seg;
    }).join('');

    var svg = '<div style="display:flex; align-items:center; justify-content:center; gap:20px; flex-wrap:wrap;">' +
      '<svg viewBox="0 0 ' + size + ' ' + size + '" style="width:168px; height:168px; flex-shrink:0;">' +
      arcs +
      '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" font-family="var(--font-display)" font-size="22" font-weight="700" fill="var(--text)">' + fmtNum(total) + '</text>' +
      '<text x="' + cx + '" y="' + (cy + 14) + '" text-anchor="middle" font-family="var(--font-body)" font-size="9.5" fill="var(--text-faint)">threats</text>' +
      '</svg>' +
      '<div style="display:flex; flex-direction:column; gap:10px;">' +
      items.map(function (d) {
        var pct = Math.round((d.value / total) * 100);
        return '<div style="display:flex; align-items:center; gap:8px; font-size:12.5px;">' +
          '<span style="width:9px;height:9px;border-radius:3px;background:' + (SEV_COLOR[d.name] || 'var(--text-faint)') + ';flex-shrink:0;"></span>' +
          '<span style="color:var(--text);font-weight:600; width:60px;">' + esc(d.name) + '</span>' +
          '<span style="color:var(--text-faint); font-family:var(--font-mono); font-size:11.5px;">' + fmtNum(d.value) + ' · ' + pct + '%</span>' +
          '</div>';
      }).join('') +
      '</div></div>';
    host.innerHTML = svg;
    if (legendHost) legendHost.innerHTML = '';
  }

  /* ------------------------------------------------------------------- */
  /* Bar rows (actions / countries / users)                               */
  /* ------------------------------------------------------------------- */
  function renderBarRows(hostSel, items) {
    var host = $(hostSel);
    if (!host) return;
    if (!items || !items.length) { host.innerHTML = emptyNote('No data'); return; }
    var max = Math.max.apply(null, items.map(function (d) { return d.value; })) || 1;
    host.innerHTML = items.map(function (d) {
      var pct = Math.max(4, Math.round((d.value / max) * 100));
      return '<div class="bar-row">' +
        '<div class="bar-row-label" title="' + esc(d.name) + '">' + esc(d.name) + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
        '<div class="bar-row-value">' + fmtNum(d.value) + '</div>' +
        '</div>';
    }).join('');
  }

  /* ------------------------------------------------------------------- */
  /* Alert ticker (overview)                                              */
  /* ------------------------------------------------------------------- */
  function renderTicker() {
    var host = $('#alertTicker');
    if (!host) return;
    var items = OV.ticker || [];
    if (!items.length) { host.innerHTML = emptyNote('No critical or high-severity events'); return; }
    host.innerHTML = items.map(function (t) {
      return '<div class="ticker-item">' +
        '<span class="tick-sev" style="background:' + (SEV_COLOR[t.severity] || 'var(--text-faint)') + '"></span>' +
        '<div class="tick-body">' +
        '<div class="tick-title">' + esc(t.threat_name) + '</div>' +
        '<div class="tick-meta">' + esc(t.Username) + ' · ' + esc(t.IP) + ' · ' + esc(t.Country) + ' · #' + t.LogID + '</div>' +
        '</div></div>';
    }).join('');
  }

  /* ------------------------------------------------------------------- */
  /* Alerts view                                                          */
  /* ------------------------------------------------------------------- */
  var alertState = { sev: 'all', q: '', page: 1, perPage: 12, openIds: {} };

  function filteredThreats() {
    var q = alertState.q.trim().toLowerCase();
    return DATA.threats.filter(function (t) {
      if (alertState.sev !== 'all' && t.sev !== alertState.sev) return false;
      if (!q) return true;
      return (t.user + ' ' + t.ip + ' ' + t.action + ' ' + t.country + ' ' + t.threat + ' ' + t.id)
        .toLowerCase().indexOf(q) !== -1;
    });
  }

  function renderAlerts() {
    var list = $('#alertList');
    var countEl = $('#alertResultCount');
    if (!list) return;
    var all = filteredThreats();
    countEl && (countEl.textContent = fmtNum(all.length) + ' alert' + (all.length === 1 ? '' : 's'));

    var totalPages = Math.max(1, Math.ceil(all.length / alertState.perPage));
    if (alertState.page > totalPages) alertState.page = totalPages;
    var start = (alertState.page - 1) * alertState.perPage;
    var pageItems = all.slice(start, start + alertState.perPage);

    if (!pageItems.length) {
      list.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><div>No alerts match your filters.</div></div>';
      renderPagination('#alertPagination', 1, 1, function () {});
      return;
    }

    list.innerHTML = pageItems.map(function (t) {
      var isOpen = !!alertState.openIds[t.id];
      var sevColor = SEV_COLOR[t.sev] || 'var(--text-faint)';
      var sevVar = SEV_VAR[t.sev];
      return '<div class="alert-card' + (isOpen ? ' open' : '') + '" data-id="' + t.id + '">' +
        '<div class="alert-card-head" role="button" tabindex="0">' +
        '<span class="sev-pill" style="background:var(' + sevVar + '-dim, rgba(255,255,255,.08)); color:' + sevColor + '">' + esc(t.sev) + '</span>' +
        '<span class="alert-title">' + esc(t.threat) + '</span>' +
        '<span class="alert-id">#' + t.id + '</span>' +
        '<svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>' +
        '</div>' +
        '<div class="alert-card-body">' +
        '<div class="alert-meta-grid">' +
        metaField('User', t.user) +
        metaField('Action', t.action) +
        metaField('IP', t.ip) +
        metaField('Country', t.country) +
        '</div>' +
        '<div class="narrative"><b>Timestamp:</b> <span class="mono">' + esc(t.ts) + '</span><br><br><b>Analysis:</b> ' + esc(t.reason) + '</div>' +
        '<div class="recommend">' + formatRecommendation(t.rec) + '</div>' +
        '</div></div>';
    }).join('');

    $all('.alert-card-head', list).forEach(function (head) {
      var card = head.closest('.alert-card');
      function toggle() {
        var id = card.getAttribute('data-id');
        alertState.openIds[id] = !alertState.openIds[id];
        card.classList.toggle('open');
      }
      head.addEventListener('click', toggle);
      head.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    });

    renderPagination('#alertPagination', alertState.page, totalPages, function (p) {
      alertState.page = p;
      renderAlerts();
    });
  }

  function metaField(label, value) {
    return '<div class="meta-field"><div class="meta-label">' + esc(label) + '</div><div class="meta-value" title="' + esc(value) + '">' + esc(value) + '</div></div>';
  }

  function formatRecommendation(text) {
    if (!text) return '';
    var safe = esc(text);
    safe = safe.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
    safe = safe.replace(/\n/g, '<br>');
    return safe;
  }

  function renderPagination(hostSel, page, totalPages, onChange) {
    var host = $(hostSel);
    if (!host) return;
    if (totalPages <= 1) { host.innerHTML = ''; return; }
    host.innerHTML =
      '<button class="page-btn" data-pg="prev" ' + (page <= 1 ? 'disabled' : '') + '>Prev</button>' +
      '<span class="page-info">Page ' + page + ' of ' + totalPages + '</span>' +
      '<button class="page-btn" data-pg="next" ' + (page >= totalPages ? 'disabled' : '') + '>Next</button>';
    var prev = host.querySelector('[data-pg="prev"]'), next = host.querySelector('[data-pg="next"]');
    if (prev) prev.addEventListener('click', function () { if (page > 1) onChange(page - 1); });
    if (next) next.addEventListener('click', function () { if (page < totalPages) onChange(page + 1); });
  }

  function initAlertsControls() {
    var search = $('#alertSearch');
    if (search) search.addEventListener('input', debounce(function () {
      alertState.q = search.value;
      alertState.page = 1;
      renderAlerts();
    }, 150));

    $all('#severityChips .chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        $all('#severityChips .chip').forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        alertState.sev = chip.getAttribute('data-sev');
        alertState.page = 1;
        renderAlerts();
      });
    });
  }

  /* ------------------------------------------------------------------- */
  /* Log Explorer                                                         */
  /* ------------------------------------------------------------------- */
  var logState = { q: '', status: 'all', sortKey: 'id', sortDir: 1, page: 1, perPage: 50 };

  function filteredLogs() {
    var q = logState.q.trim().toLowerCase();
    var rows = DATA.logs;
    if (logState.status === 'threat') rows = rows.filter(function (r) { return !!r.sev; });
    if (q) {
      rows = rows.filter(function (r) {
        return (r.user + ' ' + r.ip + ' ' + r.action + ' ' + r.country + ' ' + r.status + ' ' + r.id)
          .toLowerCase().indexOf(q) !== -1;
      });
    }
    var key = logState.sortKey, dir = logState.sortDir;
    rows = rows.slice().sort(function (a, b) {
      var av = a[key], bv = b[key];
      if (av === null || av === undefined) av = '';
      if (bv === null || bv === undefined) bv = '';
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
    return rows;
  }

  function statusColor(status) { return status === 'Failed' ? 'var(--crit)' : 'var(--ok)'; }

  function renderLogExplorer() {
    var tbody = $('#logTableBody');
    var cardsHost = $('#logCards');
    var countEl = $('#logResultCount');
    if (!tbody) return;
    var all = filteredLogs();
    countEl && (countEl.textContent = fmtNum(all.length) + ' log' + (all.length === 1 ? '' : 's'));

    var totalPages = Math.max(1, Math.ceil(all.length / logState.perPage));
    if (logState.page > totalPages) logState.page = totalPages;
    var start = (logState.page - 1) * logState.perPage;
    var pageItems = all.slice(start, start + logState.perPage);

    if (!pageItems.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-faint); padding:30px;">No logs match your search.</td></tr>';
      if (cardsHost) cardsHost.innerHTML = '';
    } else {
      tbody.innerHTML = pageItems.map(function (r) {
        var sevCell = r.sev ? '<span class="sev-pill" style="background:var(' + SEV_VAR[r.sev] + '-dim); color:' + SEV_COLOR[r.sev] + '">' + esc(r.sev) + '</span>' : '<span style="color:var(--text-faint);">—</span>';
        return '<tr>' +
          '<td class="mono-cell">#' + r.id + '</td>' +
          '<td class="mono-cell">' + esc(r.ts) + '</td>' +
          '<td>' + esc(r.user) + '</td>' +
          '<td>' + esc(r.action) + '</td>' +
          '<td class="mono-cell">' + esc(r.ip) + '</td>' +
          '<td>' + esc(r.country) + '</td>' +
          '<td><span class="status-dot-cell"><span class="status-dot" style="background:' + statusColor(r.status) + '"></span>' + esc(r.status) + '</span></td>' +
          '<td>' + sevCell + '</td>' +
          '</tr>';
      }).join('');

      if (cardsHost) {
        cardsHost.innerHTML = pageItems.map(function (r) {
          var sevCell = r.sev ? '<span class="sev-pill" style="background:var(' + SEV_VAR[r.sev] + '-dim); color:' + SEV_COLOR[r.sev] + '">' + esc(r.sev) + '</span>' : '<span style="color:var(--text-faint); font-size:11.5px;">Normal</span>';
          return '<div class="log-mcard">' +
            '<div class="log-mcard-top"><span class="log-mcard-id">#' + r.id + ' · ' + esc(r.ts) + '</span>' + sevCell + '</div>' +
            '<div class="log-mcard-grid">' +
            metaField('User', r.user) + metaField('Action', r.action) +
            metaField('IP', r.ip) + metaField('Country', r.country) +
            '</div></div>';
        }).join('');
      }
    }

    renderPagination('#logPagination', logState.page, totalPages, function (p) {
      logState.page = p;
      renderLogExplorer();
    });

    $all('.log-table thead th').forEach(function (th) {
      var key = th.getAttribute('data-key');
      var caret = $('.sort-caret', th);
      if (!caret) return;
      caret.textContent = logState.sortKey === key ? (logState.sortDir === 1 ? '▲' : '▼') : '▲▼';
    });
  }

  function initLogExplorerControls() {
    var search = $('#logSearch');
    if (search) search.addEventListener('input', debounce(function () {
      logState.q = search.value;
      logState.page = 1;
      renderLogExplorer();
    }, 150));

    $all('#logStatusChips .chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        $all('#logStatusChips .chip').forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        logState.status = chip.getAttribute('data-status');
        logState.page = 1;
        renderLogExplorer();
      });
    });

    $all('.log-table thead th').forEach(function (th) {
      th.addEventListener('click', function () {
        var key = th.getAttribute('data-key');
        if (!key) return;
        if (logState.sortKey === key) { logState.sortDir *= -1; }
        else { logState.sortKey = key; logState.sortDir = 1; }
        logState.page = 1;
        renderLogExplorer();
      });
    });
  }

  /* ------------------------------------------------------------------- */
  /* Admin console                                                        */
  /* ------------------------------------------------------------------- */
  function renderAdmin() {
    var host = $('#accountList');
    if (!host) return;
    var accounts = DATA.accounts || [];
    if (!accounts.length) {
      host.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><div>No accounts on file.</div></div>';
      return;
    }
    host.innerHTML = accounts.map(function (a, idx) {
      var locked = !!a.is_locked;
      var initial = (a.username || '?').charAt(0).toUpperCase();
      return '<div class="account-row" data-idx="' + idx + '">' +
        '<div class="acct-avatar">' + esc(initial) + '</div>' +
        '<div class="acct-info"><div class="acct-name">' + esc(a.username) + '</div><div class="acct-role">' + esc(a.role) + '</div></div>' +
        '<div class="acct-status">' +
        '<div><div class="meta-label">Failed attempts</div><div class="meta-value">' + fmtNum(a.failed_attempts) + '</div></div>' +
        '<div><div class="meta-label">Locked until</div><div class="meta-value">' + esc(a.locked_until || '—') + '</div></div>' +
        '<span class="status-pill ' + (locked ? 'locked' : 'active') + '">' + (locked ? 'LOCKED' : 'ACTIVE') + '</span>' +
        (locked ? '<button class="unlock-btn" data-idx="' + idx + '">Unlock account</button>' : '') +
        '</div></div>';
    }).join('');

    $all('.unlock-btn', host).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var idx = parseInt(btn.getAttribute('data-idx'), 10);
        var acct = DATA.accounts[idx];
        if (!acct) return;
        acct.is_locked = 0;
        acct.failed_attempts = 0;
        acct.locked_until = null;
        renderAdmin();
        showToast('Account "' + acct.username + '" unlocked successfully.');
      });
    });
  }

  function showToast(msg) {
    var el = $('#toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(function () { el.classList.remove('show'); }, 2600);
  }

  /* ------------------------------------------------------------------- */
  /* Utils                                                                */
  /* ------------------------------------------------------------------- */
  function debounce(fn, wait) {
    var t;
    return function () {
      var args = arguments, ctx = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, wait);
    };
  }

  /* ------------------------------------------------------------------- */
  /* Boot                                                                 */
  /* ------------------------------------------------------------------- */
  function boot() {
    // 1. Session Guard: Return to login.html if not authenticated
    var sessionRaw = localStorage.getItem("meridian_session");
    if (!sessionRaw) {
      window.location.href = "login.html";
      return;
    }
    var session = JSON.parse(sessionRaw);

    // 2. Display logged-in user profile in the sidebar
    var nameEl = $('.user-name');
    var roleEl = $('.user-role');
    var avatarEl = $('.avatar');
    if (nameEl) nameEl.textContent = session.username;
    if (roleEl) roleEl.textContent = session.role.toUpperCase() + ' · SOC Team';
    if (avatarEl) avatarEl.textContent = session.username.charAt(0).toUpperCase();

    // 3. Logout action: clicking the user card logs out
    var foot = $('.sidebar-foot');
    if (foot) {
      foot.style.cursor = 'pointer';
      foot.title = 'Click to log out';
      foot.addEventListener('click', function () {
        localStorage.removeItem("meridian_session");
        window.location.href = "login.html";
      });
    }

    try { initNav(); } catch (e) { console.error('nav init failed', e); }
    try { initMobileSidebar(); } catch (e) { console.error('sidebar init failed', e); }
    try { initClock(); } catch (e) { console.error('clock init failed', e); }
    try { initGlobalSearch(); } catch (e) { console.error('global search init failed', e); }

    try { renderKpis(); } catch (e) { console.error('kpi render failed', e); }
    try { renderHourlyChart(); } catch (e) { console.error('hourly chart failed', e); }
    try { renderSeverityDonut(); } catch (e) { console.error('donut failed', e); }
    try { renderBarRows('#actionBars', OV.top_actions); } catch (e) { console.error('action bars failed', e); }
    try { renderBarRows('#countryBars', OV.top_countries); } catch (e) { console.error('country bars failed', e); }
    try { renderBarRows('#userBars', OV.top_risk_users); } catch (e) { console.error('user bars failed', e); }
    try { renderTicker(); } catch (e) { console.error('ticker failed', e); }

    try { initAlertsControls(); renderAlerts(); } catch (e) { console.error('alerts init failed', e); }
    try { initLogExplorerControls(); renderLogExplorer(); } catch (e) { console.error('log explorer init failed', e); }
    try { renderAdmin(); } catch (e) { console.error('admin render failed', e); }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
