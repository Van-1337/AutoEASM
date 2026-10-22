/* AutoEASM Web UI — client logic.
   Builds the CLI command from the toggles (live preview), starts scans,
   polls the captured console output and manages views. */

(function () {
    'use strict';

    var CFG_KEY = 'autoeasmConfig';

    /* ------------------------------------------------------- module registry */
    /* key → {name, desc, flag} — flag is what appears in the command when the
       module is switched OFF (the disable-flags of main.py). */
    var MODULES = [
        { key: 'subdomains',      name: 'mod_subdomains',     desc: 'mod_subdomains_desc',     flag: '-no-subdomains' },
        { key: 'nuclei',          name: 'mod_nuclei',         desc: 'mod_nuclei_desc',         flag: '-no-vulns' },
        { key: 'takeover',        name: 'mod_takeover',       desc: 'mod_takeover_desc',       flag: '-no-takeover' },
        { key: 'dast',            name: 'mod_dast',           desc: 'mod_dast_desc',           flag: '-no-params' },
        { key: 'crawl',           name: 'mod_crawl',          desc: 'mod_crawl_desc',          flag: '-no-crawl' },
        { key: 'fuzz',            name: 'mod_fuzz',           desc: 'mod_fuzz_desc',           flag: '-no-dirs' },
        { key: 'byp4xx',          name: 'mod_byp4xx',         desc: 'mod_byp4xx_desc',         flag: '-no-bypass' },
        { key: 'waf_bypass',      name: 'mod_waf_bypass',     desc: 'mod_waf_bypass_desc',     flag: '-no-waf' },
        { key: 'inactive',        name: 'mod_inactive',       desc: 'mod_inactive_desc',       flag: '-no-inactive' },
        { key: 'social',          name: 'mod_social',         desc: 'mod_social_desc',         flag: '-no-social' },
        { key: 'postman',         name: 'mod_postman',        desc: 'mod_postman_desc',        flag: '-no-postman' },
        { key: 'leakix',          name: 'mod_leakix',         desc: 'mod_leakix_desc',         flag: '-no-leakix' },
        { key: 'securitytrails',  name: 'mod_securitytrails', desc: 'mod_securitytrails_desc', flag: '-no-history' },
        { key: 'deps',            name: 'mod_deps',           desc: 'mod_deps_desc',           flag: '-no-deps' },
        { key: 'katana_headless', name: 'mod_katana_headless', desc: 'mod_katana_headless_desc', flag: '-no-browser' },
        { key: 'katana_forms',    name: 'mod_katana_forms',   desc: 'mod_katana_forms_desc',   flag: '-no-forms' }
    ];
    var OUTPUTS = [
        { key: 'open_report', name: 'out_open_report', desc: 'out_open_report_desc', on: true },
        { key: 'markdown',    name: 'out_markdown',    desc: 'out_markdown_desc',    on: false },
        { key: 'verbose',     name: 'out_verbose',     desc: 'out_verbose_desc',     on: false }
    ];
    /* -burp-all sends everything -burp sends plus URLs behind a WAF; -burp-dirs and
       -burp-hits are separate toggles because main.py accepts any combination. */
    var BURP_ENDPOINTS = [
        { key: 'off',   label: 'burp_off' },
        { key: 'nowaf', label: 'burp_nowaf', flag: '-burp' },
        { key: 'all',   label: 'burp_all',   flag: '-burp-all' }
    ];

    /* Toggles that do nothing while another option is off. The flag is still
       sent (harmless) — the row is only marked so the setup isn't misleading.
       Keys are module keys or ids of the static checkboxes. */
    var REQUIRES = {
        dast:            function () { return !state.modules.nuclei && 'moot_nuclei'; },
        katana_headless: function () { return !state.modules.crawl && 'moot_crawl'; },
        katana_forms:    function () { return !state.modules.crawl && 'moot_crawl'; },
        byp4xx:          function () { return !state.modules.fuzz && 'moot_fuzz'; },
        subdomains:      function () { return state.ip_mode && 'moot_ip'; },
        postman:         function () { return state.ip_mode && 'moot_ip'; },
        'burp-fuzz':     function () { return !state.modules.fuzz && 'moot_dirs'; },
        'burp-bypass':   function () {
            return !(state.modules.waf_bypass || state.modules.inactive || state.modules.securitytrails) &&
                'moot_bypass';
        }
    };

    /* ------------------------------------------------------------- helpers */
    function t(key, vars) { return window.AUTOEASM_I18N.t(key, vars); }
    function $(sel, root) { return (root || document).querySelector(sel); }
    function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

    var state = {
        domains: [],
        exclude: [],
        modules: {},           // key → bool
        outputs: {},           // key → bool
        load_level: 2,
        detail_level: 2,
        rate_limit: '',
        all_ports: false,
        ip_mode: false,
        report_name: '',
        burp: { endpoints: 'off', fuzz: false, bypass: false, proxy: '127.0.0.1:8080' },
        qualys: false,
        advanced: { user_agent: '', templates: '', wordlist: '', leakix_key: '', securitytrails_key: '' }
    };
    MODULES.concat(OUTPUTS).forEach(function (m) {
        if (!(m.key in state.modules) && MODULES.indexOf(m) >= 0) { state.modules[m.key] = true; }
        if (OUTPUTS.indexOf(m) >= 0) { state.outputs[m.key] = m.on; }
    });

    /* ------------------------------------------------------------ rendering */
    function buildToggleRow(m, group) {
        var row = document.createElement('label');
        row.className = 'toggle-row';
        row.dataset.key = m.key;
        row.dataset.group = group;
        row.dataset.nameKey = m.name;
        row.dataset.descKey = m.desc;
        row.innerHTML =
            '<span class="toggle-info">' +
            '<span class="toggle-name"><span class="i18n-name"></span>' + (m.flag ? '<span class="toggle-flag">' + m.flag + '</span>' : '') + '</span>' +
            '<span class="toggle-desc"></span>' +
            '<span class="toggle-moot"></span>' +
            '</span>' +
            '<span class="switch"><input type="checkbox" checked><span class="track"></span><span class="thumb"></span></span>';
        return row;
    }

    function renderModules() {
        var grid = $('#modules-grid');
        MODULES.forEach(function (m) { grid.appendChild(buildToggleRow(m, 'modules')); });
        var ogrid = $('#outputs-grid');
        OUTPUTS.forEach(function (m) { ogrid.appendChild(buildToggleRow(m, 'outputs')); });

        var seg = $('#burp-seg');
        BURP_ENDPOINTS.forEach(function (mode) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.dataset.mode = mode.key;
            btn.dataset.i18nKey = mode.label;
            btn.textContent = t(mode.label);
            seg.appendChild(btn);
        });
        paintGenerated();
    }

    function paintGenerated() {
        $$('.toggle-row[data-name-key]').forEach(function (row) {
            var name = $('.i18n-name', row);
            var desc = $('.toggle-desc', row);
            if (name) { name.textContent = t(row.dataset.nameKey); }
            if (desc) { desc.textContent = t(row.dataset.descKey); }
        });
        $$('#burp-seg button').forEach(function (btn) {
            if (btn.dataset.i18nKey) { btn.textContent = t(btn.dataset.i18nKey); }
        });
        var empty = $('#terminal .terminal-empty');
        if (empty) { empty.textContent = t('term_wait'); }
        $('#topbar-title').textContent = t(viewTitles[currentView]);
        setScanStatus(scanStatus);
        applyDependencies();
    }

    function explainError(data) {
        if (data && data.error_code) { return t(data.error_code, data); }
        return (data && data.error) || t('launch_failed');
    }

    function renderThemes() {
        var row = $('#theme-row');
        var T = window.AUTOEASM_THEME;
        T.list.forEach(function (theme) {
            var dot = document.createElement('button');
            dot.type = 'button';
            dot.className = 'theme-dot' + (theme.id === T.stored() ? ' active' : '');
            dot.title = theme.name;
            dot.innerHTML = theme.swatch.map(function (c) { return '<i style="background:' + c + '"></i>'; }).join('');
            dot.addEventListener('click', function () {
                document.documentElement.setAttribute('data-theme', theme.id);
                T.remember(theme.id);
                $$('.theme-dot').forEach(function (d) { d.classList.remove('active'); });
                dot.classList.add('active');
            });
            row.appendChild(dot);
        });
    }

    /* --------------------------------------------------------- state I/O */
    function readForm() {
        state.domains = $('#domains').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
        state.exclude = $('#exclude').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
        state.rate_limit = $('#rate-limit').value.trim();
        state.report_name = $('#report-name').value.trim();
        state.all_ports = $('#all-ports').checked;
        state.ip_mode = $('#ip-mode').checked;
        state.qualys = $('#qualys').checked;
        state.advanced.user_agent = $('#ua').value.trim();
        state.advanced.templates = $('#tem').value.trim();
        state.advanced.wordlist = $('#sw').value.trim();
        state.advanced.leakix_key = $('#leakix-key').value.trim();
        state.advanced.securitytrails_key = $('#st-key').value.trim();
        state.burp.proxy = $('#burp-proxy').value.trim() || '127.0.0.1:8080';
        state.burp.fuzz = $('#burp-fuzz').checked;
        state.burp.bypass = $('#burp-bypass').checked;

        $$('.toggle-row').forEach(function (row) {
            var group = row.dataset.group;
            if (!group) { return; }              // static rows (all-ports, ip-mode, qualys)
            var box = $('input[type=checkbox]', row);
            state[group][row.dataset.key] = box.checked;
            row.classList.toggle('is-off', !box.checked);
        });
    }

    function writeForm() {
        $('#domains').value = state.domains.join('\n');
        $('#exclude').value = state.exclude.join('\n');
        $('#rate-limit').value = state.rate_limit;
        $('#report-name').value = state.report_name;
        $('#all-ports').checked = state.all_ports;
        $('#ip-mode').checked = state.ip_mode;
        $('#qualys').checked = state.qualys;
        $('#ua').value = state.advanced.user_agent;
        $('#tem').value = state.advanced.templates;
        $('#sw').value = state.advanced.wordlist;
        $('#leakix-key').value = state.advanced.leakix_key;
        $('#st-key').value = state.advanced.securitytrails_key;
        $('#burp-proxy').value = state.burp.proxy;
        $('#burp-fuzz').checked = state.burp.fuzz;
        $('#burp-bypass').checked = state.burp.bypass;
        setSeg('#ll-seg', 'level', state.load_level);
        setSeg('#ld-seg', 'level', state.detail_level);
        setSeg('#burp-seg', 'mode', state.burp.endpoints);
        $$('.toggle-row').forEach(function (row) {
            var group = row.dataset.group;
            if (!group) { return; }              // static rows keep their own state
            var box = $('input[type=checkbox]', row);
            box.checked = state[group][row.dataset.key];
            row.classList.toggle('is-off', !box.checked);
        });
    }

    function saveConfig() {
        try { localStorage.setItem(CFG_KEY, JSON.stringify(state)); } catch (e) { /* ignore */ }
    }
    function loadConfig() {
        try {
            var saved = JSON.parse(localStorage.getItem(CFG_KEY) || 'null');
            if (saved) { mergeState(saved); }
        } catch (e) { /* ignore */ }
    }
    /* Older builds stored a single burp.mode: off | all | nowaf | fuzz | bypass. */
    function migrateBurp(burp) {
        if (!burp || !('mode' in burp)) { return burp; }
        var migrated = { endpoints: 'off', fuzz: burp.mode === 'fuzz', bypass: burp.mode === 'bypass' };
        if (burp.mode === 'all' || burp.mode === 'nowaf') { migrated.endpoints = burp.mode; }
        if (burp.proxy) { migrated.proxy = burp.proxy; }
        return migrated;
    }
    function mergeState(saved) {
        if (saved.burp) { saved.burp = migrateBurp(saved.burp); }
        Object.keys(saved).forEach(function (k) {
            if (k === 'modules' || k === 'outputs' || k === 'advanced' || k === 'burp') {
                state[k] = Object.assign(state[k], saved[k]);
            } else {
                state[k] = saved[k];
            }
        });
    }

    /* ------------------------------------------------------------ segments */
    function setSeg(sel, attr, value) {
        $$(sel + ' button').forEach(function (btn) {
            btn.classList.toggle('active', String(btn.dataset[attr]) === String(value));
        });
    }
    function segClick(sel, attr, apply) {
        $(sel).addEventListener('click', function (event) {
            var btn = event.target.closest('button');
            if (!btn) { return; }
            setSeg(sel, attr, btn.dataset[attr]);
            apply(btn.dataset[attr]);
            updateCommand();
        });
    }

    /* ------------------------------------------------------ command builder */
    function esc(arg) {
        return /\s/.test(arg) ? '"' + arg + '"' : arg;
    }

    function buildCommand() {
        var parts = ['python', 'main.py'];
        state.domains.forEach(function (d) { parts.push('-domain', esc(d)); });
        MODULES.forEach(function (m) {
            if (!state.modules[m.key]) { parts.push('<span class="cmd-flag">' + m.flag + '</span>'); }
        });
        if (state.load_level !== 2) { parts.push('-load', state.load_level); }
        if (state.detail_level !== 2) { parts.push('-deep', state.detail_level); }
        if (state.rate_limit) { parts.push('-rate', state.rate_limit); }
        if (state.all_ports) { parts.push('<span class="cmd-flag">-all-ports</span>'); }
        if (state.ip_mode) { parts.push('<span class="cmd-flag">-ip</span>'); }
        state.exclude.forEach(function (h) { parts.push('-exclude', esc(h)); });
        if (state.report_name) { parts.push('-report', esc(state.report_name)); }
        if (!state.outputs.open_report) { parts.push('<span class="cmd-flag">-no-open</span>'); }
        if (state.outputs.markdown) { parts.push('<span class="cmd-flag">-markdown</span>'); }
        if (state.outputs.verbose) { parts.push('<span class="cmd-flag">-verbose</span>'); }
        var burpFlags = burpFlagList();
        if (burpFlags.length) {
            burpFlags.forEach(function (flag) { parts.push('<span class="cmd-flag">' + flag + '</span>'); });
            parts.push('-proxy', esc(state.burp.proxy));
        }
        if (state.qualys) { parts.push('<span class="cmd-flag">-qualys</span>'); }
        if (state.advanced.user_agent) { parts.push('-user-agent', esc(state.advanced.user_agent)); }
        if (state.advanced.templates) { parts.push('-templates', esc(state.advanced.templates)); }
        if (state.advanced.wordlist) { parts.push('-wordlist', esc(state.advanced.wordlist)); }
        return parts.join(' ');
    }

    function burpFlagList() {
        var flags = [];
        var endpoint = BURP_ENDPOINTS.filter(function (m) { return m.key === state.burp.endpoints; })[0];
        if (endpoint && endpoint.flag) { flags.push(endpoint.flag); }
        if (state.burp.fuzz) { flags.push('-burp-dirs'); }
        if (state.burp.bypass) { flags.push('-burp-hits'); }
        return flags;
    }

    function applyDependencies() {
        $$('.toggle-row').forEach(function (row) {
            var box = $('input[type=checkbox]', row);
            var rule = REQUIRES[row.dataset.key || box.id];
            var reason = rule && box.checked ? rule() : false;
            row.classList.toggle('is-moot', !!reason);
            var note = $('.toggle-moot', row);
            if (note) { note.textContent = reason ? t('moot_prefix') + t(reason) : ''; }
        });
    }

    function updateCommand() {
        readForm();
        applyDependencies();
        $('#burp-proxy').disabled = burpFlagList().length === 0;
        var badExclude = state.exclude.some(function (host) { return /[*?]/.test(host); });
        $('#exclude-warn').hidden = !badExclude;
        $('#cmd-preview').innerHTML = buildCommand();
        $('#launch-btn').disabled = state.domains.length === 0 || badExclude;
        saveConfig();
    }

    function importDomainsFile(file) {
        var reader = new FileReader();
        reader.onload = function () {
            var domains = $('#domains').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
            String(reader.result).replace(/^\uFEFF/, '').split(/\r?\n/).forEach(function (line) {
                line = line.trim();
                if (line && domains.indexOf(line) < 0) { domains.push(line); }
            });
            $('#domains').value = domains.join('\n');
            updateCommand();
        };
        reader.readAsText(file);
    }

    /* -------------------------------------------------------------- views */
    var views = { scan: 'view-scan', monitor: 'view-monitor', reports: 'view-reports', flow: 'view-flow' };
    var viewTitles = { scan: 'view_scan', monitor: 'view_monitor', reports: 'view_reports', flow: 'view_flow' };
    var currentView = 'scan';
    var scanStatus = 'ready';
    function showView(name) {
        currentView = name;
        Object.keys(views).forEach(function (key) {
            $('#' + views[key]).hidden = key !== name;
        });
        $$('.nav-item[data-view]').forEach(function (item) {
            item.classList.toggle('active', item.dataset.view === name);
        });
        $('#topbar-title').textContent = t(viewTitles[name]);
        if (name === 'reports') { refreshReports(); }
        if (name === 'flow') { document.dispatchEvent(new CustomEvent('autoeasm-flow-shown')); }
    }

    /* ------------------------------------------------------------ monitor */
    var monitor = { cursor: 0, timer: null, lastTotal: -1 };

    function lineClass(text) {
        if (/^\[\*\]/.test(text)) { return 'ln-head'; }
        if (/^\[\+\]/.test(text)) { return 'ln-ok'; }
        if (/^\[(e|!)\]/.test(text)) { return 'ln-err'; }
        return '';
    }

    function appendLines(lines) {
        var term = $('#terminal');
        var empty = $('.terminal-empty', term);
        if (empty) { empty.remove(); }
        var autoscroll = term.scrollHeight - term.scrollTop - term.clientHeight < 60;
        lines.forEach(function (text) {
            var div = document.createElement('div');
            div.className = lineClass(text);
            div.textContent = text;
            term.appendChild(div);
        });
        if (autoscroll) { term.scrollTop = term.scrollHeight; }
    }

    function setChip(chip, status) {
        chip.className = 'chip ' + ({
            idle: 'chip-idle', running: 'chip-run', ok: 'chip-ok', err: 'chip-err'
        }[status]);
        chip.innerHTML = '<span class="chip-dot"></span>' + t({
            idle: 'chip_idle', running: 'chip_running', ok: 'chip_ok', err: 'chip_err'
        }[status]);
    }

    function setScanStatus(status) {
        scanStatus = status;
        setChip($('#monitor-chip'), status === 'ready' ? 'idle' : status);
        var global = $('#global-chip');
        setChip(global, status === 'ready' ? 'idle' : status);
        if (status === 'ready') { global.lastChild.textContent = t('chip_ready'); }
        global.title = status === 'ready' ? '' : t('chip_open');
    }

    function poll() {
        fetch('/api/scan/status?since=' + monitor.cursor)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.total > monitor.lastTotal || data.lines.length) {
                    appendLines(data.lines);
                    monitor.cursor = data.total;
                    monitor.lastTotal = data.total;
                }
                if (data.running) {
                    setScanStatus('running');
                    $('#skip-btn').disabled = false;
                    $('#stop-btn').disabled = false;
                } else {
                    $('#skip-btn').disabled = true;
                    $('#stop-btn').disabled = true;
                    setScanStatus(data.exit_code === 0 ? 'ok' : 'err');
                    if (monitor.timer) {
                        clearInterval(monitor.timer);
                        monitor.timer = null;
                        appendLines(['', t('scan_finished', { code: data.exit_code })]);
                        refreshReports();
                    }
                }
            })
            .catch(function () { /* transient network hiccup: keep polling */ });
    }

    function startPolling() {
        monitor.cursor = 0;
        monitor.lastTotal = -1;
        $('#terminal').innerHTML = '<div class="terminal-empty">' + t('term_wait') + '</div>';
        if (monitor.timer) { clearInterval(monitor.timer); }
        monitor.timer = setInterval(poll, 1500);
        poll();
    }

    /* ------------------------------------------------------------ reports */
    function fmtSize(bytes) {
        if (bytes > 1048576) { return (bytes / 1048576).toFixed(1) + t('mb'); }
        if (bytes > 1024) { return (bytes / 1024).toFixed(1) + t('kb'); }
        return bytes + t('b');
    }
    function fmtTime(unix) {
        var locales = { uk: 'uk-UA', ru: 'ru-RU', en: 'en-GB', pl: 'pl-PL' };
        return new Date(unix * 1000).toLocaleString(locales[window.AUTOEASM_I18N.current()] || 'ru-RU');
    }

    function refreshReports() {
        fetch('/api/reports').then(function (r) { return r.json(); }).then(function (data) {
            var list = $('#reports-list');
            list.innerHTML = '';
            if (!data.reports.length) {
                list.innerHTML = '<div class="list-empty">' + t('reports_empty') + '</div>';
                return;
            }
            data.reports.forEach(function (rep) {
                var row = document.createElement('div');
                row.className = 'list-row';
                row.innerHTML =
                    '<span><span class="list-name">' + rep.name + '</span><br>' +
                    '<span class="list-meta">' + fmtTime(rep.mtime) + ' · ' + fmtSize(rep.size) + '</span></span>' +
                    '<a class="btn btn-small" target="_blank" rel="noopener" href="/api/report/' + encodeURIComponent(rep.name) + '">' + t('open') + '</a>';
                list.appendChild(row);
            });
        });
    }

    /* --------------------------------------------------------------- boot */
    function launch() {
        readForm();
        if (!state.domains.length) { return; }
        $('#launch-btn').disabled = true;
        fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(state)
        })
            .then(function (r) { return r.json().then(function (data) { return { ok: r.ok, data: data }; }); })
            .then(function (res) {
                if (!res.ok) {
                    alert(explainError(res.data));
                    return;
                }
                $('#monitor-command').textContent = 'python ' + (res.data.command || '');
                showView('monitor');
                startPolling();
            })
            .catch(function (err) { alert(t('net_error', { detail: err })); })
            .finally(updateCommand);
    }

    document.addEventListener('DOMContentLoaded', function () {
        renderModules();
        renderThemes();
        loadConfig();
        writeForm();
        updateCommand();

        /* live command preview */
        $('#view-scan').addEventListener('input', updateCommand);
        $('#view-scan').addEventListener('change', updateCommand);
        segClick('#ll-seg', 'level', function (v) { state.load_level = parseInt(v, 10); });
        segClick('#ld-seg', 'level', function (v) { state.detail_level = parseInt(v, 10); });
        segClick('#burp-seg', 'mode', function (v) { state.burp.endpoints = v; });
        $('#domains-file-btn').addEventListener('click', function () { $('#domains-file').click(); });
        $('#domains-file').addEventListener('change', function (event) {
            if (event.target.files[0]) { importDomainsFile(event.target.files[0]); }
            event.target.value = '';
        });

        /* navigation */
        $$('.nav-item[data-view]').forEach(function (item) {
            item.addEventListener('click', function () { showView(item.dataset.view); });
        });

        /* launch / control */
        $('#launch-btn').addEventListener('click', launch);
        $('#copy-btn').addEventListener('click', function () {
            readForm();
            var plain = buildCommand().replace(/<[^>]+>/g, '');
            navigator.clipboard.writeText(plain).then(function () {
                var btn = $('#copy-btn');
                btn.textContent = t('copied');
                setTimeout(function () { btn.textContent = t('copy_cmd'); }, 1600);
            });
        });
        $('#stop-btn').addEventListener('click', function () {
            fetch('/api/scan/stop', { method: 'POST' }).then(function () { poll(); });
        });
        $('#skip-btn').addEventListener('click', function () {
            fetch('/api/scan/skip', { method: 'POST' })
                .then(function (r) { return r.json(); })
                .then(function (data) { if (!data.ok) { alert(explainError(data) || t('skip_failed_fallback')); } });
        });
        $('#back-btn').addEventListener('click', function () { showView('scan'); });
        $('#global-chip').addEventListener('click', function () {
            if (!$('#global-chip').classList.contains('chip-idle')) { showView('monitor'); }
        });
        $('#refresh-reports').addEventListener('click', refreshReports);
        document.addEventListener('autoeasm-lang', function () {
            paintGenerated();
            if (currentView === 'reports') { refreshReports(); }
        });

        /* reflect an already-running scan (e.g. page reload mid-scan) */
        fetch('/api/scan/status').then(function (r) { return r.json(); }).then(function (data) {
            if (data.running || data.lines.length) {
                $('#monitor-command').textContent = 'python ' + (data.command || '');
                showView('monitor');
                startPolling();
            }
        });
    });
})();