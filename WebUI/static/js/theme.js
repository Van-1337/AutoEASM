/* Theme registry — ported from the ESET IPMS dashboard.
   Loaded synchronously in <head> so the stored palette applies before the
   first paint (no flash of the default theme). */

(function () {
    'use strict';

    var STORAGE_KEY = 'autoeasmTheme';
    var FALLBACK = 'dark';

    /* swatch = [surface, accent, secondary] — three dots per option. */
    var THEMES = [
        { id: 'dark',       name: 'Dark',       swatch: ['#080c14', '#38bdf8', '#22c55e'] },
        { id: 'light',      name: 'Light',      swatch: ['#f4f7f9', '#3b82f6', '#10b981'] },
        { id: 'milk',       name: 'Milk',       swatch: ['#f6f1e7', '#9a6736', '#4f8a5b'] },
        { id: 'tiffany',    name: 'Tiffany',    swatch: ['#eef9f8', '#0aa5a1', '#2f8f6a'] },
        { id: 'rolex',      name: 'Rolex',      swatch: ['#041a12', '#c9a227', '#34a06a'] },
        { id: 'police',     name: 'Police',     swatch: ['#050c18', '#0057b7', '#ffd22f'] },
        { id: 'vintage',    name: 'Vintage',    swatch: ['#e8dcc3', '#8a5a2b', '#9c3428'] },
        { id: 'cyber',      name: 'Cyber',      swatch: ['#070312', '#00e5ff', '#ff3d81'] },
        { id: 'vyshyvanka', name: 'Vyshyvanka', swatch: ['#eef4fc', '#0057b7', '#ffd22f'] },
        { id: 'anime',      name: 'Anime',      swatch: ['#fdeef6', '#c81f66', '#9b5cf6'] }
    ];

    function find(id) {
        for (var i = 0; i < THEMES.length; i += 1) {
            if (THEMES[i].id === id) { return THEMES[i]; }
        }
        return null;
    }

    function stored() {
        try {
            var theme = find(window.localStorage.getItem(STORAGE_KEY));
            return theme ? theme.id : FALLBACK;
        } catch (err) {
            return FALLBACK;
        }
    }

    function remember(id) {
        try {
            window.localStorage.setItem(STORAGE_KEY, id);
        } catch (err) { /* ignore */ }
    }

    window.AUTOEASM_THEME = {
        list: THEMES,
        fallback: FALLBACK,
        find: find,
        stored: stored,
        remember: remember
    };

    document.documentElement.setAttribute('data-theme', stored());
})();