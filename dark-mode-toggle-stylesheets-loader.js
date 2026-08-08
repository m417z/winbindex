'use strict';

// Writes out the theme stylesheets, honoring the theme pinned with
// dark-mode-toggle. The links are kept in a noscript element so that without
// JavaScript they still apply, following the system preference.
//
// The stylesheets have to be written from here, before the browser starts
// laying out the page, or the pinned theme would flash the other theme first.
(function () {
    var stylesheets = document.getElementById('dark-mode-toggle-stylesheets').textContent;

    var mode = null;
    try {
        mode = localStorage.getItem('dark-mode-toggle');
    } catch (e) {
        // Storage can be inaccessible, fall back to the system preference.
    }

    var lightMedia = /\(\s*prefers-color-scheme\s*:\s*light\s*\)/gi;
    var darkMedia = /\(\s*prefers-color-scheme\s*:\s*dark\s*\)/gi;

    // Adding 'all' makes the pinned theme match unconditionally, and 'and not
    // all' makes the other one never match.
    switch (mode) {
    case 'light':
        stylesheets = stylesheets.replace(lightMedia, '$&, all').replace(darkMedia, '$& and not all');
        break;

    case 'dark':
        stylesheets = stylesheets.replace(darkMedia, '$&, all').replace(lightMedia, '$& and not all');
        break;
    }

    document.write(stylesheets);
})();
