/**
 * TrustVault - Appearance Theme Manager
 *
 * Implements Light, Dark, and System theme preferences with instant switching,
 * localStorage persistence (zero secrets), and dynamic OS color-scheme tracking.
 */
(function() {
  'use strict';

  var STORAGE_KEY = 'trustvault_theme_pref';

  /**
   * Safely reads theme preference from localStorage. Defaults to 'system'.
   */
  function getPreference() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'light' || saved === 'dark' || saved === 'system') {
        return saved;
      }
    } catch (e) {
      // Storage access blocked or restricted
    }
    return 'system';
  }

  /**
   * Safely writes theme preference to localStorage.
   */
  function savePreference(pref) {
    try {
      localStorage.setItem(STORAGE_KEY, pref);
    } catch (e) {
      // Storage access blocked
    }
  }

  /**
   * Checks if operating system currently prefers dark color scheme.
   */
  function isSystemDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  /**
   * Applies the theme preference immediately to the DOM and color-scheme.
   */
  function applyTheme(pref) {
    var effective = pref;
    if (pref === 'system') {
      effective = isSystemDark() ? 'dark' : 'light';
    }

    document.documentElement.setAttribute('data-theme', effective);
    document.documentElement.style.colorScheme = effective;
    updateSelectorUI(pref);
  }

  /**
   * Synchronizes active state across all theme switcher buttons on the page.
   */
  function updateSelectorUI(activePref) {
    var buttons = document.querySelectorAll('[data-theme-value]');
    for (var i = 0; i < buttons.length; i++) {
      var btn = buttons[i];
      var val = btn.getAttribute('data-theme-value');
      var isActive = (val === activePref);
      btn.setAttribute('aria-checked', isActive ? 'true' : 'false');
      if (isActive) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    }
  }

  /**
   * Initializes theme manager: binds clicks and system media query listener.
   */
  function initTheme() {
    var currentPref = getPreference();
    applyTheme(currentPref);

    // Bind click events on all theme switcher controls
    var buttons = document.querySelectorAll('[data-theme-value]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', function(e) {
        e.preventDefault();
        var selected = this.getAttribute('data-theme-value');
        if (selected === 'light' || selected === 'dark' || selected === 'system') {
          savePreference(selected);
          applyTheme(selected);
        }
      });
    }

    // Bind OS media query change listener to respond dynamically when preference is 'system'
    if (window.matchMedia) {
      var mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      var handleOSChange = function() {
        if (getPreference() === 'system') {
          applyTheme('system');
        }
      };

      if (mediaQuery.addEventListener) {
        mediaQuery.addEventListener('change', handleOSChange);
      } else if (mediaQuery.addListener) {
        mediaQuery.addListener(handleOSChange);
      }
    }
  }

  // Initialize as soon as DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
  } else {
    initTheme();
  }
})();
