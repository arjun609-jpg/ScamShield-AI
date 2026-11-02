/* ScamShield AI : theme.js (light / dark toggle) */
(function () {
  var KEY = "scamshield-theme";
  var root = document.documentElement;

  function savedTheme() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var btn = document.getElementById("themeToggle");
    if (btn) {
      btn.textContent = theme === "light" ? "\uD83C\uDF19" : "\u2600\uFE0F";
      btn.setAttribute("aria-label", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
      btn.title = theme === "light" ? "Switch to dark theme" : "Switch to light theme";
    }
    window.dispatchEvent(new Event("themechange"));
  }

  // Runs in <head>, so the saved theme is set before the page is drawn (no flash).
  applyTheme(savedTheme() === "light" ? "light" : "dark");

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("themeToggle");
    applyTheme(root.getAttribute("data-theme"));   // sets the button icon
    if (btn) {
      btn.addEventListener("click", function () {
        var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
        try { localStorage.setItem(KEY, next); } catch (e) {}
        applyTheme(next);
      });
    }
  });
})();