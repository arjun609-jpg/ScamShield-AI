"use strict";

/* ============ ScamShield AI : auth.js ============
   Real authentication with Supabase Auth (email + password).

   - Passwords go to Supabase over HTTPS. This app never stores them.
   - Only the PUBLISHABLE (anon) key belongs here. NEVER put the
     service_role / secret key in any file of this website.
   - Hiding the dashboard in the browser is the visible part of access
     control. Your data is protected on the server by Row Level Security
     (see supabase-setup.sql). */

(function () {
  /* ------------------------------------------------------------
     1. Your Supabase project settings (these two values are public by design)
  ------------------------------------------------------------ */
  const SUPABASE_URL = "https://ptzgnpvokdktfmoijuco.supabase.co";
  const SUPABASE_KEY = "sb_publishable_0eqjv6bbZPQxEDEQHqD_rg_NxNx5eJx";

  const $ = (id) => document.getElementById(id);
  const REMEMBER_KEY = "scamshield.remember";
  const VIEWS = ["loading", "login", "signup", "forgot", "reset", "verify"];
  const MSG_IDS = ["msgLogin", "msgSignup", "msgForgot", "msgReset", "msgVerify"];
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  // Read hints from the address bar BEFORE the Supabase client cleans it.
  const hashParams = new URLSearchParams(window.location.hash.slice(1));
  let recoveryMode = hashParams.get("type") === "recovery";
  let justVerified = hashParams.get("type") === "signup";
  const linkError = hashParams.get("error_description") || hashParams.get("error")
    ? (hashParams.get("error_code") === "otp_expired"
      ? "That link has expired or was already used. Request a new one."
      : "That link is not valid. Request a new one.")
    : "";
  if (linkError) window.history.replaceState(null, "", window.location.pathname + window.location.search);

  // Where Supabase sends people after they click an email link.
  // Must be listed under Authentication > URL Configuration > Redirect URLs.
  const REDIRECT_URL = window.location.origin + window.location.pathname.replace(/index\.html$/, "");

  let sb = null;
  let shownUserId = null;
  let currentView = "loading";
  let pendingEmail = "";
  let cooldownTimer = null;
  let justSignedIn = false;
  let toastTimer = null;

  /* ------------------------------------------------------------
     2. Session storage ("Remember session")
     Supabase keeps a session TOKEN (never the password). Remembered ->
     localStorage (survives closing the browser). Not remembered ->
     sessionStorage (ends when the tab closes).
  ------------------------------------------------------------ */
  function wantsRemember() {
    try { return window.localStorage.getItem(REMEMBER_KEY) !== "0"; } catch (e) { return true; }
  }

  const authStorage = {
    getItem(key) {
      try {
        const a = window.localStorage.getItem(key);
        return a !== null ? a : window.sessionStorage.getItem(key);
      } catch (e) { return null; }
    },
    setItem(key, value) {
      try {
        const keep = wantsRemember();
        (keep ? window.localStorage : window.sessionStorage).setItem(key, value);
        (keep ? window.sessionStorage : window.localStorage).removeItem(key);
      } catch (e) { /* storage blocked */ }
    },
    removeItem(key) {
      try { window.localStorage.removeItem(key); window.sessionStorage.removeItem(key); } catch (e) { /* ignore */ }
    }
  };

  /* ------------------------------------------------------------
     3. Small UI helpers
  ------------------------------------------------------------ */
  function msg(id, text, type) {
    const el = $(id);
    if (!el) return;
    el.textContent = text || "";
    el.className = "auth-msg " + (type || "error");
    el.setAttribute("role", type === "success" || type === "info" ? "status" : "alert");
    el.hidden = !text;
  }

  function clearMsgs() {
    MSG_IDS.forEach((id) => msg(id, ""));
    document.querySelectorAll(".auth-form [aria-invalid]").forEach((el) => el.removeAttribute("aria-invalid"));
  }

  function fail(msgId, fieldId, text) {
    msg(msgId, text, "error");
    const field = $(fieldId);
    if (field) { field.setAttribute("aria-invalid", "true"); field.focus(); }
  }

  function resetPasswordFields() {
    document.querySelectorAll(".pw-input").forEach((input) => { input.value = ""; input.type = "password"; });
    document.querySelectorAll(".pw-toggle").forEach((b) => {
      b.textContent = "Show";
      b.setAttribute("aria-pressed", "false");
      b.setAttribute("aria-label", "Show password");
    });
  }

  function setBusy(btn, busy, busyText) {
    if (busy) {
      btn.dataset.label = btn.textContent;
      btn.textContent = busyText;
    } else if (btn.dataset.label) {
      btn.textContent = btn.dataset.label;
    }
    btn.disabled = busy;
    btn.setAttribute("aria-busy", String(busy));
  }

  async function guarded(btn, busyText, msgId, work) {
    setBusy(btn, true, busyText);
    try { await work(); } catch (e) { msg(msgId, friendly(e)); } finally { setBusy(btn, false); }
  }

  function toast(text) {
    const el = $("toast");
    el.textContent = text;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 4500);
  }

  function setView(name, focus) {
    currentView = name;
    VIEWS.forEach((v) => { const el = $("view-" + v); if (el) el.hidden = v !== name; });
    $("authTabs").hidden = !(name === "login" || name === "signup");
    $("tabLogin").classList.toggle("active", name === "login");
    $("tabSignup").classList.toggle("active", name === "signup");
    $("tabLogin").setAttribute("aria-selected", String(name === "login"));
    $("tabSignup").setAttribute("aria-selected", String(name === "signup"));
    clearMsgs();
    resetPasswordFields();
    if (focus) {
      const first = document.querySelector("#view-" + name + " input:not([type=checkbox])");
      if (first) first.focus();
    }
  }

  /* ------------------------------------------------------------
     4. Validation and friendly errors
  ------------------------------------------------------------ */
  function passwordProblem(pw) {
    if (pw.length < 8) return "Use at least 8 characters.";
    if (pw.length > 72) return "That password is too long (maximum 72 characters).";
    if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return "Include at least one letter and one number.";
    return "";
  }

  function isNotConfirmed(err) {
    return !!err && (err.code === "email_not_confirmed" || /not confirmed/i.test(err.message || ""));
  }

  function friendly(err) {
    const code = (err && err.code) || "";
    const text = ((err && err.message) || "").toLowerCase();
    if (code === "invalid_credentials" || text.includes("invalid login")) return "Email or password is incorrect.";
    if (code === "over_email_send_rate_limit" || code === "over_request_rate_limit" ||
        (err && err.status === 429) || text.includes("rate limit")) {
      return "Too many attempts. Please wait a few minutes and try again.";
    }
    if (code === "weak_password") return "That password is too weak. Use at least 8 characters with a letter and a number.";
    if (code === "same_password") return "Choose a password that is different from your old one.";
    if (code === "user_already_exists" || text.includes("already registered")) {
      return "An account with this email may already exist. Try logging in or reset your password.";
    }
    if (code === "email_address_not_authorized") {
      return "This project can only email approved test addresses right now. The site owner needs to set up custom SMTP.";
    }
    if (code === "signup_disabled") return "New sign-ups are turned off for this project.";
    if (text.includes("failed to fetch") || text.includes("network") || (err && err.name === "AuthRetryableFetchError")) {
      return "Could not reach the server. Check your internet connection and try again.";
    }
    return "Something went wrong. Please try again.";
  }

  /* ------------------------------------------------------------
     5. Screens: auth page <-> dashboard
  ------------------------------------------------------------ */
  function showAuth(view, focus) {
    if (shownUserId && window.ScamShield) window.ScamShield.stop();
    shownUserId = null;
    $("appShell").hidden = true;
    $("authScreen").hidden = false;
    document.body.classList.add("auth-mode");
    setView(view || "login", focus);
  }

  function displayName(user) {
    const meta = user.user_metadata || {};
    return (meta.full_name || "").trim() || (user.email || "User").split("@")[0];
  }

  function setProfileName(name) {
    const initial = (name.trim().charAt(0) || "U").toUpperCase();
    ["sideName", "profName"].forEach((id) => { $(id).textContent = name; });
    ["sideAvatar", "profAvatar"].forEach((id) => { $(id).textContent = initial; });
  }

  function renderProfile(user) {
    setProfileName(displayName(user));
    $("sideEmail").textContent = user.email || "";
    $("profEmail").textContent = user.email || "";
    $("profVerified").textContent = user.email_confirmed_at ? "Verified" : "Not verified";
    $("profSince").textContent = user.created_at
      ? new Date(user.created_at).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" })
      : "";
    // Read the name from the profiles table (Row Level Security returns only your own row).
    sb.from("profiles").select("full_name").maybeSingle().then(
      (res) => { if (res && res.data && res.data.full_name) setProfileName(res.data.full_name); },
      () => { /* profile name is optional */ }
    );
  }

  async function showApp(user) {
    if (shownUserId === user.id) return;
    shownUserId = user.id;
    renderProfile(user);
    $("authScreen").hidden = true;
    $("appShell").hidden = false;
    document.body.classList.remove("auth-mode");
    window.scrollTo(0, 0);
    if (justVerified) { toast("Email verified. Welcome to ScamShield AI."); justVerified = false; }
    else if (justSignedIn) { toast("Welcome back, " + displayName(user).split(" ")[0] + "."); }
    justSignedIn = false;
    if (window.ScamShield) await window.ScamShield.start(sb, user);
  }

  function route(session) {
    if (recoveryMode) {
      if (currentView !== "reset" || shownUserId) showAuth("reset", true);
      return;
    }
    if (session && session.user) { showApp(session.user); return; }
    if (currentView === "loading" || currentView === "reset" || shownUserId) showAuth("login");
  }

  /* ------------------------------------------------------------
     6. Form handlers
  ------------------------------------------------------------ */
  function openVerify(email, justSent) {
    pendingEmail = email;
    $("verifyEmail").textContent = email;
    setView("verify");
    if (justSent) {
      msg("msgVerify", "Account created. Open the link in the email to verify your address, then log in.", "success");
      startCooldown();
    } else {
      clearInterval(cooldownTimer);
      $("resendBtn").disabled = false;
      $("resendBtn").textContent = "Resend email";
    }
  }

  function startCooldown() {
    const btn = $("resendBtn");
    let left = 60;
    clearInterval(cooldownTimer);
    const tick = () => {
      btn.textContent = left > 0 ? "Resend email (" + left + "s)" : "Resend email";
      btn.disabled = left > 0;
      if (left <= 0) clearInterval(cooldownTimer);
      left--;
    };
    tick();
    cooldownTimer = setInterval(tick, 1000);
  }

  async function onSignup(e) {
    e.preventDefault();
    clearMsgs();
    const name = $("suName").value.trim().replace(/\s+/g, " ");
    const email = $("suEmail").value.trim().toLowerCase();
    const pw = $("suPassword").value;
    const pw2 = $("suConfirm").value;

    if (name.length < 2 || name.length > 60) return fail("msgSignup", "suName", "Enter your full name (2 to 60 characters).");
    if (!EMAIL_RE.test(email)) return fail("msgSignup", "suEmail", "Enter a valid email address.");
    const problem = passwordProblem(pw);
    if (problem) return fail("msgSignup", "suPassword", problem);
    if (pw !== pw2) return fail("msgSignup", "suConfirm", "The two passwords do not match.");

    await guarded($("signupBtn"), "Creating account…", "msgSignup", async () => {
      const { data, error } = await sb.auth.signUp({
        email: email,
        password: pw,
        options: { data: { full_name: name }, emailRedirectTo: REDIRECT_URL }
      });
      if (error) { msg("msgSignup", friendly(error)); return; }
      resetPasswordFields();
      if (data.session) return; // email confirmation is switched off: onAuthStateChange opens the dashboard
      openVerify(email, true);
    });
  }

  async function onLogin(e) {
    e.preventDefault();
    clearMsgs();
    const email = $("liEmail").value.trim().toLowerCase();
    const pw = $("liPassword").value;
    if (!EMAIL_RE.test(email)) return fail("msgLogin", "liEmail", "Enter a valid email address.");
    if (!pw) return fail("msgLogin", "liPassword", "Enter your password.");

    await guarded($("loginBtn"), "Logging in…", "msgLogin", async () => {
      try { window.localStorage.setItem(REMEMBER_KEY, $("liRemember").checked ? "1" : "0"); } catch (err) { /* ignore */ }
      justSignedIn = true;
      const { error } = await sb.auth.signInWithPassword({ email: email, password: pw });
      if (error) {
        justSignedIn = false;
        if (isNotConfirmed(error)) {
          openVerify(email, false);
          msg("msgVerify", "Your email is not verified yet. Open the link we sent you, or request a new one.", "info");
          return;
        }
        msg("msgLogin", friendly(error));
        return;
      }
      resetPasswordFields();
    });
  }

  async function onForgot(e) {
    e.preventDefault();
    clearMsgs();
    const email = $("fpEmail").value.trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return fail("msgForgot", "fpEmail", "Enter a valid email address.");

    await guarded($("forgotBtn"), "Sending…", "msgForgot", async () => {
      const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: REDIRECT_URL });
      const code = (error && error.code) || "";
      if (error && (code.startsWith("over_") || error.status === 429 || /fetch|network/i.test(error.message || ""))) {
        msg("msgForgot", friendly(error));
        return;
      }
      // Same answer whether or not the account exists, so nobody can probe for registered emails.
      msg("msgForgot", "If an account exists for " + email + ", we sent a link to reset the password. Check your inbox and spam folder.", "success");
    });
  }

  async function onReset(e) {
    e.preventDefault();
    clearMsgs();
    const pw = $("rsPassword").value;
    const pw2 = $("rsConfirm").value;
    const problem = passwordProblem(pw);
    if (problem) return fail("msgReset", "rsPassword", problem);
    if (pw !== pw2) return fail("msgReset", "rsConfirm", "The two passwords do not match.");

    await guarded($("resetBtn"), "Updating…", "msgReset", async () => {
      const { error } = await sb.auth.updateUser({ password: pw });
      if (error) { msg("msgReset", friendly(error)); return; }
      resetPasswordFields();
      msg("msgReset", "Password updated. Opening your dashboard…", "success");
      recoveryMode = false;
      const { data } = await sb.auth.getSession();
      setTimeout(() => { route(data.session); toast("Password updated."); }, 1200);
    });
  }

  async function onResend() {
    if (!pendingEmail) return;
    const btn = $("resendBtn");
    btn.disabled = true;
    btn.textContent = "Sending…";
    try {
      const { error } = await sb.auth.resend({ type: "signup", email: pendingEmail, options: { emailRedirectTo: REDIRECT_URL } });
      if (error) msg("msgVerify", friendly(error));
      else msg("msgVerify", "If this address still needs verifying, we sent a new link.", "success");
    } catch (err) {
      msg("msgVerify", friendly(err));
    }
    startCooldown();
  }

  async function cancelRecovery() {
    recoveryMode = false;
    await sb.auth.signOut({ scope: "local" });
    showAuth("login");
  }

  async function logout() {
    try { await sb.auth.signOut(); } catch (e) { /* the local session is removed anyway */ }
    route(null);
    msg("msgLogin", "You have been logged out.", "info");
  }

  /* ------------------------------------------------------------
     7. Start-up: check the session before showing anything
  ------------------------------------------------------------ */
  function setupProblem() {
    if (window.location.protocol === "file:") {
      return "Open this page with VS Code Live Server or from GitHub Pages. Sign-in does not work from a file:// address.";
    }
    if (!window.supabase || !window.supabase.createClient) {
      return "The Supabase library did not load. Check your internet connection and reload the page.";
    }
    if (/YOUR-/.test(SUPABASE_URL + SUPABASE_KEY)) {
      return "Supabase is not set up yet. Add your project URL and publishable key at the top of auth.js.";
    }
    return "";
  }

  async function bootstrap() {
    let session = null;
    try {
      const res = await sb.auth.getSession();
      session = res.data.session;
      if (session) {
        // Ask the Supabase server to confirm the session is real, not just present in storage.
        const check = await sb.auth.getUser();
        if (check.error || !check.data.user) {
          if (check.error && [401, 403, 404].includes(check.error.status)) await sb.auth.signOut({ scope: "local" });
          session = null;
        }
      }
    } catch (e) {
      session = null;
    }
    route(session);
    if (linkError) { setView("login"); msg("msgLogin", linkError, "error"); }
  }

  function bindEvents() {
    $("view-login").addEventListener("submit", onLogin);
    $("view-signup").addEventListener("submit", onSignup);
    $("view-forgot").addEventListener("submit", onForgot);
    $("view-reset").addEventListener("submit", onReset);
    $("resendBtn").addEventListener("click", onResend);
    $("cancelResetBtn").addEventListener("click", cancelRecovery);

    document.querySelectorAll("[data-goto]").forEach((el) => {
      el.addEventListener("click", () => setView(el.dataset.goto, true));
    });
    document.querySelectorAll("[data-logout]").forEach((el) => el.addEventListener("click", logout));
    document.querySelectorAll(".auth-form input").forEach((input) => {
      input.addEventListener("input", () => input.removeAttribute("aria-invalid"));
    });
    document.querySelectorAll("[data-toggle-password]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const input = $(btn.dataset.togglePassword);
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        btn.textContent = show ? "Hide" : "Show";
        btn.setAttribute("aria-pressed", String(show));
        btn.setAttribute("aria-label", (show ? "Hide" : "Show") + " password");
      });
    });
  }

  function init() {
    bindEvents();
    const problem = setupProblem();
    if (problem) {
      showAuth("login");
      msg("msgLogin", problem, "error");
      document.querySelectorAll(".auth-form button[type=submit]").forEach((b) => { b.disabled = true; });
      return; // the dashboard stays hidden
    }

    sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, storage: authStorage }
    });

    // Do not call other Supabase methods inside this callback; defer with setTimeout.
    sb.auth.onAuthStateChange((event, session) => {
      if (event === "PASSWORD_RECOVERY") { recoveryMode = true; setTimeout(() => route(session), 0); }
      else if (event === "SIGNED_OUT") { setTimeout(() => route(null), 0); }
      else if (event === "SIGNED_IN" || event === "USER_UPDATED") { setTimeout(() => route(session), 0); }
    });

    bootstrap();
  }

  init();
})();