"use strict";

/* ============ ScamShield AI : script.js ============
   Rule-based, client-side detection.Rule-based engine runs in the browser; AI runs through a Netlify Function.
   The score is a heuristic indicator score, NOT a fraud probability. */

(function () {
  const $ = (id) => document.getElementById(id);

   let db = null;       // Supabase client (set after login)
   let userId = null;   // logged-in user id
  const MAX_HISTORY = 50;
  const GAUGE_LENGTH = 326.7; // 2 * PI * r (r = 52)

  let mode = "message";
  let history = [];
  let historyFilter = "all";
  let historySearch = "";
  let lastResult = null;
  let chart = null;

  
  /* Counts a number up (or down) inside an element, e.g. 0 -> 68. */
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function animateNumber(el, to, duration, fromZero) {
    cancelAnimationFrame(el._countFrame);
    const from = fromZero ? 0 : (parseInt(el.textContent, 10) || 0);
    if (reduceMotion || from === to) { el.textContent = String(to); return; }
    const start = performance.now();
    function tick(now) {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);   // fast at first, slow at the end
      el.textContent = String(Math.round(from + (to - from) * eased));
      if (t < 1) el._countFrame = requestAnimationFrame(tick);
    }
    el._countFrame = requestAnimationFrame(tick);
  }
  /* ------------------------------------------------------------
     1. Sample inputs (fictional, safe to demo)
  ------------------------------------------------------------ */
  const SAMPLES = [
    { label: "Urgent KYC alert", mode: "message",
      text: "URGENT: Your bank account will be blocked today due to incomplete KYC. Verify immediately at http://bank-kyc-update.example.com or your account will be suspended. Do not delay!" },
    { label: "Normal bill confirmation", mode: "message",
      text: "Hi! Your electricity bill payment of Rs. 850 was received. Thank you. You can view your receipt in the official app." },
    { label: "OTP request", mode: "message",
      text: "Your account is at risk. Share the OTP 000000 with our support agent now to stop an unauthorised transaction." },
    { label: "Shortened link", mode: "url", text: "https://bit.ly/example" },
    { label: "HTTP login page", mode: "url", text: "http://example.com/account/login" }
  ];

  /* ------------------------------------------------------------
     2. URL analysis
  ------------------------------------------------------------ */
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
    "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly", "s.id", "t.ly", "bl.ink", "v.gd"];

  const ODD_TLDS = ["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "support", "loan", "icu", "cyou", "buzz", "rest", "monster", "sbs", "country", "men"];

  const BRAND_TERMS = ["paytm", "phonepe", "googlepay", "gpay", "upi", "bhim", "sbi", "hdfc", "icici",
    "axis", "kotak", "pnb", "npci", "rbi", "bank", "kyc", "amazon", "flipkart", "refund", "reward",
    "cashback", "wallet"];

  const LOOKALIKE_BRANDS = ["paytm", "phonepe", "googlepay", "hdfcbank", "icicibank", "axisbank",
    "kotak", "amazon", "flipkart", "npci"];

  const OFFICIAL_DOMAINS = ["paytm.com", "phonepe.com", "google.com", "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "npci.org.in", "rbi.org.in",
    "amazon.in", "amazon.com", "flipkart.com", "bhimupi.org.in"];

  const PATH_WORDS = /(login|log-in|signin|sign-in|verify|verification|kyc|account|update|secure|password|otp|confirm|wallet|refund|claim)/i;

  function parseUrl(raw) {
    const s = String(raw).trim();
    if (!s || /\s/.test(s)) return null;
    const explicit = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
    if (explicit && !/^https?:\/\//i.test(s)) return null;
    let u;
    try { u = new URL(explicit ? s : "http://" + s); } catch (e) { return null; }
    const host = u.hostname.toLowerCase();
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
    if (!isIp && !host.includes(".")) return null;
    return { url: u, host: host, isIp: isIp, explicit: explicit };
  }

  function registeredDomain(host) {
    const parts = host.split(".");
    if (parts.length <= 2) return host;
    const second = parts[parts.length - 2];
    const last = parts[parts.length - 1];
    const take = (last.length === 2 && ["co", "com", "org", "net", "gov", "ac", "nic", "edu"].includes(second)) ? 3 : 2;
    return parts.slice(-take).join(".");
  }

  function isOfficial(host) {
    return OFFICIAL_DOMAINS.includes(registeredDomain(host)) || host.endsWith(".gov.in");
  }

  function hasBrandTerm(host) {
    const tokens = host.split(/[.\-_]/);
    return BRAND_TERMS.some((term) =>
      tokens.some((tk) => tk === term || (term.length >= 5 && tk.includes(term))));
  }

  function looksLikeLookalike(host) {
    if (host.includes("xn--")) return true;
    const raw = host.replace(/-/g, "");
    const base = raw.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o")
      .replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s");
    const norms = [base.replace(/1/g, "l"), base.replace(/1/g, "i")];
    return LOOKALIKE_BRANDS.some((b) => !raw.includes(b) && norms.some((n) => n.includes(b)));
  }

  const URL_RULES = [
    { key: "shortener", points: 28, title: "URL shortener",
      why: "A shortened link hides the real destination, so you cannot see where it leads before you click.",
      test: (p) => SHORTENERS.includes(p.host) },
    { key: "ip", points: 30, title: "Raw IP address used as the website",
      why: "Genuine banks and payment apps use proper domain names, not numeric IP addresses.",
      test: (p) => p.isIp },
    { key: "userinfo", points: 30, title: "Hidden user information in the link",
      why: "A link like name@site can make a fake address look like a trusted one.",
      test: (p) => !!(p.url.username || p.url.password) },
    { key: "tld", points: 20, title: "Unusual domain ending",
      why: "Some domain endings are cheap and often used for throwaway scam sites. This alone does not prove fraud.",
      test: (p) => !p.isIp && ODD_TLDS.includes(p.host.split(".").pop()) },
    { key: "brand", points: 18, title: "Bank or payment term in an unverified domain",
      why: "Scam sites often put words like bank, KYC or UPI in the address to look official. This domain is not on our small list of known official domains.",
      test: (p) => !p.isIp && hasBrandTerm(p.host) && !isOfficial(p.host) },
    { key: "lookalike", points: 22, title: "Possible lookalike or encoded domain",
      why: "The domain may imitate a known brand with swapped letters or special characters.",
      test: (p) => !p.isIp && !isOfficial(p.host) && looksLikeLookalike(p.host) },
    { key: "http", points: 10, title: "Uses HTTP instead of HTTPS",
      why: "HTTP links are not encrypted. Genuine payment pages use HTTPS.",
      test: (p) => p.explicit && p.url.protocol === "http:" },
    { key: "path", points: 16, title: "Login, verify or account action in the link",
      why: "Scam links often ask you to log in, verify or update an account. Real sites use this too, so check who sent it.",
      test: (p) => PATH_WORDS.test(p.url.pathname + p.url.search) }
  ];

  function analyseUrl(parsed) {
    const flags = {};
    const list = [];
    URL_RULES.forEach((r) => {
      if (r.test(parsed)) {
        flags[r.key] = true;
        list.push({ title: r.title, why: r.why, points: r.points });
      }
    });
    return { flags: flags, list: list };
  }

  /* ------------------------------------------------------------
     3. Message analysis
  ------------------------------------------------------------ */
  const URL_IN_TEXT = /(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|ow\.ly|shorturl\.at)\/[^\s<>"']+/gi;

  function extractUrls(text) {
    const found = (text.match(URL_IN_TEXT) || []).map((u) => u.replace(/[.,;:!?)\]]+$/, ""));
    const unique = [...new Set(found)];
    return unique.map(parseUrl).filter(Boolean).map((p) => analyseUrl(p).flags);
  }

  function hasCredentialRequest(text) {
    // Ignore warnings such as "Do not share your OTP with anyone".
    const cleaned = text.replace(/\b(?:do not|don't|dont|never|nahi|mat)\s+(?:share|send|tell|give|provide|disclose|forward)\b[^.!?\n]*/gi, " ");
    const secret = "(?:otp|one[- ]time password|upi[- ]?pin|m-?pin|pin|cvv|cvc|password|passcode|card number)";
    const verb = "(?:share|send|tell|give|provide|enter|submit|reply|forward|read out|disclose|batao|bata|bhejo)";
    const a = new RegExp(`\\b${verb}\\b[^.!?\\n]{0,40}?\\b${secret}\\b`, "i");
    const b = new RegExp(`\\b${secret}\\b[^.!?\\n]{0,40}\\b(?:share|send|reply|forward)\\b`, "i");
    return a.test(cleaned) || b.test(cleaned);
  }

  const MESSAGE_RULES = [
    { points: 32, title: "Asks for OTP, UPI PIN, CVV or password",
      why: "Banks and payment apps never ask you to share these. Anyone who asks is likely trying to take your money.",
      test: (t) => hasCredentialRequest(t) },
    { points: 28, title: "Mentions a remote-access or screen-sharing tool",
      why: "Scammers ask you to install apps like AnyDesk or TeamViewer so they can see your screen and approve payments.",
      test: (t) => /anydesk|teamviewer|quick ?support|airdroid|rustdesk|screen[- ]?shar|remote (?:access|support|control)|\.apk\b|install (?:this|the) app/i.test(t) },
    { points: 22, title: "Threatens to block or suspend your account",
      why: "Threats of losing access are used to scare you into acting before you think.",
      test: (t) => /\b(?:account|card|upi|wallet|sim|service|number)\b[^.!?\n]{0,40}\b(?:blocked|suspended|deactivated|frozen|closed|terminated|disabled|restricted)\b|will be (?:blocked|suspended|deactivated|closed)|khata band/i.test(t) },
    { points: 20, title: "Urgent or pressuring language",
      why: "Scammers rush you so you do not stop to verify. Real organisations give you time and official channels.",
      test: (t) => /\burgent(?:ly)?\b|immediately|\bimmediate\b|right now|\basap\b|act now|do not delay|don't delay|last chance|expires? (?:today|soon|in)|within \d+ ?(?:hours?|hrs?|minutes?|mins?)|turant|jaldi|\babhi\b|account (?:is )?at risk|(?:share|send|reply|call|click|pay|verify|update)[^.!?\n]{0,60}\bnow\b/i.test(t) },
    { points: 20, title: "Unexpected refund, QR code or payment request",
      why: "Fake refunds, cashback and collect requests trick people into approving payments or scanning QR codes that take money out.",
      test: (t) => /refund|cashback|collect request|\bqr\b|accept (?:the )?(?:request|payment)/i.test(t) },
    { points: 18, title: "Unexpected KYC or identity update",
      why: "Fake KYC messages are one of the most common scams in India. Banks do not complete KYC through random links.",
      test: (t) => /\bkyc\b|re-?kyc|(?:pan|aadhaar|aadhar)\b[^.!?\n]{0,20}(?:update|verif|link)|verify (?:your )?(?:identity|account|details)|update (?:your )?(?:details|pan|aadhaar)/i.test(t) },
    { points: 18, title: "Prize, lottery or reward language",
      why: "You cannot win a prize you never entered for. Reward messages are used to lure you into sharing details or paying a fee.",
      test: (t) => /lottery|jackpot|\bprize\b|you(?:'ve| have) won|congratulations[^.!?\n]{0,40}(?:won|selected)|lucky draw|gift card|free (?:gift|recharge)/i.test(t) },
    { points: 15, title: "Pretends to be support or an authority",
      why: "Scammers pose as bank staff, support agents or officials to gain your trust.",
      test: (t) => /customer care|\bour (?:support )?(?:agent|executive|representative|team)\b|support (?:agent|executive)|bank (?:officer|manager|executive|official)|\b(?:rbi|npci|cbi|police|cyber cell|income tax)\b[^.!?\n]{0,15}(?:officer|department|notice)/i.test(t) },
    { points: 22, title: "Promises instant or easy money",
      why: "Real banks and apps never hand out large amounts instantly for a small task. Easy-money promises are used to lure you into paying or sharing details.",
      test: (t) => /easy money|instant (?:cash|money|payout)|(?:get|earn|win|receive)\s+(?:rs\.?|₹|inr)?\s*\d[\d,]{3,}\s*(?:rupees|rs|inr)?[^.!?\n]{0,40}\b(?:instantly|daily|per day|fast|in minutes)\b|paise kamao|ghar baithe (?:kamao|earn)|turant paise/i.test(t) },
    { points: 26, title: "Mentions betting, gambling or prediction games",
      why: "Betting and prediction apps are a common bait: they show small early wins, then push you to deposit more money that you cannot withdraw.",
      test: (t) => /\bbetting\b|\bcasino\b|\bsatta\b|\bmatka\b|teen ?patti|\baviator\b|colou?r prediction|online rummy|\bbet(?:ting)? (?:app|id|site)\b/i.test(t) },
    { points: 28, title: "Guaranteed returns or investment promise",
      why: "No genuine investment can guarantee profit. Fake trading groups show fake profits to make you invest more.",
      test: (t) => /guaranteed (?:returns?|profit)|double your (?:money|investment)|(?:paisa|paise|money) double|risk[- ]?free (?:investment|trading|returns?)|daily (?:profit|returns?|income)|fixed returns?|100% (?:profit|returns?)|\bvip (?:group|channel)\b|stock tips? group/i.test(t) },
    { points: 30, title: "Fake job or task-based earning offer",
      why: "Real employers do not charge a fee to give you a job. Task scams pay small amounts first, then ask you to deposit money.",
      test: (t) => /(?:like|subscribe|rate|review)s?\b[^.!?\n]{0,30}\b(?:earn|paid)\b|part[- ]?time (?:job|work|task)|work from home[^.!?\n]{0,40}(?:earn|income|salary|₹|rs)|registration fee|joining fee|(?:job|naukri)[^.!?\n]{0,30}(?:fee|deposit)|data entry job|task[- ]based (?:job|earning)/i.test(t) },
    { points: 40, title: "Digital arrest or fake courier / agency threat",
      why: "Police, CBI or customs never arrest anyone over a video call or ask you to keep the call on. This is a pressure scam.",
      test: (t) => /digital arrest|(?:parcel|courier|package)[^.!?\n]{0,60}(?:drugs?|illegal|narcotics?|contraband|seized)|\b(?:cbi|ncb|customs|narcotics|cyber ?crime|trai)\b\s+(?:officer|department|team|case|notice)|arrest warrant|money laundering case|stay on (?:the )?(?:video )?call|(?:do not|don't) (?:disconnect|tell anyone)/i.test(t) },
    { points: 26, title: "Instant or pre-approved loan offer",
      why: "Fake loan apps ask for a processing fee or access to your contacts and photos before any money arrives.",
      test: (t) => /instant loan|pre[- ]?approved (?:loan|credit|limit)|loan (?:approved|without documents|in \d+ minutes)|no (?:documents?|cibil|credit check)[^.!?\n]{0,20}loan|loan[^.!?\n]{0,30}no (?:documents?|cibil)|(?:loan|credit limit)[^.!?\n]{0,40}(?:processing|advance) fee/i.test(t) },








    { points: 24, title: "Link with a possibly deceptive domain",
      why: "The link contains bank or payment words, a lookalike name or other tricks that scam sites use to look genuine.",
      test: (t, c) => c.urls.some((f) => f.brand || f.lookalike || f.ip || f.userinfo) },
    { points: 20, title: "Shortened link",
      why: "A shortened link hides where it really goes.",
      test: (t, c) => c.urls.some((f) => f.shortener) },
    { points: 8, title: "Contains an external link",
      why: "Links in unexpected messages are a common way to reach fake pages. Do not tap it. Use the official app instead.",
      test: (t, c) => c.urls.length > 0 }
  ];

  /* ------------------------------------------------------------
     4. Scoring and result text
  ------------------------------------------------------------ */
  const LABELS = { low: "Low risk", moderate: "Moderate risk", high: "High risk", critical: "Critical risk" };

  function levelFor(score) {
    if (score <= 25) return "low";
    if (score <= 50) return "moderate";
    if (score <= 75) return "high";
    return "critical";
  }

  function recommendationFor(level) {
    if (level === "high" || level === "critical") {
      return "Do not click the link, reply, scan a QR code, or share credentials. Contact the organisation using its official app or a number you already trust.";
    }
    if (level === "moderate") {
      return "Pause and verify the sender and domain independently. Open the official app or type the known website address yourself.";
    }
    return "No strong rule match was found, but the sender and content are not verified. Never share an OTP, UPI PIN, CVV, or password.";
  }

  function summaryFor(level, count, kind) {
    const noun = kind === "url" ? "link" : "message";
    let s;
    if (level === "low") s = `Few known warning signs matched (${count}). This does not prove the ${noun} is safe.`;
    else if (level === "moderate") s = `Some warning signs matched. They deserve independent verification before you act.`;
    else if (level === "high") s = `Multiple warning signs matched. Do not act on this ${noun} until you verify it independently.`;
    else s = `Several serious warning signs matched. Do not interact with this ${noun}.`;
    if (kind === "url") s += " A domain pattern is a warning indicator, not proof of fraud.";
    return s;
  }

  function buildResult(kind, input, indicators, linkCount) {
    const score = Math.min(100, indicators.reduce((sum, i) => sum + i.points, 0));
    const level = levelFor(score);
    indicators.sort((a, b) => b.points - a.points);
    return {
      mode: kind, input: input, score: score, level: level, indicators: indicators,
      links: linkCount, summary: summaryFor(level, indicators.length, kind),
      recommendation: recommendationFor(level), time: new Date().toISOString()
    };
  }
  /* =========================================
   MULTILINGUAL + SCAM CATEGORY DETECTION
========================================= */

const SCAM_CATEGORY_RULES = [
  {
    name: "OTP Scam",
    keywords: [
      "share your otp", "send otp", "tell me your otp",
      "otp batao", "otp bhejo", "otp share karo",
      "otp forward karo", "otp dedo", "otp de do",
      "ओटीपी बताओ", "ओटीपी भेजो", "ओटीपी साझा करें",
      "ओटीपी दे दो"
    ]
  },
  {
    name: "UPI / Payment Fraud",
    keywords: [
      "upi pin", "collect request", "receive money",
      "enter pin to receive", "payment approve",
      "upi pin daalo", "upi pin dalo", "paise receive karne",
      "paise lene ke liye pin", "payment approve karo",
      "पैसे प्राप्त करने", "यूपीआई पिन डालें",
      "पैसे लेने के लिए पिन"
    ]
  },
  {
    name: "KYC Scam",
    keywords: [
      "update your kyc", "kyc expired", "complete kyc",
      "kyc update karo", "kyc karwao", "kyc kar lo",
      "account band ho jayega", "account block ho jayega",
      "केवाईसी अपडेट करें", "केवाईसी पूरी करें",
      "खाता बंद हो जाएगा"
    ]
  },
  {
    name: "Phishing Scam",
    keywords: [
      "click this link", "verify your account",
      "login immediately", "update your password",
      "is link par click karo", "link kholo",
      "link par click karein", "account verify karo",
      "इस लिंक पर क्लिक करें", "खाते को सत्यापित करें",
      "लिंक खोलें"
    ]
  },
  {
    name: "Job Scam",
    keywords: [
      "registration fee", "job offer fee",
      "pay to get job", "work from home earning",
      "registration fees jama karo", "job ke liye paise",
      "naukri ke liye fees", "job pakki",
      "रजिस्ट्रेशन फीस जमा करें", "नौकरी के लिए पैसे",
      "नौकरी पक्की"
    ]
  },
  {
    name: "Lottery / Prize Scam",
    keywords: [
      "you have won", "lottery winner", "claim your prize",
      "lucky draw", "inaam jeeta", "lottery lagi hai",
      "aap jeet gaye", "inaam claim karo",
      "आपने इनाम जीता", "लॉटरी लगी है",
      "आप जीत गए हैं"
    ]
  },
  {
    name: "Investment Scam",
    keywords: [
      "guaranteed returns", "double your money",
      "risk free investment", "daily profit",
      "paise double", "paisa double", "guaranteed profit",
      "fixed return", "पैसे डबल", "गारंटीड रिटर्न",
      "रोजाना मुनाफा"
    ]
  },
  {
    name: "Impersonation Scam",
    keywords: [
      "i am calling from bank", "bank officer",
      "police officer", "customer care executive",
      "main bank se bol raha", "bank se bol raha hoon",
      "police se bol raha", "main police bol raha",
      "मैं बैंक से बोल रहा हूं", "पुलिस अधिकारी",
      "बैंक अधिकारी"
    ]
  },
  {
    name: "Delivery Scam",
    keywords: [
      "parcel delivery fee", "delivery charge pending",
      "pay parcel fee", "parcel release",
      "parcel ke paise do", "delivery ke liye payment",
      "parcel rok diya", "पार्सल शुल्क",
      "डिलीवरी के लिए भुगतान", "पार्सल रोक दिया"
    ]
  },
    {
    name: "Betting / Easy Money Scam",
    keywords: ["start betting", "betting app", "instant money", "easy money", "paise kamao", "ghar baithe kamao"]
  },
  {
    name: "Digital Arrest / Fake Agency Scam",
    keywords: ["digital arrest", "arrest warrant", "stay on the call", "cbi officer", "customs officer", "money laundering case"]
  },
  {
    name: "Loan App Scam",
    keywords: ["instant loan", "pre-approved loan", "processing fee", "no documents"]
  }
];

/* Detect English, Hindi and Hinglish */
function detectMessageLanguage(text) {
  const value = text.toLowerCase();

  const hasHindiScript = /[\u0900-\u097F]/.test(value);

  const hinglishWords = [
    "hai", "hain", "aap", "apka", "apna", "karo",
    "kro", "karna", "krna", "bhejo", "batao",
    "btao", "paise", "paisa", "khata", "band",
    "abhi", "turant", "nahi", "mat", "mein",
    "se", "ho jayega", "kar do", "dedo", "de do"
  ];

  const hasRomanHindi = hinglishWords.some(word => {
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("(^|\\W)" + escaped + "($|\\W)", "i").test(value);
  });

  const hasEnglish = /\b(the|your|you|account|bank|payment|share|click|verify|update|urgent|please|immediately)\b/i.test(value);

  if (hasHindiScript && hasEnglish) return "Mixed Hindi-English";
  if (hasHindiScript) return "Hindi";
  if (hasRomanHindi && hasEnglish) return "Mixed Hindi-English";
  if (hasRomanHindi) return "Hinglish";

  return "English";
}

/* Identify the most relevant scam category */
function detectScamCategory(text) {
  const value = text.toLowerCase();

  const matched = SCAM_CATEGORY_RULES
    .filter(category =>
      category.keywords.some(keyword => value.includes(keyword))
    )
    .map(category => category.name);

  return matched.length ? matched : ["Unclassified / No category match"];
}
  function scanMessage(text) {
  const ctx = { urls: extractUrls(text) };

  const hits = MESSAGE_RULES.filter((r) => r.test(text, ctx))
    .map((r) => ({
      title: r.title,
      why: r.why,
      points: r.points
    }));

  const result = buildResult(
    "message",
    text,
    hits,
    ctx.urls.length
  );

  // New multilingual features
  result.language = detectMessageLanguage(text);
  result.categories = detectScamCategory(text);

  return result;
}

  function scanUrl(parsed, original) {
    return buildResult("url", original, analyseUrl(parsed).list, 1);
  }

  /* ------------------------------------------------------------
     5. Rendering the result
  ------------------------------------------------------------ */
    /* ----- Mark the suspicious parts inside the user's message ----- */
  const LINK_RE = /(?:https?:\/\/|www\.)[^\s<>"']*[^\s<>"'.,;:!?)\]]|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|ow\.ly|shorturl\.at)\/[^\s<>"']*[^\s<>"'.,;:!?)\]]/;
  const SECRET = "(?:otp|one[- ]time password|upi[- ]?pin|m-?pin|pin|cvv|cvc|password|passcode|card number)";
  const ASK_VERB = "(?:share|send|tell|give|provide|enter|submit|reply|forward|read out|disclose|batao|bata|bhejo)";

  // "rules" = rule titles from MESSAGE_RULES. A pattern is used only when one of its rules matched.
  const HIGHLIGHT_PATTERNS = [
    { rules: ["Asks for OTP, UPI PIN, CVV or password"], cls: "hl-danger", tip: "Asks for a secret code",
      re: new RegExp(`\\b${ASK_VERB}\\b[^.!?\\n]{0,40}?\\b${SECRET}\\b|\\b${SECRET}\\b[^.!?\\n]{0,40}\\b(?:share|send|reply|forward)\\b`, "i") },
    { rules: ["Mentions a remote-access or screen-sharing tool"], cls: "hl-danger", tip: "Remote-access or screen-sharing tool",
      re: /anydesk|teamviewer|quick ?support|airdroid|rustdesk|screen[- ]?shar\w*|remote (?:access|support|control)|\S+\.apk\b|install (?:this|the) app/i },
    { rules: ["Digital arrest or fake courier / agency threat"], cls: "hl-danger", tip: "Fake agency or arrest threat",
      re: /digital arrest|arrest warrant|money laundering case|stay on (?:the )?(?:video )?call|(?:do not|don't) (?:disconnect|tell anyone)|\b(?:cbi|ncb|customs|narcotics|cyber ?crime|trai)\b\s+(?:officer|department|team|case|notice)/i },
    { rules: ["Threatens to block or suspend your account"], cls: "hl-warn", tip: "Threat to block your account",
      re: /\b(?:account|card|upi|wallet|sim|service|number)\b[^.!?\n]{0,40}\b(?:blocked|suspended|deactivated|frozen|closed|terminated|disabled|restricted)\b|will be (?:blocked|suspended|deactivated|closed)|khata band/i },
    { rules: ["Urgent or pressuring language"], cls: "hl-warn", tip: "Pressure to act fast",
      re: /\burgent(?:ly)?\b|immediately|\bimmediate\b|\binstantly\b|right now|\basap\b|act now|do not delay|don't delay|last chance|expires? (?:today|soon|in)|within \d+ ?(?:hours?|hrs?|minutes?|mins?)|turant|jaldi|\babhi\b|account (?:is )?at risk/i },
    { rules: ["Unexpected refund, QR code or payment request"], cls: "hl-warn", tip: "Unexpected refund or payment request",
      re: /refund|cashback|collect request|\bqr\b|accept (?:the )?(?:request|payment)/i },
    { rules: ["Unexpected KYC or identity update"], cls: "hl-warn", tip: "Unexpected KYC or identity update",
      re: /\bkyc\b|re-?kyc|verify (?:your )?(?:identity|account|details)|update (?:your )?(?:details|pan|aadhaar)/i },
    { rules: ["Prize, lottery or reward language"], cls: "hl-warn", tip: "Prize or reward bait",
      re: /lottery|jackpot|\bprize\b|you(?:'ve| have) won|lucky draw|gift card|free (?:gift|recharge)/i },
    { rules: ["Pretends to be support or an authority"], cls: "hl-warn", tip: "Pretends to be support or an authority",
      re: /customer care|support (?:agent|executive)|bank (?:officer|manager|executive|official)|\b(?:rbi|npci|cbi|police|cyber cell|income tax)\b/i },
    { rules: ["Promises instant or easy money"], cls: "hl-warn", tip: "Easy-money promise",
      re: /easy money|instant (?:cash|money|payout)|(?:get|earn|win|receive)\s+(?:rs\.?|₹|inr)?\s*\d[\d,]{3,}(?:\s*(?:rupees|rs|inr)\b)?|paise kamao|ghar baithe (?:kamao|earn)|turant paise/i },
    { rules: ["Mentions betting, gambling or prediction games"], cls: "hl-warn", tip: "Betting or gambling bait",
      re: /\bbetting\b|\bcasino\b|\bsatta\b|\bmatka\b|teen ?patti|\baviator\b|colou?r prediction|online rummy/i },
    { rules: ["Guaranteed returns or investment promise"], cls: "hl-warn", tip: "Guaranteed-profit promise",
      re: /guaranteed (?:returns?|profit)|double your (?:money|investment)|(?:paisa|paise|money) double|risk[- ]?free (?:investment|trading|returns?)|daily (?:profit|returns?|income)|fixed returns?|100% (?:profit|returns?)|\bvip (?:group|channel)\b/i },
    { rules: ["Fake job or task-based earning offer"], cls: "hl-warn", tip: "Fake job or task offer",
      re: /part[- ]?time (?:job|work|task)|registration fee|joining fee|data entry job|task[- ]based (?:job|earning)/i },
    { rules: ["Instant or pre-approved loan offer"], cls: "hl-warn", tip: "Instant loan bait",
      re: /instant loan|pre[- ]?approved (?:loan|credit|limit)|processing fee|advance fee/i },
    { rules: ["Contains an external link", "Shortened link", "Link with a possibly deceptive domain"], cls: "hl-link", tip: "Link: do not tap it",
      re: LINK_RE }
  ];

  function renderFlagged(r) {
    const box = $("flaggedBox");
    const out = $("flaggedText");
    out.textContent = "";
    if (r.mode !== "message" || !r.input) { box.hidden = true; return; }

    const hit = new Set(r.indicators.map((i) => i.title));
    const ranges = [];
    HIGHLIGHT_PATTERNS.forEach((p) => {
      if (!p.rules.some((t) => hit.has(t))) return;
      const re = new RegExp(p.re.source, "gi");
      let m;
      while ((m = re.exec(r.input)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        ranges.push({ start: m.index, end: m.index + m[0].length, cls: p.cls, tip: p.tip });
      }
    });
    if (ranges.length === 0) { box.hidden = true; return; }

    ranges.sort((a, b) => a.start - b.start || b.end - a.end);
    let pos = 0;
    ranges.forEach((rg) => {
      if (rg.start < pos) return;   // overlaps a part that is already marked
      if (rg.start > pos) out.appendChild(document.createTextNode(r.input.slice(pos, rg.start)));
      const mark = document.createElement("mark");
      mark.className = "hl " + rg.cls;
      mark.title = rg.tip;
      mark.textContent = r.input.slice(rg.start, rg.end);   // textContent keeps the user's text safe
      out.appendChild(mark);
      pos = rg.end;
    });
    if (pos < r.input.length) out.appendChild(document.createTextNode(r.input.slice(pos)));
    box.hidden = false;
  }

   /* ----- AI panel: combined faisla + AI ki report ----- */
  function renderAIPanel(r) {
    let panel = $("aiPanel");
    if (!panel) {
      panel = document.createElement("section");
      panel.id = "aiPanel";
      panel.className = "ai-panel";
      $("resultBody").appendChild(panel);
    }
    panel.textContent = "";

    // textContent use karte hain, taaki AI ka text kabhi HTML ban ke na chale
    const add = (tag, text, cls) => {
      const el = document.createElement(tag);
      if (cls) el.className = cls;
      el.textContent = text;
      panel.appendChild(el);
      return el;
    };
    const addList = (title, items, makeItem) => {
      if (!items || items.length === 0) return;
      add("h4", title);
      const ul = document.createElement("ul");
      ul.className = "ai-list";
      items.forEach((item) => ul.appendChild(makeItem(item)));
      panel.appendChild(ul);
    };
    const plainItem = (text) => {
      const li = document.createElement("li");
      li.textContent = text;
      return li;
    };
    const nice = (s) => String(s || "").replace(/_/g, " ").toLowerCase();

    add("h3", "AI analysis (second opinion)", "ai-title");

    if (r.aiState === "loading") {
      add("p", "AI is reading this " + (r.mode === "url" ? "link" : "message") + "...", "ai-muted");
      return;
    }
    if (r.aiState !== "done" || !r.ai) {
      add("p", "AI analysis was unavailable. The result above uses the rule-based engine only.", "ai-muted");
      return;
    }

    const ai = r.ai;

    if (r.fusion) {
      const badge = add("div", "Combined: " + r.fusion.label, "ai-final");
      badge.dataset.final = r.fusion.final;
      add("p", r.fusion.reason, "ai-muted");
    }

    add("p", "AI verdict: " + nice(ai.verdict) + " | Risk: " + nice(ai.risk_level) +
      " | Confidence: " + nice(ai.confidence), "ai-muted");
    if (ai.category && ai.category !== "NONE") {
      add("p", "Possible scam type: " + nice(ai.category), "ai-muted");
    }
    add("p", ai.explanation);

    addList("What the AI noticed", ai.indicators, (i) => {
      const li = document.createElement("li");
      const strong = document.createElement("strong");
      strong.textContent = nice(i.type);
      const span = document.createElement("span");
      span.textContent = (i.evidence ? '"' + i.evidence + '" - ' : "") + i.reason;
      li.append(strong, span);
      return li;
    });
    addList("What to do", ai.recommended_actions, plainItem);
    addList("What the AI could not check", ai.limitations, plainItem);
  }

  function renderResult(r) {
    lastResult = r;
    $("resultPanel").dataset.level = r.level;
    $("resultEmpty").hidden = true;
    $("resultBody").hidden = false;

    animateNumber($("scoreNumber"), r.score, 800, true);
    const fill = $("gaugeFill");
    fill.style.strokeDashoffset = String(GAUGE_LENGTH);   // restart the ring from empty
    void fill.getBoundingClientRect();
    fill.style.strokeDashoffset = String(GAUGE_LENGTH * (1 - r.score / 100));
    $("riskLabel").textContent = LABELS[r.level];
    $("resultSummary").textContent = r.summary;
    // Show detected language
    $("detectedLanguage").textContent =
     r.language || (r.mode === "url" ? "URL analysis" : "Not detected");

// Show detected scam category
    $("detectedCategory").textContent =
    (r.categories || ["URL-related risk analysis"]).join(", ");
    $("recommendText").textContent = r.recommendation;
    $("copyStatus").textContent = "";

    const list = $("indicatorList");
    list.textContent = "";
    if (r.indicators.length === 0) {
      list.appendChild(makeIndicator("No known warning signs matched",
        "The rules found nothing unusual, but the sender is still unverified."));
    } else {
      r.indicators.forEach((i) => list.appendChild(makeIndicator(`${i.title} (+${i.points})`, i.why)));
    }
     renderFlagged(r);
     renderAIPanel(r);
    $("resultPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function makeIndicator(title, why) {
    const li = document.createElement("li");
    const strong = document.createElement("strong");
    const span = document.createElement("span");
    strong.textContent = title;
    span.textContent = why;
    li.append(strong, span);
    return li;
  }

  function resetResult() {
    endScanning();
    lastResult = null;
    $("resultBody").hidden = true;
    $("resultEmpty").hidden = false;
    $("gaugeFill").style.strokeDashoffset = String(GAUGE_LENGTH);
    delete $("resultPanel").dataset.level;
  }

  /* ------------------------------------------------------------
     6. History (LocalStorage)
  ------------------------------------------------------------ */
    function setCloudStatus(text) {
    const el = $("syncStatus");
    if (el) el.textContent = text;
  }

  async function loadHistory() {
    history = [];
    if (!db || !userId) return;
    setCloudStatus("Loading your scans…");
    const { data, error } = await db.from("scans")
      .select("created_at, mode, input, score, level, indicators, links")
      .order("created_at", { ascending: false })
      .limit(MAX_HISTORY);
    if (error) { setCloudStatus("Could not load your saved scans. Check your connection."); return; }
    history = data.map((row) => ({
      t: row.created_at,
      mode: row.mode,
      input: row.input,
      score: row.score,
      level: row.level,
      indicators: row.indicators || [],
      links: row.links || 0
    }));
    setCloudStatus("");
  }

  function addToHistory(r) {
    const entry = {
      t: r.time, mode: r.mode, input: r.input.slice(0, 500), score: r.score, level: r.level,
      indicators: r.indicators.map((i) => i.title), links: r.links
    };
     history.unshift(entry);
    history = history.slice(0, MAX_HISTORY);
    if (!db || !userId) return;
    // user_id is filled in by the database from the login session, so it cannot be faked.
    db.from("scans")
      .insert({ mode: entry.mode, input: entry.input, score: entry.score, level: entry.level,
                indicators: entry.indicators, links: entry.links })
      .then(({ error }) => { if (error) setCloudStatus("This scan could not be saved to your account."); });
  }
  
  function fmtTime(iso) {
    return new Date(iso).toLocaleString("en-IN", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  }

  
function renderHistory() {
    const body = $("historyBody");
    body.textContent = "";

    history.forEach((h) => {
        const tr = document.createElement("tr");

        // Scan input
        const tdInput = document.createElement("td");
        tdInput.textContent = h.input.length > 70
            ? h.input.slice(0, 70) + "…"
            : h.input;
        tdInput.title = h.input;

        // Scan type
        const tdType = document.createElement("td");
        tdType.textContent = h.mode === "url" ? "URL" : "Message";

        // Risk level
        const tdRisk = document.createElement("td");
        tdRisk.textContent = h.level || "Unknown";

        // Risk score
        const tdScore = document.createElement("td");
        tdScore.textContent = (h.score ?? 0) + "/100";

        // Scan time
        const tdTime = document.createElement("td");
        tdTime.textContent = fmtTime(h.t);

        tr.append(tdInput, tdType, tdRisk, tdScore, tdTime);
        body.appendChild(tr);
    });

    $("historyEmpty").hidden = history.length > 0;
}


  


  function renderStats() {
    animateNumber($("statTotal"), history.length, 700);
    animateNumber($("statHigh"), history.filter((h) => h.level === "high" || h.level === "critical").length, 700);
    animateNumber($("statLinks"), history.reduce((sum, h) => sum + (h.links || 0), 0), 700);
  }

  /* ------------------------------------------------------------
     7. Chart (optional, needs Chart.js from the CDN)
  ------------------------------------------------------------ */
  function dayKey(d) {
    const p = (n) => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
  }

  function last7Days() {
    const labels = [];
    const counts = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = dayKey(d);
      labels.push(d.toLocaleDateString("en-IN", { weekday: "short", day: "numeric" }));
      counts.push(history.filter((h) => dayKey(new Date(h.t)) === key).length);
    }
    return { labels: labels, counts: counts };
  }

  function chartColors() {
    const css = getComputedStyle(document.documentElement);
    return {
      text: css.getPropertyValue("--muted").trim(),
      grid: css.getPropertyValue("--border").trim(),
      bar: css.getPropertyValue("--cyan").trim()
    };
  }

    function renderChart() {
    const canvas = $("activityChart");
    if (typeof Chart === "undefined") {
      canvas.hidden = true;
      $("chartFallback").hidden = false;
      return;
    }
    const data = last7Days();
    const c = chartColors();
    if (!chart) {
      chart = new Chart(canvas, {
        type: "bar",
        data: { labels: data.labels,
          datasets: [{ label: "Scans", data: data.counts, backgroundColor: c.bar, borderRadius: 6 }] },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: c.text }, grid: { display: false } },
            y: { beginAtZero: true, ticks: { color: c.text, precision: 0 }, grid: { color: c.grid } }
          }
        }
      });
    } else {
      chart.data.labels = data.labels;
      chart.data.datasets[0].data = data.counts;
      chart.data.datasets[0].backgroundColor = c.bar;
      chart.options.scales.x.ticks.color = c.text;
      chart.options.scales.y.ticks.color = c.text;
      chart.options.scales.y.grid.color = c.grid;
      chart.update();
    }
  }

  // redraw the chart when the theme changes
  window.addEventListener("themechange", () => { if (chart) renderChart(); });
  
     /* ----- Extra charts: risk levels (doughnut) and top scam categories (bar) ----- */
  let levelChart = null;
  let categoryChart = null;

  function cssColor(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function levelCounts() {
    const c = { low: 0, moderate: 0, high: 0, critical: 0 };
    history.forEach((h) => { if (c[h.level] !== undefined) c[h.level]++; });
    return c;
  }

  // Categories are worked out again from the saved message text, so no database change is needed.
  function categoryCounts() {
    const counts = {};
    history.forEach((h) => {
      if (h.mode !== "message" || !h.input) return;
      detectScamCategory(h.input).forEach((name) => {
        if (name.indexOf("Unclassified") === 0) return;
        counts[name] = (counts[name] || 0) + 1;
      });
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }

  // Writes the total number of scans in the middle of the doughnut.
  const centerTextPlugin = {
    id: "centerText",
    afterDraw(chart) {
      const o = chart.options.plugins.centerText;
      if (!o) return;
      const a = chart.chartArea;
      const x = (a.left + a.right) / 2;
      const y = (a.top + a.bottom) / 2;
      const family = getComputedStyle(document.body).fontFamily;
      const ctx = chart.ctx;
      ctx.save();
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = o.color;
      ctx.font = "700 30px " + family;
      ctx.fillText(String(o.total), x, y - 8);
      ctx.fillStyle = o.sub;
      ctx.font = "13px " + family;
      ctx.fillText(o.total === 1 ? "scan" : "scans", x, y + 18);
      ctx.restore();
    }
  };

  // Writes the number at the end of each category bar.
  const barValuePlugin = {
    id: "barValues",
    afterDatasetsDraw(chart) {
      const o = chart.options.plugins.barValues;
      if (!o) return;
      const family = getComputedStyle(document.body).fontFamily;
      const ctx = chart.ctx;
      ctx.save();
      ctx.fillStyle = o.color;
      ctx.font = "700 13px " + family;
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      chart.getDatasetMeta(0).data.forEach((bar, i) => {
        ctx.fillText(String(chart.data.datasets[0].data[i]), bar.x + 8, bar.y);
      });
      ctx.restore();
    }
  };

  // Blue to cyan gradient for the bars (re-read on every draw, so it follows the theme).
  function barGradient(context) {
    const area = context.chart.chartArea;
    if (!area) return cssColor("--cyan");
    const g = context.chart.ctx.createLinearGradient(area.left, 0, area.right, 0);
    g.addColorStop(0, cssColor("--blue"));
    g.addColorStop(1, cssColor("--cyan"));
    return g;
  }

  function renderBreakdownCharts() {
    const hasChart = typeof Chart !== "undefined";
    const muted = cssColor("--muted");
    const text = cssColor("--text");

    /* Risk levels */
    const lc = levelCounts();
    const levelData = [lc.low, lc.moderate, lc.high, lc.critical];
    const levelTotal = levelData.reduce((a, b) => a + b, 0);
    const levelColors = [cssColor("--green"), cssColor("--amber"), "#f97316", cssColor("--red")];
    $("levelWrap").hidden = !hasChart || levelTotal === 0;
    $("levelEmpty").hidden = hasChart && levelTotal > 0;
    $("levelEmpty").textContent = hasChart
      ? "No scans yet. Your risk-level split will appear here."
      : "The chart could not load (you may be offline).";
    if (hasChart && levelTotal > 0) {
      if (!levelChart) {
        levelChart = new Chart($("levelChart"), {
          type: "doughnut",
          data: { labels: ["Low", "Moderate", "High", "Critical"],
            datasets: [{ data: levelData, backgroundColor: levelColors, borderWidth: 0, borderRadius: 6, hoverOffset: 6 }] },
          options: { responsive: true, maintainAspectRatio: false, cutout: "68%", spacing: 3,
            plugins: {
              legend: { position: "bottom", labels: { color: muted, usePointStyle: true, pointStyle: "circle", boxWidth: 8, padding: 14 } },
              centerText: { total: levelTotal, color: text, sub: muted }
            } },
          plugins: [centerTextPlugin]
        });
      } else {
        levelChart.data.datasets[0].data = levelData;
        levelChart.data.datasets[0].backgroundColor = levelColors;
        levelChart.options.plugins.legend.labels.color = muted;
        levelChart.options.plugins.centerText = { total: levelTotal, color: text, sub: muted };
        levelChart.update();
      }
    }

    /* Top scam categories */
    const rows = categoryCounts();
    $("categoryWrap").hidden = !hasChart || rows.length === 0;
    $("categoryEmpty").hidden = hasChart && rows.length > 0;
    $("categoryEmpty").textContent = hasChart
      ? "No scam category found yet. Scan a suspicious message and it will show up here."
      : "The chart could not load (you may be offline).";
    if (hasChart && rows.length > 0) {
      const labels = rows.map((r) => r[0]);
      const values = rows.map((r) => r[1]);
      const biggest = Math.max.apply(null, values);
      if (!categoryChart) {
        categoryChart = new Chart($("categoryChart"), {
          type: "bar",
          data: { labels: labels,
            datasets: [{ label: "Scans", data: values, backgroundColor: barGradient,
              borderRadius: 8, borderSkipped: false, barThickness: 18 }] },
          options: { indexAxis: "y", responsive: true, maintainAspectRatio: false,
            layout: { padding: { right: 28 } },
            plugins: { legend: { display: false }, barValues: { color: text } },
            scales: {
              x: { display: false, beginAtZero: true, suggestedMax: biggest + 1 },
              y: { grid: { display: false }, border: { display: false },
                ticks: { color: muted, callback: function (v) {
                  const l = this.getLabelForValue(v);
                  return l.length > 24 ? l.slice(0, 23) + "…" : l;
                } } }
            } },
          plugins: [barValuePlugin]
        });
      } else {
        categoryChart.data.labels = labels;
        categoryChart.data.datasets[0].data = values;
        categoryChart.options.scales.x.suggestedMax = biggest + 1;
        categoryChart.options.scales.y.ticks.color = muted;
        categoryChart.options.plugins.barValues = { color: text };
        categoryChart.update();
      }
    }
  }

  // redraw with the right colours when the theme is switched
  window.addEventListener("themechange", () => { if (levelChart || categoryChart) renderBreakdownCharts(); });

  /* ----- Recent scans card (fills the space under the scanner) ----- */
  function renderRecent() {
    const list = $("recentList");
    list.textContent = "";
    const items = history.slice(0, 20);
    $("recentEmpty").hidden = items.length > 0;
    items.forEach((h) => {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "recent-item";

      const badge = document.createElement("span");
      badge.className = "recent-badge level-" + h.level;
      badge.textContent = String(h.score);

      const body = document.createElement("span");
      body.className = "recent-body";
      const text = document.createElement("span");
      text.className = "recent-text";
      text.textContent = h.input;
      const meta = document.createElement("span");
      meta.className = "recent-meta";
      meta.textContent = (h.mode === "url" ? "URL" : "Message") + " · " + fmtTime(h.t);
      body.appendChild(text);
      body.appendChild(meta);

      btn.appendChild(badge);
      btn.appendChild(body);
      btn.addEventListener("click", () => {
        setMode(h.mode === "url" ? "url" : "message");
        $("scanInput").value = h.input;
        updateCounter();
        $("scanInput").focus();
      });
      li.appendChild(btn);
      list.appendChild(li);
    });
  }
  function refreshDashboard() {
    renderHistory();
    renderStats();
    renderChart();
    renderBreakdownCharts();
    renderRecent();
  }

  /* ------------------------------------------------------------
     8. Scanner controls
  ------------------------------------------------------------ */
  function showError(msg) {
    const el = $("inputError");
    el.textContent = msg;
    el.hidden = false;
  }

  function hideError() {
    $("inputError").hidden = true;
    $("inputError").textContent = "";
  }

  function updateCounter() {
    $("charCount").textContent = String($("scanInput").value.length);
  }

  function clearInput() {
    $("scanInput").value = "";
    updateCounter();
    hideError();
  }

  function renderSamples() {
    const box = $("sampleButtons");
    box.textContent = "";
    SAMPLES.filter((s) => s.mode === mode).forEach((s) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      b.textContent = s.label;
      b.addEventListener("click", () => {
        $("scanInput").value = s.text;
        updateCounter();
        hideError();
        $("scanInput").focus();
      });
      box.appendChild(b);
    });
  }

  function setMode(next) {
    mode = next;
    const isMsg = mode === "message";
    $("tabMessage").classList.toggle("active", isMsg);
    $("tabUrl").classList.toggle("active", !isMsg);
    $("tabMessage").setAttribute("aria-selected", String(isMsg));
    $("tabUrl").setAttribute("aria-selected", String(!isMsg));
    $("scanPanel").setAttribute("aria-labelledby", isMsg ? "tabMessage" : "tabUrl");
    $("inputLabel").textContent = isMsg
      ? "Paste an SMS, WhatsApp message or payment request"
      : "Enter one URL or domain to check";
    $("scanInput").placeholder = isMsg
      ? "Paste the message here. Do not paste real OTPs, PINs or passwords."
      : "Example: https://example.com/page (the link is never opened)";
    clearInput();
    resetResult();
    renderSamples();
  }

    /* ----- "Analysing..." animation ----- */
  let scanTimer = null;
  let scanStepTimer = null;

  function startScanning() {
    const steps = mode === "message"
      ? ["Reading the message...", "Checking urgency and threat words...", "Looking for links and payment requests...", "Matching known scam patterns..."]
      : ["Reading the link...", "Checking the domain...", "Looking for risky patterns...", "Matching known scam patterns..."];
    let i = 0;
    $("scanStep").textContent = steps[0];
    $("resultEmpty").hidden = true;
    $("resultBody").hidden = true;
    $("scanningState").hidden = false;
    delete $("resultPanel").dataset.level;
    $("analyseBtn").disabled = true;
    $("analyseBtn").textContent = "Analysing...";
    scanStepTimer = setInterval(() => {
      i = Math.min(i + 1, steps.length - 1);
      $("scanStep").textContent = steps[i];
    }, 200);
  }

  function endScanning() {
    clearTimeout(scanTimer);
    clearInterval(scanStepTimer);
    scanTimer = null;
    scanStepTimer = null;
    $("scanningState").hidden = true;
    $("analyseBtn").disabled = false;
    $("analyseBtn").textContent = "Analyse";
  }

  function analyse() {
    if (scanTimer) return;   // already analysing
    hideError();
    const value = $("scanInput").value.trim();

    if (!value) {
      showError(mode === "message"
        ? "Paste a message first, then select Analyse."
        : "Enter a URL or domain first, then select Analyse.");
      return;
    }

    let result;
    if (mode === "message") {
      result = scanMessage(value);
    } else {
      if (/\s/.test(value)) { showError("Enter one URL at a time, without spaces."); return; }
      const parsed = parseUrl(value);
      if (!parsed) {
        showError("That does not look like a valid http(s) URL or domain. Try something like https://example.com/page");
        return;
      }
      result = scanUrl(parsed, value);
    }
    
        // ---- AI branch: purane engine ke saath hi shuru, alag chalta hai ----
   
           // ---- AI branch: purane engine ke saath hi shuru, alag chalta hai ----
    if (typeof getAIAnalysis === "function") {
      result.aiState = "loading";
      getAIAnalysis(value.slice(0, 3000)).then((ai) => {
        result.ai = ai;                                   // AI fail hua to null
        result.aiState = ai ? "done" : "unavailable";
        if (typeof combineResults === "function") {
          result.fusion = combineResults(result, ai);
        }
        // Sirf tab screen badlo jab user abhi isi result ko dekh raha ho
        if (lastResult === result) renderAIPanel(result);
      });
    } else {
      result.aiState = "unavailable";
    }
    
     
    const finish = () => {
      endScanning();
      renderResult(result);
      addToHistory(result);
      refreshDashboard();
    };

    const quick = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (quick) { finish(); return; }   // no animation if the person prefers reduced motion

    startScanning();
    scanTimer = setTimeout(finish, 800);
  }

  /* ------------------------------------------------------------
     9. Copy report and CSV export
  ------------------------------------------------------------ */
  function buildReport(r) {
    const lines = [
      "ScamShield AI report",
      "Type: " + (r.mode === "url" ? "URL" : "Message"),
      "Input: " + r.input.slice(0, 300),
      `Risk: ${LABELS[r.level]} (heuristic score ${r.score}/100, not a fraud probability)`,
      "Summary: " + r.summary,
      "Warning signs:"
    ];
    if (r.indicators.length === 0) lines.push("- None matched");
    r.indicators.forEach((i) => lines.push(`- ${i.title}: ${i.why}`));
    lines.push("Next step: " + r.recommendation);
    return lines.join("\n");
  }

  function copyReport() {
    if (!lastResult) return;
    const text = buildReport(lastResult);
    const status = $("copyStatus");
    const done = (ok) => {
      status.textContent = ok ? "Report copied." : "Could not copy. Please select and copy the text manually.";
      setTimeout(() => { status.textContent = ""; }, 3000);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => done(true), () => done(false));
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      done(ok);
    }
  }

  function csvCell(v) {
    let s = String(v == null ? "" : v).replace(/\r?\n/g, " ");
    if (/^[=+\-@\t]/.test(s)) s = "'" + s; // stops spreadsheet formula injection
    return '"' + s.replace(/"/g, '""') + '"';
  }

  function exportCsv() {
    if (history.length === 0) {
      alert("There are no scans to export yet.");
      return;
    }
    const rows = [["Timestamp", "Type", "Input", "Score", "Risk level", "Indicators"]];
    history.forEach((h) => rows.push([
      h.t, h.mode, h.input, h.score, LABELS[h.level] || h.level, (h.indicators || []).join("; ")
    ]));
    const csv = rows.map((r) => r.map(csvCell).join(",")).join("\r\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "scamshield-history.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }


   async function clearHistory() {
    if (history.length === 0 || !db) return;
    if (!confirm("Delete all your saved scans? This cannot be undone.")) return;
    const { error } = await db.from("scans").delete().eq("user_id", userId);
    if (error) { setCloudStatus("Could not clear your history. Please try again."); return; }
    history = [];
    setCloudStatus("");
    refreshDashboard();
  }

  /* ------------------------------------------------------------
     10. Sidebar, modal, navigation
  ------------------------------------------------------------ */
  function openSidebar() {
    $("sidebar").classList.add("open");
    $("sidebarBackdrop").hidden = false;
    $("menuToggle").setAttribute("aria-expanded", "true");
  }

  function closeSidebar() {
    $("sidebar").classList.remove("open");
    $("sidebarBackdrop").hidden = true;
    $("menuToggle").setAttribute("aria-expanded", "false");
  }

  function openAbout() {
    $("aboutModal").hidden = false;
    $("closeAbout").focus();
  }

  function closeAbout() {
    $("aboutModal").hidden = true;
    $("openAbout").focus();
  }

  function setupNavHighlight() {
    const links = Array.from(document.querySelectorAll(".nav-link"));
    links.forEach((l) => l.addEventListener("click", closeSidebar));
    if (!("IntersectionObserver" in window)) return;
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          links.forEach((l) => l.classList.toggle("active", l.getAttribute("href") === "#" + e.target.id));
        }
      });
    }, { rootMargin: "-30% 0px -60% 0px" });
    links.forEach((l) => {
      const section = document.querySelector(l.getAttribute("href"));
      if (section) io.observe(section);
    });
  }

  /* ------------------------------------------------------------
     11. Start
  ------------------------------------------------------------ */
  function init() {
    const now = new Date();
    $("todayDate").textContent = now.toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" });
    $("todayDate").setAttribute("datetime", now.toISOString().slice(0, 10));

    $("tabMessage").addEventListener("click", () => setMode("message"));
    $("tabUrl").addEventListener("click", () => setMode("url"));
    $("scanInput").addEventListener("input", () => { updateCounter(); hideError(); });
    $("scanInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyse();
    });
    $("analyseBtn").addEventListener("click", analyse);
    $("clearBtn").addEventListener("click", clearInput);
    $("copyBtn").addEventListener("click", copyReport);
    $("newScanBtn").addEventListener("click", () => { clearInput(); resetResult(); $("scanInput").focus(); });
    $("exportBtn").addEventListener("click", exportCsv);
    $("clearHistoryBtn").addEventListener("click", clearHistory);
    

    $("menuToggle").addEventListener("click", () => {
      $("sidebar").classList.contains("open") ? closeSidebar() : openSidebar();
    });
    $("sidebarBackdrop").addEventListener("click", closeSidebar);
    $("openAbout").addEventListener("click", openAbout);
    $("closeAbout").addEventListener("click", closeAbout);
    $("aboutModal").addEventListener("click", (e) => { if (e.target === $("aboutModal")) closeAbout(); });
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (!$("aboutModal").hidden) closeAbout();
      else closeSidebar();
    });

    setupNavHighlight();
      setupNavHighlight();
    renderSamples();
  }

  // auth.js calls these when someone logs in or out.
  window.ScamShield = {
    async start(client, user) {
      db = client;
      userId = user.id;
      setMode("message");
      history = [];
      refreshDashboard();
      await loadHistory();
      refreshDashboard();
      if (chart) chart.resize();
    },
    stop() {
      db = null;
      userId = null;
      history = [];
      setMode("message");
      setCloudStatus("");
      refreshDashboard();
    }
  };

  init();
})();