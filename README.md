# ScamShield AI

**Protect before you pay.**

An explainable FinTech safety prototype that flags suspicious UPI-related messages and phishing URL patterns using client-side heuristic analysis, with real user accounts and a private scan history.

Built for **HackFront India** (FinTech theme).

> **Accuracy note:** The detection engine is **not a trained AI model**. It is a transparent, rule-based JavaScript engine. It does not verify who sent a message, open links, or use live threat-intelligence data. The score is a heuristic indicator score, **not a probability of fraud**.

---

## 1. Problem statement

Digital-payment users in India receive messages and links that imitate banks, payment apps, support teams and government services. Common tricks include:

- Threatening that an account, card or UPI access will be blocked
- Asking for an unexpected KYC or identity update
- Asking for an OTP, UPI PIN, CVV or password
- Sending shortened or deceptive links
- Promising unexpected cashback, prizes or refunds
- Asking users to install remote-access or screen-sharing apps
- Creating urgency so the user does not verify

Many users do not know which details are suspicious or what to do next.

## 2. Solution overview

After logging in, a user can paste a message or a URL and get:

- A risk score from 0 to 100
- A risk category (Low, Moderate, High, Critical)
- A list of warning signs found, each with a plain-language explanation
- A recommended next step

The analysis runs in the browser. Each user's saved scan history is stored in their own account and protected by database Row Level Security.

## 3. Features

- Real authentication with Supabase Auth: sign up, log in, log out
- Email verification, password reset, "Remember session" option
- Form validation, show/hide password, loading states and clear error messages
- Dashboard hidden until a valid session is confirmed with the Supabase server
- Profile section (name, email, verification status, member since)
- Message scanner (SMS, WhatsApp, payment requests)
- URL scanner (analysed as text only, the link is never opened)
- Explainable results with a score ring, indicators and advice
- Private cloud scan history (latest 50 scans per user) with Row Level Security
- Dashboard: total scans, high/critical flags, links detected, 7-day activity chart
- CSV export of scan history, copy report button
- Safety guide: Stop, Verify, Report (1930 helpline and the National Cyber Crime Reporting Portal)
- Demo samples, including a normal message that is not flagged
- Responsive dark dashboard with a mobile sidebar and keyboard-friendly controls

## 4. Technology stack

- HTML5, CSS3, vanilla JavaScript
- [Supabase](https://supabase.com/) Auth and Postgres (Row Level Security)
- [Supabase JavaScript client](https://supabase.com/docs/reference/javascript) from a CDN (pinned version)
- [Chart.js](https://www.chartjs.org/) from a CDN (optional, the app still works without it)

No build tools and no backend server of our own. Hosted as a static site on GitHub Pages.

## 5. Screenshots

Add real screenshots after running the app (create an `assets` folder for them).

| Login | Dashboard | Result panel |
|---|---|---|
| _add `assets/login.png`_ | _add `assets/dashboard.png`_ | _add `assets/result.png`_ |

## 6. Project structure

```text
ScamShield-AI/
├── index.html           Page structure: auth screen + dashboard
├── style.css            Dark theme and layout
├── script.js            Detection engine, scoring, charts, scan history
├── auth.js              Supabase authentication and session handling
├── supabase-setup.sql   Tables and Row Level Security policies
├── data/
│   └── test-cases.json  Fictional test inputs and expected results
├── README.md
├── LICENSE
└── .gitignore
```

## 7. Supabase setup

You need a free Supabase project. The dashboard labels can change slightly over time.

1. **Create a project** at supabase.com. Save the database password somewhere private. Never put it in this repository.
2. **Create the tables and security rules:** open **SQL Editor**, create a new query, paste the whole of `supabase-setup.sql` and run it. This creates `profiles` and `scans`, enables Row Level Security, adds an automatic profile trigger and keeps each user's latest 50 scans.
3. **Copy the public keys:** open **Project Settings, API Keys** and copy the **Project URL** and the **publishable key** (`sb_publishable_...`). The older **anon** key also works. Paste them into the two constants at the top of `auth.js`:
   ```javascript
   const SUPABASE_URL = "https://ptzgnpvokdktfmoijuco.supabase.co";
   const SUPABASE_KEY =  "sb_publishable_0eqjv6bbZPQxEDEQHqD_rg_NxNx5eJx";
   ```
   These two values are meant to be public. Never use the `service_role` or secret key anywhere in this project.
4. **Email sign-in:** open **Authentication, Sign In / Providers, Email**. Keep the provider enabled, keep **Confirm email** turned on and set the minimum password length to 8.
5. **Redirect URLs:** open **Authentication, URL Configuration**.
   - Site URL: `https://arjun609-jpg.github.io/ScamShield-AI/
   - Add these Redirect URLs:
     - `https://arjun609-jpg.github.io/ScamShield-AI/**`
     - `http://127.0.0.1:5500/**`
     - `http://localhost:5500/**`
6. **Email delivery:** Supabase's built-in email sender is meant for testing and is heavily limited. For real sign-ups, add custom SMTP (for example Resend or Brevo) under **Authentication, Emails, SMTP Settings**.

## 8. Local setup

1. Download or clone the repository and open the folder in VS Code.
2. Fill in your Supabase URL and key in `auth.js` (section 7, step 3).
3. Install the **Live Server** extension, right-click `index.html` and choose **Open with Live Server**. Opening the file directly (`file://`) does not work, because sign-in needs a normal web address.

## 9. How the risk score works

Each matched rule adds points. Points are summed and capped at 100.

| Score | Category |
|---|---|
| 0 to 25 | Low risk |
| 26 to 50 | Moderate |
| 51 to 75 | High risk |
| 76 to 100 | Critical |

**Message rules**

| Pattern | Points |
|---|---|
| Asks for OTP, UPI PIN, CVV or password | +32 |
| Remote-access or screen-sharing tool mentioned | +28 |
| Account-blocking or suspension threat | +22 |
| Urgent or pressuring language | +20 |
| Unexpected refund, QR or payment request | +20 |
| Shortened link | +20 |
| Unexpected KYC or identity update | +18 |
| Prize or reward language | +18 |
| Support or authority impersonation cue | +15 |
| Link with a possibly deceptive domain | +24 |
| Contains an external link | +8 |

**URL rules**

| Indicator | Points |
|---|---|
| URL shortener | +28 |
| Raw IP address as host | +30 |
| Hidden user information in the link | +30 |
| Possible lookalike or encoded domain | +22 |
| Unusual domain ending | +20 |
| Bank or payment term in an unverified domain | +18 |
| Login, verify or KYC word in the path | +16 |
| HTTP instead of HTTPS | +10 |

A low score never means "safe". It only means few known rules matched.

## 10. Test cases

All samples are fictional. More cases are in `data/test-cases.json`.

| Input | Expected result |
|---|---|
| Urgent KYC alert (message) | Critical |
| OTP request (message) | High |
| Normal electricity bill confirmation (message) | Low, score 0 |
| `https://bit.ly/example` (URL) | Moderate (shortener) |
| `http://example.com/account/login` (URL) | Moderate (HTTP and login path) |

**Authentication checklist**

1. Opening the site while logged out shows the login page, never the dashboard.
2. Sign up with a bad email, a short password or mismatched passwords shows an error.
3. A valid sign-up shows "Check your email"; the verification link opens the dashboard.
4. Logging in before verifying shows the verification screen.
5. Log out returns to the login page, and the browser Back button does not reveal the dashboard.
6. Refreshing the page keeps the session. With "Remember session" off, a new browser session asks for login again.
7. "Forgot password" email opens the "Set a new password" screen, and the new password works.
8. Two different accounts never see each other's scan history.

## 11. Security and privacy

- Passwords are handled by Supabase Auth over HTTPS. This app never stores them, and nothing password-related is kept in LocalStorage.
- The browser keeps a session token (not the password). With "Remember session" on it lives in LocalStorage, otherwise in SessionStorage.
- Only the publishable key is used in the browser. The `service_role` / secret key is never used or committed.
- On every page load the app asks the Supabase server to confirm the session before showing the dashboard.
- **Row Level Security** is enabled on `profiles` and `scans`. A signed-in user can read, add and delete only their own scans, and visitors who are not logged in get no access. The `user_id` of a scan is set by the database from the login session, so it cannot be faked from the browser.
- Scans are analysed in the browser. Only the saved history entry (up to 500 characters of the input, score and warning signs) is stored in the user's account. Submitted URLs are never opened or fetched.
- Please do not paste real OTPs, PINs, card numbers or passwords into the scanner.
- User text is inserted with `textContent` to avoid HTML injection.

## 12. Limitations

- False negatives: new or cleverly worded scams can score low.
- False positives: genuine messages can match rules (for example a real bank message that contains a link).
- English-focused. Hindi, Hinglish and regional-language detection is minimal.
- The list of official domains is small and is not a verification service.
- No sender verification and no live reputation checks.
- Hiding the dashboard in the browser is only the user-facing part. The site's code is public static JavaScript, so the real protection is on each user's stored data (Row Level Security).

## 13. Deploy with GitHub Pages

1. Create a public repository named `ScamShield-AI` on GitHub.
2. Check that `auth.js` contains only the Project URL and the publishable key, and nothing secret.
3. In the project folder run:

```bash
git init
git add .
git commit -m "Build ScamShield AI with Supabase authentication"
git branch -M main
git remote add origin https://arjun609-jpg.github.io/ScamShield-AI.git
git push -u origin main
```

4. In the repository open **Settings, Pages**, choose **Deploy from a branch**, select `main` and `/ (root)`, then **Save**.
5. Open `https://arjun609-jpg.github.io/ScamShield-AI/`.` after a minute.
6. Make sure the Site URL and Redirect URLs in Supabase match this address exactly (section 7, step 5).

## 14. Demo walkthrough

1. Explain the problem: convincing messages push people into unsafe payments.
2. Show the sign-up and login screen, then log in.
3. Load the **Urgent KYC alert** sample and select **Analyse**. Walk through the score and each warning sign.
4. Switch to **URL scan** and test the shortened link sample.
5. Run the **Normal bill confirmation** sample to show that not everything is flagged.
6. Show scan history, **Export CSV** and the **Profile** section, then log out.
7. Explain that each user's data is private through Row Level Security.
8. State the limitations and next steps.

## 15. Future improvements

These are plans, not features that exist today.

- Hindi and Hinglish message analysis, more regional-language patterns
- A labelled, consented dataset to measure precision, recall and F1
- Compare the rules baseline with a trained model while keeping explanations
- Optional threat-intelligence checks through a secure backend
- Safe server-side URL analysis with protection against SSRF and malicious redirects
- Optional sign-in with Google and rate limiting on scan saving

## 16. If you lose money to a cyber fraud (India)

Call **1930** immediately and report at the [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/).

## 17. License

Released under the [MIT License](LICENSE).