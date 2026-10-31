# ScamShield AI

**Protect before you pay.**

An explainable FinTech safety prototype that flags suspicious UPI-related messages and phishing URL patterns using client-side heuristic analysis.

Built for **HackFront India** (FinTech theme).

> **Accuracy note:** This prototype is **not a trained AI model**. It uses a transparent, rule-based JavaScript engine. It does not connect to banks, verify who sent a message, open links, or use live threat-intelligence data. The score is a heuristic indicator score, **not a probability of fraud**.

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

ScamShield AI lets a user paste a message or a URL and get:

- A risk score from 0 to 100
- A risk category (Low, Moderate, High, Critical)
- A list of warning signs found, each with a plain-language explanation
- A recommended next step

Everything runs in the browser. No account, API key or server is needed.

## 3. Features

- Message scanner (SMS, WhatsApp, payment requests)
- URL scanner (analysed as text only, the link is never opened)
- Explainable results with a score ring, indicators and advice
- Scan history saved in LocalStorage (latest 50 scans) with confirmation before clearing
- Dashboard: total scans, high/critical flags, links detected, 7-day activity chart
- CSV export of scan history
- Copy report button
- Safety guide: Stop, Verify, Report (includes the 1930 helpline and the National Cyber Crime Reporting Portal)
- Demo samples, including a normal message that is not flagged
- Responsive dark dashboard with a mobile sidebar and keyboard-friendly controls

## 4. Technology stack

- HTML5
- CSS3
- Vanilla JavaScript
- [Chart.js](https://www.chartjs.org/) from a CDN (optional, the app still works without it)
- Browser LocalStorage

No build tools, backend, database or paid service.

## 5. Screenshots

Add real screenshots after running the app.

| Dashboard | Result panel | Mobile view |
|---|---|---|
| _add `assets/dashboard.png`_ | _add `assets/result.png`_ | _add `assets/mobile.png`_ |

## 6. Local setup

1. Download or clone the repository.
2. Open the `ScamShield-AI` folder in VS Code.
3. Either double-click `index.html`, or install the **Live Server** extension, right-click `index.html` and choose **Open with Live Server**.

```text
ScamShield-AI/
├── index.html
├── style.css
├── script.js
├── data/
│   └── test-cases.json
├── assets/
├── README.md
├── LICENSE
└── .gitignore
```

## 7. How the risk score works

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

## 8. Sample test cases

All samples are fictional.

| Input | Expected result |
|---|---|
| Urgent KYC alert (message) | Score 92, Critical |
| OTP request (message) | Score 67, High |
| Normal electricity bill confirmation (message) | Score 0, Low |
| `https://bit.ly/example` (URL) | Score 28, Moderate (shortener) |
| `http://example.com/account/login` (URL) | Score 26, Moderate (HTTP + login path) |

Also check: empty input shows an error, an invalid URL shows an error, and history survives a page refresh.

## 9. Privacy and limitations

**Privacy**

- Analysis runs entirely in your browser. Input is never sent to a server.
- Submitted URLs are never opened or fetched.
- Scan history is stored in this browser's LocalStorage. Use **Clear history** to delete it.
- The app never asks for OTPs, PINs, card numbers or banking logins. Do not paste real ones.
- User text is inserted with `textContent` to avoid HTML injection.

**Limitations**

- False negatives: new or cleverly worded scams can score low.
- False positives: genuine messages can match rules (for example a real bank message that contains a link).
- English-focused. Hindi, Hinglish and regional-language detection is only minimal.
- The list of official domains is small and is not a verification service.
- No sender verification, no live reputation checks.

## 10. Deploy with GitHub Pages

1. Create a public repository named `ScamShield-AI` on GitHub.
2. In the project folder run:

```bash
git init
git add .
git commit -m "Build ScamShield AI prototype"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ScamShield-AI.git
git push -u origin main
```

3. In the repository go to **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select branch `main` and folder `/ (root)`, then **Save**.
6. Wait a minute, then open the URL shown in the Pages settings. It usually looks like `https://arjun609-jpg.github.io/ScamShield-AI/`.

## 11. Demo walkthrough

1. Explain the problem: convincing messages push people into unsafe payments.
2. Open the dashboard and load the **Urgent KYC alert** sample, then select **Analyse**.
3. Walk through the score and each warning sign.
4. Switch to **URL scan** and test the shortened link sample.
5. Run the **Normal bill confirmation** sample to show that not everything is flagged.
6. Show scan history and **Export CSV**.
7. Point out that analysis is local and needs no banking details.
8. State the limitations and next steps.

## 12. Future improvements

These are plans, not features that exist today.

- Hindi and Hinglish message analysis, more regional-language patterns
- More realistic genuine-message test cases to reduce false positives
- A labelled, consented dataset to measure precision, recall and F1
- Compare the rules baseline with a trained model, keeping explanations
- Optional threat-intelligence checks through a secure backend
- Safe server-side URL analysis with protection against SSRF and malicious redirects

## 13. If you lose money to a cyber fraud (India)

Call **1930** immediately and report at the [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/).

## 14. License

Released under the [MIT License](LICENSE).