// Purane engine aur AI ke jawab ko milakar ek final faisla banata hai.

const FUSION_LABELS = {
  HIGH_RISK: "High risk",
  SUSPICIOUS: "Suspicious",
  NEEDS_REVIEW: "Needs review",
  LOW_RISK: "No strong indicators found",
};

// Rows: purane engine ka level (low, moderate, high)
// Columns: AI (safe, pakka nahi, shak, bahut shak)
const FUSION_TABLE = [
  ["LOW_RISK",     "NEEDS_REVIEW", "NEEDS_REVIEW", "SUSPICIOUS"],
  ["NEEDS_REVIEW", "NEEDS_REVIEW", "SUSPICIOUS",   "SUSPICIOUS"],
  ["NEEDS_REVIEW", "NEEDS_REVIEW", "HIGH_RISK",    "HIGH_RISK"],
];

// URL mein ye signal mile to AI isse kam nahi kar sakta
const HARD_SIGNALS = [
  "Raw IP address used as the website",
  "Hidden user information in the link",
  "Possible lookalike or encoded domain",
];

function ruleRank(level) {
  if (level === "high" || level === "critical") return 2;
  if (level === "moderate") return 1;
  return 0;
}

function aiRank(ai) {
  if (ai.verdict === "INSUFFICIENT_EVIDENCE") return 1;
  if (ai.risk_level === "HIGH" || ai.verdict === "MALICIOUS") return 3;
  if (ai.risk_level === "MEDIUM" || ai.verdict === "SUSPICIOUS") return 2;
  return 0;
}

function combineResults(ruleResult, ai) {
  const rr = ruleRank(ruleResult.level);
  const hard = (ruleResult.indicators || []).some((i) => HARD_SIGNALS.includes(i.title));

  let final;
  let reason;

  if (!ai) {
    // AI nahi chala: sirf purana engine
    final = ["LOW_RISK", "NEEDS_REVIEW", "HIGH_RISK"][rr];
    reason = "AI analysis was unavailable, so this result uses the rule-based engine only.";
  } else if (hard) {
    final = "HIGH_RISK";
    reason = "The rule engine found a strong warning sign in the link. A reassuring AI opinion cannot lower this.";
  } else {
    final = FUSION_TABLE[rr][aiRank(ai)];
    if (final === "HIGH_RISK") reason = "Both the rule engine and the AI found strong warning signs.";
    else if (final === "SUSPICIOUS") reason = "At least one check found clear warning signs. Verify before you act.";
    else if (final === "NEEDS_REVIEW") reason = "The two checks do not agree, or evidence is weak. Do not treat this as safe. Verify independently.";
    else reason = "Neither check found strong warning signs. This does not prove it is safe.";
  }

  return {
    final,
    label: FUSION_LABELS[final],
    reason,
    aiAvailable: !!ai,
  };
}