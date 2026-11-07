// Backend function ko bulao aur AI ki report lao.
// Kuch bhi galat ho to null lautao (app crash nahi hoga).
async function getAIAnalysis(text) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000); // 12 second se zyada nahi ruko

  try {
    const res = await fetch("/.netlify/functions/analyze-message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });

    if (!res.ok) return null;

    const data = await res.json();
    return data.analysis || null;
  } catch (err) {
    console.warn("AI analysis nahi mila:", err.name);
    return null;
  } finally {
    clearTimeout(timer);
  }
}