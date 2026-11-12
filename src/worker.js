// Serves the app from /public (via the ASSETS binding) and handles POST /api/plan.
const MODEL = "claude-haiku-5-5";

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { "content-type": "application/json" },
  });
}

async function makePlan(request, env) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: "not_configured" }, 501);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
  const goal = String(body.goal || "").trim().slice(0, 120);
  const days = Number(body.days);
  if (!goal || !Number.isInteger(days) || days < 3 || days > 30) return json({ error: "bad_request" }, 400);

  const prompt =
    "You are a practical coach. The person's goal: \"" + goal + "\".\n" +
    "Break it into exactly " + days + " daily steps, one per day, in order. Each step is a small, concrete action " +
    "that takes about 20 to 30 minutes, builds on the day before, and is written as an instruction (for example " +
    "\"Read 20 pages of your book\"). Keep each step under 60 characters. Make the last day a short review or wrap-up.\n" +
    "Reply with JSON only, no other text, in this shape: {\"steps\":[\"...\"]}";

  let res;
  try {
    res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 2000,
        messages: [{ role: "user", content: prompt }],
      }),
    });
  } catch (e) {
    return json({ error: "upstream" }, 502);
  }
  if (!res.ok) return json({ error: "upstream" }, 502);

  const data = await res.json();
  const text = (data.content || []).map((b) => b.text || "").join("");
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) return json({ error: "parse" }, 502);
  let steps;
  try { steps = JSON.parse(match[0]).steps; } catch (e) { return json({ error: "parse" }, 502); }
  if (!Array.isArray(steps) || !steps.length) return json({ error: "parse" }, 502);

  steps = steps.slice(0, days).map((s) => String(s).trim().slice(0, 80));
  return json({ steps });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/plan") {
      if (request.method !== "POST") return json({ error: "method" }, 405);
      return makePlan(request, env);
    }
    return env.ASSETS.fetch(request);
  },
};
