import fs from "node:fs/promises";

const candidates = JSON.parse(await fs.readFile("candidates.json", "utf8"));
const systemPrompt = await fs.readFile("prompts/issue-resolution-system.txt", "utf8");
const outputSchema = JSON.parse(await fs.readFile("schemas/issue-resolution-output.json", "utf8"));

function isMaintainerRole(role) {
  return ["MEMBER", "OWNER", "COLLABORATOR"].includes(role || "");
}

function preScore(candidate) {
  let score = 0;
  const hardSignals = [];
  const contradictions = [];

  for (const t of candidate.timeline) {
    const sourceIssue = t.source?.issue;

    if (t.event === "cross-referenced" && sourceIssue?.pull_request?.html_url) {
      hardSignals.push({
        type: "merged_pr",
        url: sourceIssue.html_url
      });
      score += 40; // provisional until PR merged state is verified
    }

    if (["referenced", "connected"].includes(t.event)) {
      score += 10;
    }
  }

  for (const c of candidate.comments) {
    const body = c.body.toLowerCase();

    if (
      isMaintainerRole(c.author_association) &&
      /\b(fixed|resolved|duplicate|superseded|closing)\b/.test(body)
    ) {
      score += 25;
      hardSignals.push({
        type: "maintainer_comment",
        url: c.html_url
      });
    }

    if (/\b(still broken|still happening|not fixed|reproducible)\b/.test(body)) {
      score -= 50;
      contradictions.push({
        type: "later_unresolved_comment",
        url: c.html_url
      });
    }
  }

  return { score, hardSignals, contradictions };
}

// GitHub Models gpt-4o has an 8000 token input limit.
// Reserve ~2000 tokens for system prompt + response overhead.
// 1 token ~= 4 chars, so cap user message at ~24000 chars.
const MAX_USER_MESSAGE_CHARS = 24000;

function truncate(text, maxChars) {
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + "\n\n[... truncated due to length]";
}

function buildUserMessage(candidate, pre) {
  const { issue, comments, timeline } = candidate;

  const commentBlock = comments
    .map((c) => `[${c.author_association}] ${c.user} (${c.created_at}):\n${c.body}`)
    .join("\n---\n");

  const timelineBlock = timeline
    .filter((t) => ["cross-referenced", "referenced", "connected", "closed", "reopened"].includes(t.event))
    .map((t) => {
      let line = `${t.event} (${t.created_at})`;
      if (t.source?.issue?.html_url) line += ` — ${t.source.issue.html_url}`;
      if (t.source?.issue?.pull_request?.html_url) line += ` (PR: ${t.source.issue.pull_request.html_url})`;
      return line;
    })
    .join("\n");

  const sections = [
    `## Issue #${issue.number}: ${issue.title}`,
    `URL: ${issue.html_url}`,
    `Created: ${issue.created_at} | Updated: ${issue.updated_at}`,
    `Labels: ${issue.labels.join(", ") || "none"}`,
    "",
    "### Body",
    truncate(issue.body || "(empty)", 4000),
    "",
    "### Comments",
    commentBlock || "(none)",
    "",
    "### Timeline events",
    timelineBlock || "(none)",
  ];

  if (candidate.linked_prs?.length) {
    sections.push("");
    sections.push("### Linked PRs (verified state)");
    for (const pr of candidate.linked_prs) {
      const status = pr.merged ? `MERGED (${pr.merged_at})` : pr.state.toUpperCase();
      sections.push(`- PR #${pr.number}: ${pr.title} — ${status} — ${pr.url}`);
    }
  }

  if (pre.hardSignals.length || pre.contradictions.length) {
    sections.push("");
    sections.push("### Automated evidence scan");
    for (const s of pre.hardSignals) {
      sections.push(`- SIGNAL: ${s.type} — ${s.url}`);
    }
    for (const c of pre.contradictions) {
      sections.push(`- CONTRADICTION: ${c.type} — ${c.url}`);
    }
  }

  return truncate(sections.join("\n"), MAX_USER_MESSAGE_CHARS);
}

const MODEL = "gpt-4o-mini";
const MAX_RETRIES = 5;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callGitHubModel(candidate, pre) {
  const body = JSON.stringify({
    model: MODEL,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: buildUserMessage(candidate, pre) },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "issue_resolution",
        strict: true,
        schema: outputSchema,
      },
    },
    temperature: 0.1,
  });

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const res = await fetch("https://models.inference.ai.azure.com/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.GH_TOKEN}`,
        "Content-Type": "application/json",
      },
      body,
    });

    if (res.status === 429) {
      const retryAfter = Number(res.headers.get("retry-after")) || 30;
      if (retryAfter > 120) {
        console.warn(`  [QUOTA EXHAUSTED] API wants ${retryAfter}s wait — skipping remaining issues.`);
        return null;
      }
      console.warn(`  [RATE LIMITED] Waiting ${retryAfter}s (attempt ${attempt + 1}/${MAX_RETRIES})...`);
      await sleep(retryAfter * 1000);
      continue;
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`GitHub Models ${res.status}: ${text}`);
    }

    const data = await res.json();
    return JSON.parse(data.choices[0].message.content);
  }

  throw new Error(`GitHub Models: exceeded ${MAX_RETRIES} retries due to rate limiting`);
}

function enforcePolicy(modelOut, pre) {
  const approvedReasons = new Set([
    "resolved_by_merged_pr",
    "maintainer_confirmed_resolved",
    "duplicate_confirmed",
    "superseded_confirmed"
  ]);

  const hasHardSignal =
    (modelOut.hard_signals || []).some(s =>
      ["merged_pr", "maintainer_comment", "duplicate_reference", "superseded_reference"].includes(s.type)
    ) || pre.hardSignals.length > 0;

  const hasContradiction =
    (modelOut.contradictions || []).length > 0 || pre.contradictions.length > 0;

  // Only auto-close with very strict criteria
  if (
    modelOut.decision === "AUTO_CLOSE" &&
    modelOut.confidence >= 0.97 &&
    approvedReasons.has(modelOut.reason_code) &&
    hasHardSignal &&
    !hasContradiction
  ) {
    return "AUTO_CLOSE";
  }

  // Downgrade AUTO_CLOSE that didn't pass the gate
  if (modelOut.decision === "AUTO_CLOSE") {
    return "MANUAL_REVIEW";
  }

  // Otherwise trust the model
  return modelOut.decision;
}

console.log(`Classifying ${candidates.length} candidates with ${MODEL}...\n`);

// 15 req/min limit → 1 request every 4s. Use 4.5s for safety margin.
const PACE_MS = 4500;
let lastRequestTime = 0;

async function paced(fn) {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < PACE_MS) await sleep(PACE_MS - elapsed);
  lastRequestTime = Date.now();
  return fn();
}

const decisions = [];
for (const candidate of candidates) {
  const pre = preScore(candidate);
  const modelOut = await paced(() => callGitHubModel(candidate, pre));

  if (modelOut === null) {
    console.warn(`\nQuota exhausted after ${decisions.length} issues. Writing partial results.`);
    break;
  }

  const finalDecision = enforcePolicy(modelOut, pre);

  decisions.push({
    repository: candidate.repository,
    issue_number: candidate.issue.number,
    issue_url: candidate.issue.html_url,
    title: candidate.issue.title,
    pre_score: pre.score,
    final_decision: finalDecision,
    model: modelOut
  });

  console.log(
    `#${candidate.issue.number} | pre_score: ${pre.score} | model: ${modelOut.decision} @ ${modelOut.confidence} | final: ${finalDecision} | ${modelOut.reason_code}`
  );
}

await fs.writeFile("decisions.json", JSON.stringify(decisions, null, 2));
console.log(`\nWrote ${decisions.length} decisions to decisions.json`);