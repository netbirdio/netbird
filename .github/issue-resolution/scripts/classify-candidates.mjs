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

function buildUserMessage(candidate) {
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

  const msg = [
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
  ].join("\n");

  return truncate(msg, MAX_USER_MESSAGE_CHARS);
}

const MODEL = "gpt-4o";
const MAX_RETRIES = 5;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callGitHubModel(candidate) {
  const body = JSON.stringify({
    model: MODEL,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: buildUserMessage(candidate) },
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

  if (
    modelOut.decision === "AUTO_CLOSE" &&
    modelOut.confidence >= 0.97 &&
    approvedReasons.has(modelOut.reason_code) &&
    hasHardSignal &&
    !hasContradiction
  ) {
    return "AUTO_CLOSE";
  }

  if (modelOut.decision === "KEEP_OPEN" && pre.score < 25) {
    return "KEEP_OPEN";
  }

  if (
    modelOut.decision === "MANUAL_REVIEW" ||
    modelOut.decision === "AUTO_CLOSE" ||
    pre.score >= 25
  ) {
    return "MANUAL_REVIEW";
  }

  return "KEEP_OPEN";
}

console.log(`Classifying ${candidates.length} candidates with ${MODEL}...\n`);

const decisions = [];
for (const candidate of candidates) {
  const pre = preScore(candidate);
  const modelOut = await callGitHubModel(candidate);
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