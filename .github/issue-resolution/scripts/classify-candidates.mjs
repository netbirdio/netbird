import fs from "node:fs/promises";

const candidates = JSON.parse(await fs.readFile("candidates.json", "utf8"));

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

async function callGitHubModel(issuePacket) {
  // Replace this stub with the GitHub Models inference call used by your org.
  // The workflow already has models: read permission.
  return {
    decision: "MANUAL_REVIEW",
    reason_code: "likely_fixed_but_unconfirmed",
    confidence: 0.74,
    hard_signals: [],
    contradictions: [],
    summary: "Potential resolution candidate; evidence is not strong enough to close automatically.",
    close_comment: "This appears resolved, so we’re closing it automatically. Reply if this is still reproducible.",
    manual_review_note: "Potential resolution candidate. Please review evidence before closing."
  };
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

  if (
    modelOut.decision === "MANUAL_REVIEW" ||
    modelOut.confidence >= 0.60 ||
    pre.score >= 25
  ) {
    return "MANUAL_REVIEW";
  }

  return "KEEP_OPEN";
}

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
}

await fs.writeFile("decisions.json", JSON.stringify(decisions, null, 2));