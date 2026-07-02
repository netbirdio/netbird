import fs from "node:fs/promises";

const token = process.env.GH_TOKEN;
const repo = process.env.REPO; // "owner/repo"
const maxIssues = Number(process.env.MAX_ISSUES) || 100;

const headers = {
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

async function rest(url) {
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${res.status} ${url}: ${await res.text()}`);
  return res.json();
}

async function restSafe(url) {
  const res = await fetch(url, { headers });
  if (!res.ok) return null;
  return res.json();
}

async function paginate(url, max) {
  const items = [];
  let page = 1;
  while (items.length < max) {
    const perPage = Math.min(100, max - items.length);
    const sep = url.includes("?") ? "&" : "?";
    const batch = await rest(`${url}${sep}per_page=${perPage}&page=${page}`);
    if (!batch.length) break;
    items.push(...batch);
    page++;
  }
  return items.slice(0, max);
}

console.log(`Fetching up to ${maxIssues} open issues from ${repo}...`);

const issues = await paginate(
  `https://api.github.com/repos/${repo}/issues?state=open&sort=updated&direction=asc`,
  maxIssues
);

// Filter out pull requests (GitHub API returns PRs as issues too)
const realIssues = issues.filter((i) => !i.pull_request);
console.log(`Found ${realIssues.length} open issues (excluded PRs).`);

const candidates = [];
for (const issue of realIssues) {
  const [comments, timeline] = await Promise.all([
    rest(`https://api.github.com/repos/${repo}/issues/${issue.number}/comments?per_page=100`),
    rest(`https://api.github.com/repos/${repo}/issues/${issue.number}/timeline?per_page=100`),
  ]);

  candidates.push({
    repository: repo,
    issue: {
      number: issue.number,
      html_url: issue.html_url,
      title: issue.title,
      body: issue.body,
      created_at: issue.created_at,
      updated_at: issue.updated_at,
      labels: issue.labels.map((l) => l.name),
    },
    comments: comments.map((c) => ({
      body: c.body,
      author_association: c.author_association,
      html_url: c.html_url,
      created_at: c.created_at,
      user: c.user?.login,
    })),
    timeline: timeline.map((t) => ({
      event: t.event,
      created_at: t.created_at,
      source: t.source
        ? {
            issue: {
              html_url: t.source.issue?.html_url,
              pull_request: t.source.issue?.pull_request
                ? { html_url: t.source.issue.pull_request.html_url }
                : undefined,
            },
          }
        : undefined,
    })),
    linked_prs: [],
  });

  // Fetch merge status for cross-referenced PRs
  const prUrls = new Set();
  for (const t of timeline) {
    const prHtml = t.source?.issue?.pull_request?.html_url;
    if (t.event === "cross-referenced" && prHtml) {
      prUrls.add(prHtml);
    }
  }

  const candidate = candidates[candidates.length - 1];
  for (const prHtml of prUrls) {
    // Extract owner/repo and PR number from URL like https://github.com/owner/repo/pull/123
    const match = prHtml.match(/github\.com\/([^/]+\/[^/]+)\/pull\/(\d+)/);
    if (!match) continue;
    const [, prRepo, prNum] = match;
    const pr = await restSafe(`https://api.github.com/repos/${prRepo}/pulls/${prNum}`);
    if (!pr) continue;
    candidate.linked_prs.push({
      number: pr.number,
      title: pr.title,
      url: prHtml,
      state: pr.state,
      merged: pr.merged || false,
      merged_at: pr.merged_at,
    });
  }

  console.log(`  #${issue.number} — ${comments.length} comments, ${timeline.length} timeline events, ${candidate.linked_prs.length} linked PRs`);
}

await fs.writeFile("candidates.json", JSON.stringify(candidates, null, 2));
console.log(`Wrote ${candidates.length} candidates to candidates.json`);
