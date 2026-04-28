import fs from "node:fs/promises";

const decisions = JSON.parse(await fs.readFile("decisions.json", "utf8"));
const dryRun = String(process.env.DRY_RUN).toLowerCase() === "true";

const headers = {
  Authorization: `Bearer ${process.env.GH_TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

async function rest(url, method = "GET", body) {
  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) throw new Error(`${res.status} ${url}: ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

async function graphql(query, variables) {
  const res = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables })
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  const json = await res.json();
  if (json.errors) throw new Error(JSON.stringify(json.errors));
  return json.data;
}

async function addLabel(owner, repo, issueNumber, labels) {
  return rest(
    `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/labels`,
    "POST",
    { labels }
  );
}

async function addComment(owner, repo, issueNumber, body) {
  return rest(
    `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/comments`,
    "POST",
    { body }
  );
}

async function closeIssue(owner, repo, issueNumber) {
  return rest(
    `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}`,
    "PATCH",
    { state: "closed", state_reason: "completed" }
  );
}

async function getIssueNodeId(owner, repo, issueNumber) {
  const issue = await rest(`https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}`);
  return issue.node_id;
}

async function addToProject(issueNodeId) {
  const mutation = `
    mutation($projectId: ID!, $contentId: ID!) {
      addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) {
        item { id }
      }
    }
  `;

  const data = await graphql(mutation, {
    projectId: process.env.PROJECT_ID,
    contentId: issueNodeId
  });

  return data.addProjectV2ItemById.item.id;
}

async function setTextField(itemId, fieldId, value) {
  const mutation = `
    mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $value: String!) {
      updateProjectV2ItemFieldValue(input: {
        projectId: $projectId,
        itemId: $itemId,
        fieldId: $fieldId,
        value: { text: $value }
      }) {
        projectV2Item { id }
      }
    }
  `;

  return graphql(mutation, {
    projectId: process.env.PROJECT_ID,
    itemId,
    fieldId,
    value
  });
}

for (const d of decisions) {
  const [owner, repo] = d.repository.split("/");

  if (d.final_decision === "AUTO_CLOSE") {
    if (dryRun) {
        await addLabel(owner, repo, d.issue_number, ["resolution-candidate"]);
        const issueNodeId = await getIssueNodeId(owner, repo, d.issue_number);
        const itemId = await addToProject(issueNodeId);
        await setTextField(itemId, process.env.PROJECT_REASON_FIELD_ID, `DRY_RUN:${d.model.reason_code}`);
        await setTextField(itemId, process.env.PROJECT_CONFIDENCE_FIELD_ID, String(d.model.confidence));
        console.log(`[DRY RUN] Would auto-close #${d.issue_number}`);
        continue;
    }

    await addLabel(owner, repo, d.issue_number, ["auto-closed-resolved"]);
    await addComment(owner, repo, d.issue_number, d.model.close_comment);
    await closeIssue(owner, repo, d.issue_number);
  }

  if (d.final_decision === "MANUAL_REVIEW") {
    await addLabel(owner, repo, d.issue_number, ["resolution-candidate"]);

    const issueNodeId = await getIssueNodeId(owner, repo, d.issue_number);
    const itemId = await addToProject(issueNodeId);

    if (process.env.PROJECT_CONFIDENCE_FIELD_ID) {
      await setTextField(itemId, process.env.PROJECT_CONFIDENCE_FIELD_ID, String(d.model.confidence));
    }
    if (process.env.PROJECT_REASON_FIELD_ID) {
      await setTextField(itemId, process.env.PROJECT_REASON_FIELD_ID, d.model.reason_code);
    }
    if (process.env.PROJECT_EVIDENCE_FIELD_ID) {
      await setTextField(itemId, process.env.PROJECT_EVIDENCE_FIELD_ID, d.issue_url);
    }
    if (process.env.PROJECT_LINKED_PR_FIELD_ID) {
      const linked = (d.model.hard_signals || []).map(x => x.url).join(", ");
      if (linked) {
        await setTextField(itemId, process.env.PROJECT_LINKED_PR_FIELD_ID, linked);
      }
    }
    if (process.env.PROJECT_REPO_FIELD_ID) {
      await setTextField(itemId, process.env.PROJECT_REPO_FIELD_ID, d.repository);
    }

    await addComment(
      owner,
      repo,
      d.issue_number,
      d.model.manual_review_note ||
        "This issue looks like a possible resolution candidate, but not with enough certainty for automatic closure. Added to the review queue."
    );
  }
}