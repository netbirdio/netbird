import fs from "node:fs/promises";

const decisions = JSON.parse(await fs.readFile("decisions.json", "utf8"));
const dryRun = String(process.env.DRY_RUN).toLowerCase() === "true";

const ghHeaders = {
  Authorization: `Bearer ${process.env.GH_TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

// Use PROJECT_PAT for project board operations, fall back to GH_TOKEN
const projectHeaders = {
  Authorization: `Bearer ${process.env.PROJECT_PAT || process.env.GH_TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

async function rest(url, method = "GET", body) {
  const res = await fetch(url, {
    method,
    headers: ghHeaders,
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) throw new Error(`${res.status} ${url}: ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

async function graphql(query, variables) {
  const res = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: projectHeaders,
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

  try {
    const data = await graphql(mutation, {
      projectId: process.env.PROJECT_ID,
      contentId: issueNodeId
    });
    return data.addProjectV2ItemById.item.id;
  } catch (err) {
    console.warn(`[WARN] Could not add to project (needs PAT with project scope): ${err.message}`);
    return null;
  }
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

async function setNumberField(itemId, fieldId, value) {
  const mutation = `
    mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $value: Float!) {
      updateProjectV2ItemFieldValue(input: {
        projectId: $projectId,
        itemId: $itemId,
        fieldId: $fieldId,
        value: { number: $value }
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

async function setSingleSelectField(itemId, fieldId, optionId) {
  const mutation = `
    mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
      updateProjectV2ItemFieldValue(input: {
        projectId: $projectId,
        itemId: $itemId,
        fieldId: $fieldId,
        value: { singleSelectOptionId: $optionId }
      }) {
        projectV2Item { id }
      }
    }
  `;

  return graphql(mutation, {
    projectId: process.env.PROJECT_ID,
    itemId,
    fieldId,
    optionId
  });
}

async function addToProjectWithFields(owner, repo, d) {
  const issueNodeId = await getIssueNodeId(owner, repo, d.issue_number);
  const itemId = await addToProject(issueNodeId);

  if (itemId) {
    if (process.env.PROJECT_STATUS_FIELD_ID && process.env.PROJECT_STATUS_OPTION_NEEDS_REVIEW_ID) {
      await setSingleSelectField(itemId, process.env.PROJECT_STATUS_FIELD_ID, process.env.PROJECT_STATUS_OPTION_NEEDS_REVIEW_ID);
    }
    if (process.env.PROJECT_CONFIDENCE_FIELD_ID) {
      await setNumberField(itemId, process.env.PROJECT_CONFIDENCE_FIELD_ID, d.model.confidence);
    }
    if (process.env.PROJECT_REASON_FIELD_ID) {
      await setTextField(itemId, process.env.PROJECT_REASON_FIELD_ID, d.model.reason_code);
    }
    if (process.env.PROJECT_EVIDENCE_FIELD_ID) {
      await setTextField(itemId, process.env.PROJECT_EVIDENCE_FIELD_ID, d.issue_url);
    }
    console.log(`  → Added to project board (Status: Needs Review)`);
  }
}

for (const d of decisions) {
  const [owner, repo] = d.repository.split("/");

  if (d.final_decision === "KEEP_OPEN") {
    console.log(`#${d.issue_number} → KEEP_OPEN (confidence: ${d.model.confidence}, reason: ${d.model.reason_code})`);
    continue;
  }

  if (dryRun) {
    console.log(`[DRY RUN] #${d.issue_number} → ${d.final_decision} (confidence: ${d.model.confidence}, reason: ${d.model.reason_code})`);
    // In dry-run: populate project board but don't touch issues
    if (d.final_decision === "MANUAL_REVIEW" || d.final_decision === "AUTO_CLOSE") {
      await addToProjectWithFields(owner, repo, d);
    }
    continue;
  }

  if (d.final_decision === "AUTO_CLOSE") {
    await addLabel(owner, repo, d.issue_number, ["auto-closed-resolved"]);
    await addComment(owner, repo, d.issue_number, d.model.close_comment);
    await closeIssue(owner, repo, d.issue_number);
    await addToProjectWithFields(owner, repo, d);
  }

  if (d.final_decision === "MANUAL_REVIEW") {
    await addLabel(owner, repo, d.issue_number, ["resolution-candidate"]);
    await addToProjectWithFields(owner, repo, d);
    await addComment(
      owner,
      repo,
      d.issue_number,
      d.model.manual_review_note ||
        "This issue looks like a possible resolution candidate, but not with enough certainty for automatic closure. Added to the review queue."
    );
  }
}