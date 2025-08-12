---
name: Bug/Issue report
about: Create a report to help us improve
title: ''
labels: ['triage-needed']
assignees: ''

---

**Describe the problem**

A clear and concise description of what the problem is.

**To Reproduce**

Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**

A clear and concise description of what you expected to happen.

**Are you using NetBird Cloud?**

Please specify whether you use NetBird Cloud or self-host NetBird's control plane.

**NetBird version**

`netbird version`

**Is any other VPN software installed?**

If yes, which one?

**Debug output**

To help us resolve the problem, please attach the following anonymized status output

  netbird status -dA

Create and upload a debug bundle, and share the returned file key:

  netbird debug for 1m -AS -U

*Uploaded files are automatically deleted after 30 days.*


Alternatively, create the file only and attach it here manually:

  netbird debug for 1m -AS


**Screenshots**

If applicable, add screenshots to help explain your problem.

**Additional context**

Add any other context about the problem here.

**Have you tried these troubleshooting steps?**
- [ ] Reviewed [client troubleshooting](https://docs.netbird.io/how-to/troubleshooting-client) (if applicable)
- [ ] Checked for newer NetBird versions
- [ ] Searched for similar issues on GitHub (including closed ones)
- [ ] Restarted the NetBird client
- [ ] Disabled other VPN software
- [ ] Checked firewall settings

