# Upstream NetBird Regression: User Role Loses Visibility of Policy-Reachable Peers

**Reported:** 2026-05-04 by Michael Uray ("Georg sees only his own peer in the dashboard, not the Gegenstellen — that's not what we want, before each user saw their own peers PLUS their counterparts").
**Affects:** Anyone running NetBird upstream commit `db44848e2` or later (merged 2026-04-28 in PR #6006 "[management] Drop netmap calculation on peer read").
**Severity:** UX-breaking for any account using the `user` role -- those users see ONLY their own peers in the web dashboard, no longer the routing peers / counterparts their access policies allow them to reach.

## What changed upstream

PR #6006 simplified `GetPeers` and `GetPeer` in `management/server/peer.go`. The pre-PR code had two branches for a non-admin user:

  1. Collect their OWN peers (filter by `peer.UserID == user.Id`).
  2. For each own peer, expand with peers reachable via account ACL
     (`account.GetPeerConnectionResources(...)`), and merge the results.
     Implemented in helper `getUserAccessiblePeers`.

PR #6006 deleted step 2 + the helper. New code:

```go
return am.Store.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
```

Same regression in `GetPeer` (single-peer detail) -- the helper
`checkIfUserOwnsPeer` was removed; it now returns `Internal` error
for any peer the user does not directly own.

The PR title indicates the motivation: avoiding a netmap calculation
on every peer-list read because it was expensive on large accounts.
Trade-off was made WITHOUT replacing the visibility logic with
something cheaper, so the feature was simply lost.

## Symptom on our deployment

`georg.stoisser-gigacher` has 1 own peer (`ctb50-d`) and 17 auto_groups,
including 16 `*-access` groups that source policies into `*-Rx` /
`*-NW` destination groups (e.g. `Lunz.am.See.FWR-access` ->
`Lunz.am.See.FWR.Rx`). With the regressed code, the dashboard
shows only `ctb50-d`. Operationally useless -- the user wants to
see the routing peers their device can reach.

Switching the role to `auditor` works around the regression but
gives the user read access to ALL peers (including peers belonging
to other users' personal devices), which is too much.

## Fix on this branch

Branch: `fix/user-peer-visibility-restore` (NetBird repo)
Base: `730f9840c` (Phase-3.7i complete set)

Restored both helpers:

- `getUserAccessiblePeers(ctx, accountID, ownPeers)` -- expands the
  own-peer list with ACL-reachable peers via
  `account.GetPeerConnectionResources` (which is still in the
  codebase, just no longer called from peer.go).
- `checkIfUserOwnsPeer(ctx, accountID, userID, peer)` -- per-peer
  check: any of the user's own peers reaches `peer` via ACL?

Code paths in `GetPeers` and `GetPeer` re-wired to call them. Both
functions match the upstream pre-#6006 behaviour byte-for-byte
modulo the surrounding code that was already refactored
(name/IP filter handling stays in the caller; signature uses
`ownPeers` directly to avoid a redundant `GetAccountPeers` call).

## Verification

After deploying the rebuilt mgmt image:

  curl -sk -H "Authorization: Token <Georg's token>" \
       https://netbird.uplink.plant-control.net:44106/api/peers \
    | jq '. | length'

Expected: more than 1 (own peer + every routing peer / Gegenstelle his
access policies allow him to reach), but LESS than 58 (he should NOT
see other users' personal peers).

## Performance note

PR #6006 was correct that `GetPeerConnectionResources` is not free.
Mitigations we keep in mind:

  - It is only called for users who hit the non-admin branch (typically
    a small subset of total /api/peers requests -- admin tools call
    with admin tokens).
  - Each invocation walks `len(ownPeers)` policies. Most users have
    1-3 own peers, so cost stays low.
  - `requestBuffer.GetAccountWithBackpressure` is the same call
    upstream used. We add no new pressure beyond what the pre-#6006
    code already had.
  - For large accounts where this still hurts, a follow-up could cache
    the user-id -> reachable-peer-id set per account snapshot, with
    invalidation on policy / group / peer change.

## Upstream relationship

Worth filing this as an upstream issue / PR after we ship our fix
internally. Either the visibility loss was deliberate (then it's a
deliberate UX downgrade that should be documented) or it was an
oversight (then the helpers should come back, perhaps with a cache).
