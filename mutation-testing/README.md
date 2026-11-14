# Combined behavior mutation experiment

This branch deliberately introduces 68 behavioral regressions for an E2E test-effectiveness experiment. It is not a product fix and must not be merged or deployed.

The mutations do not alter PAT, token, credential or signature handling. Valid authentication is still required by test fixtures. The existing test expectations remain unchanged.

`behavior-manifest.json` maps the applied BEH identifiers to source locations. The base commit is `c4a6e4c339c03ba6878610a04db9c2b3c583b793`.

Run the control-plane E2E suite against the paired core and cloud branch commits. A combined run measures aggregate detection: one early assertion or fixture failure can hide later mutations. Do not interpret the number of failed tests as the number of independently detected mutations. Use isolated follow-up runs to attribute individual survivors and kills.

BEH-055 clears short job failure reasons after normal formatting, preserving the BEH-052 boundary-truncation mutation in the same block.
