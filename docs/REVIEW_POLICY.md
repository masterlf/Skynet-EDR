# Review Policy
Skynet-EDR uses pull requests for all repository changes.
## Current solo-maintainer mode
Until additional trusted reviewers are available, branch protection allows zero required approvals. This is a temporary project-bootstrap setting, not the target security posture.
Current requirement:
- branch required for every change
- pull request required for traceability
- green CI/security checks before merge
- squash merge preferred
- reviewer summary in PR body or comments when Hermes performs the change
## Target mode
When another trusted reviewer or bot identity is available, restore:
- at least one required approving review
- stale-review dismissal
- conversation resolution
- code owner review for sensitive paths if maintainers are available
## Rationale
GitHub does not allow the same account to approve its own pull request. For now, requiring approvals would block automation without adding real independent review. The compensating controls are small PRs, green automated checks, explicit PR summaries, and post-merge verification.
