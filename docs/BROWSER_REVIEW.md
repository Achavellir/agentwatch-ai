# Browser release review

Reviewed November 11, 2026 for local release 0.3.0. Scope: a single developer on a trusted Mac, reviewing saved activity using policy rules. No public deployment, spending or publication was performed for this change.

ECC guidance applied: Python testing, security review, build checks and browser QA. This is a project review, not an independent security certification.

## Verified results

- 60 unit and integration tests passed, including 14 new browser-server and launcher tests. Existing CLI, input validation, report permissions and evaluation tests remain passing.
- UI package statement coverage: 94% overall (95% for the server module). Uncovered paths include socket/thread failure handling, a timeout handler, one deeply nested envelope handler and the module-only launcher. This is not a claim of exhaustive security coverage.
- The frozen synthetic evaluation passed with unchanged input fixture hashes: all four designed scenarios retained their expected signals; 5/40 normal sessions requested review.
- The wheel built successfully and installed into a fresh Python environment using the existing dependency constraints. Installed CLI rules-only and ML checks passed, and installed browser assets plus a real loopback policy-review request passed outside the source tree.
- No new application runtime dependencies were added. Coverage, Playwright and axe-core were development-only checks. The November 7 dependency advisory result remains a dated check; it was not rerun or relabeled as a new audit.
- End-to-end browser checks passed for the sample, generated file inputs, HTML/JSON downloads, sample download, filtering, evidence expansion, stale-results clearing, invalid domains/JSON/UTF-8, oversized and empty files, untrusted markup, pagination, clearing results, network failure and keyboard activation.
- Desktop, tablet and phone layouts were inspected at 1440, 768 and 375 pixels. No horizontal overflow was found. Automated axe checks reported no violations against the selected WCAG A/AA tags at all three widths. This is not a full accessibility conformance claim; no screen-reader audit was performed.
- ECC browser checks observed successful local assets/review requests and no console errors. The automated test observed no uncaught JavaScript errors or external requests. Visual regression against a prior screenshot baseline is inconclusive because this interface has no previous baseline. Field Core Web Vitals and INP have not been measured.

## Confirmed issues resolved

- Added a narrow shared byte-input parser rather than maintaining a separate browser event schema, so CLI and browser review results match.
- Invalidated previous results and download links when review settings change or a new review fails, avoiding downloads that appear to reflect different settings.
- Rejected non-ASCII or incorrect request tokens without allowing an uncaught token-comparison type error.
- Prevented markup execution in the new results view by inserting uploaded identifiers as text. Existing HTML exports remain escaped.
- Kept the service fixed to loopback, checked Host and Origin, required a per-process token, rejected cross-site requests and unsupported request encodings, and bounded uploads/concurrency.

The ECC upload-file connector rejected both the repository and chat workspace paths. No real file was accessed through that connector. Browser tests instead supplied generated synthetic File objects through the file input. Backend integration tests separately read the repository's committed demo fixture and compared its complete results with the CLI checker.

## Remaining boundaries and proposed work

- Ready for local pilot use; not ready for a public, multi-user service. Do not tunnel or reverse-proxy this listener.
- Policy rules only in the browser. Optional ML remains available through the CLI and needs a representative reviewed baseline.
- Trusted telemetry, real-agent adapters and independent evaluation remain missing. Test passing does not establish attack detection accuracy or measured reviewer time savings.
- Memory processing does not prevent browser extensions, other local processes, OS swap or downloaded reports from exposing metadata. Downloads use browser-managed permissions rather than the CLI's private output directory.
- Next validation priority: integrate one authorized agent workflow, have a reviewer label separate real traces, and compare rules-only versus ML versus combined review workload before claiming additional ML value.

Verdict: ready for a bounded local developer pilot within these limits. Public production deployment is outside the completed scope.
