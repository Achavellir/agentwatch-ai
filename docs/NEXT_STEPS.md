# Local pilot roadmap — November 23, 2026

## Verified now

- Version 0.3 offers local browser policy review and CLI policy/optional ML review.
- Real-site demo records one public Python.org request and automatically creates
  two reports under different policies. Live run returned HTTP 200 and recorded
  125 outgoing HTTP bytes. This is a scripted request, not an autonomous agent.
- 66 local tests pass; frozen synthetic evaluation passes unchanged (5/40 normal
  sessions flagged). This is regression evidence, not independent accuracy.

## Remaining release gates

1. **Actual agent integration (estimated 1–2 focused working days).** Instrument
   one developer-owned agent's HTTP and file tools using trusted approval and
   sensitivity labels. Verify complete traces and failure handling. Run without
   manual JSON preparation. No paid model calls without separate authorization.
2. **Independent validation (estimated 1–2 weeks, data dependent).** Obtain
   authorized representative traces, label expected outcomes independently,
   freeze a separate evaluation set before tuning, and report false alerts,
   missed issues and missing events. Existing synthetic fixtures remain regression
   tests. Do not convert anomaly margins into attack probabilities.
3. **Pilot release (estimated 2–3 working days after feedback).** Resolve important
   findings; refresh dependency advisories; test installation and the end-to-end
   workflow on supported systems; document recovery and retention; recruit pilot
   users and record their feedback.

These are effort estimates, not scheduled commitments or an unattended promise
of work. A local pilot could take roughly 2–3 weeks if suitable traces and reviewer
feedback are available promptly. A production completion date cannot responsibly
be set until those gates pass. Public multiuser hosting, live blocking and broad
framework support are outside this first local release.

## Confirmed limits versus proposed improvements

Confirmed: current demos are scripted/synthetic; automatic general agent capture
is absent; approval labels and log completeness depend on the producer; the last
documented dependency advisory audit is November 7. The demo wrapper creates
private output files, while the general TraceWriter still relies on the caller's
filesystem permissions and single-process use.

Proposed priorities: actual tool-wrapper integration; independently reviewed
evaluation; harden and document telemetry integrity/private storage for pilots.
