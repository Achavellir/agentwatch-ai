I’ve finished the latest local version of AgentWatch AI, a security engineering portfolio project I’m building with AI coding assistance.

It reviews AI-agent tool activity using local machine learning and explicit policy rules, then produces an offline report with event-level evidence.

This update focused on making the results more trustworthy:
• Missing network destinations now trigger review instead of silently passing.
• The trace writer and reader use the same input validation.
• Evaluation checks fixture hashes, explicit labels, and copied sessions across data splits.
• Regression checks fail when expected detections disappear or normal alerts exceed the recorded baseline.

All 38 automated tests pass locally.

On the synthetic dataset, all four designed scenarios were flagged, alongside 5 of 40 normal sessions. One scenario is benign high-volume traffic, so “flagged” does not mean “attack detected.”

A useful finding: the model missed the lookalike-domain scenario, while the exact-hostname rule caught it. Keeping those signals independent matters.

This is an offline prototype, not a preventive control or a production-validated security product. Independent real-agent evaluation is still ahead.

No paid model API or cloud hosting was needed for this update.

Code: https://github.com/Achavellir/agentwatch-ai

#AISecurity #DetectionEngineering #Python #Cybersecurity
