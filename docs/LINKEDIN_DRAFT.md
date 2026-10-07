I’ve been exploring a practical security question: how can we spot risky behavior when an AI agent starts using tools?

With AI coding assistance, I built AgentWatch AI, a local prototype that combines:
• Isolation Forest anomaly detection for unusual tool-use patterns
• Explicit rules for unapproved destinations and actions without recorded approval
• An offline analyst report with event-level evidence

One useful result: the model did not flag the lookalike-domain scenario, but the exact-hostname rule did. That is why I kept the two signals independent.

The synthetic evaluation used 200 baseline sessions and 44 separate test sessions. All four designed scenarios were flagged for review, along with 5 of 40 normal sessions. That 12.5% normal-session alert rate is a reminder that threshold calibration and representative data matter. These results are not production detection accuracy.

The project includes 14 automated tests, reproducible fixtures, an integration helper and documented limitations. It uses local machine learning, not an LLM API, and does not execute or block any agent actions.

Next step: validation with authorized real agent telemetry.

Repository: https://github.com/Achavellir/agentwatch-ai

#AISecurity #DetectionEngineering #MachineLearning #Cybersecurity
