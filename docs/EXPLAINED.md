# How to explain AgentWatch AI

Imagine a research assistant normally reads a few documents and makes small requests to approved websites. One run suddenly makes 100 requests and sends much more data. AgentWatch marks that run as unusual. If another run sends sensitive data to an unapproved host, a separate rule points to the exact logged event even if the model misses it.

## The pipeline

1. Your agent application records tool activity as metadata.
2. You provide a reviewed baseline of normal sessions.
3. Isolation Forest learns which feature combinations are uncommon.
4. New sessions are scored and checked against explicit rules.
5. A human reviews the HTML report and source-event references.

The model is genuine machine learning, trained and run locally. It is not an LLM chatbot. This avoids sending logs to an external model and makes results repeatable, but it cannot reason about the semantic meaning of a prompt or determine an attacker's intent.

## Recruiter explanation

“I developed an AI-assisted portfolio prototype called AgentWatch AI to explore monitoring tool-using AI agents. It combines an Isolation Forest anomaly model with explicit destination and approval rules. Findings include event references, and the tool produces an offline analyst report. I tested it on clearly labeled synthetic data and documented false alerts and the limits of that evaluation. The next step is validation with authorized real agent telemetry.”

Before saying this in an interview, run the demo yourself and be able to explain why unusually high traffic can be legitimate. The important tradeoff is signal versus review workload, not claiming perfect detection.
