# CertifEye: Privacy-Preserving AI-Assisted Security Assessment

## Presentation purpose

**Audience:** colleagues exploring practical, responsible AI adoption.

**Core message:** AI does not replace security judgment. It makes a well-scoped, privacy-preserving security assessment easier to build, repeat, explain, and improve.

**Recommended length:** 12–15 minutes, followed by a short live demonstration.

---

## Opening (about 60 seconds)

> “This is not an AI tool that connects to Active Directory and declares an environment secure. CertifEye is a security-engineered evidence pipeline. It collects the right AD CS evidence, keeps sensitive information local, produces deterministic findings, and—when appropriate—creates a structured scrubbed package that AI can help explain and prioritize. AI accelerates analysis; it does not replace security validation.”

Start with the problem: an AD CS assessment can contain sensitive identities, certificate history, access-control information, and infrastructure context. Traditional tools can surface checks, but the handoff from technical evidence to a clear remediation plan is difficult—especially for teams without deep PKI experience.

---

## The CertifEye workflow

```text
Approved AD CS environment
          ↓
Read-only PowerShell collector
          ↓
Raw and private evidence kept local
          ↓
Scrubbed, correlated evidence package
          ↓
Deterministic offline report ─────→ Optional AI-assisted review
          ↓                                  ↓
Operator validation                    Context, explanation,
and remediation                         prioritization, questions
```

Key points to say:

- Collection is PowerShell-first and read-only.
- The static analyzer provides a repeatable baseline: ESC1–ESC11 posture signals, coverage, reports, findings CSV, and graph exports.
- Tokenization preserves correlation without exposing the original identity values to an external reviewer.
- A local-only mode exists for engagements where AI sharing is not appropriate; no token map is required in that mode.
- Missing or unreadable evidence is reported as **Not Evaluated**, not silently treated as clean.

---

## Why this is an AI enablement use case

The useful AI pattern is not “ask AI to assess the domain.” It is:

1. **Collect the facts that matter** with a purpose-built, bounded collector.
2. **Apply deterministic checks** for known, testable conditions.
3. **Remove or tokenize sensitive values** before optional AI review.
4. **Give AI structured evidence and guardrails** so it can explain, connect, and prioritize—not invent facts.
5. **Keep a qualified operator in the decision loop** for validation and remediation.

This makes AI useful to more people without giving it uncontrolled access to sensitive systems.

---

## Static analysis and AI-assisted review are complementary

| Deterministic offline analysis | AI-assisted review |
| --- | --- |
| Repeatable ESC posture checks | Plain-language explanation for different audiences |
| Stable findings and coverage states | Correlation of related, scrubbed evidence |
| Regression-tested reports and graph | Environment-aware remediation sequencing |
| Conservative handling of missing evidence | Suggested validation questions and caveats |
| Works fully offline | Optional, governed enhancement |

Important boundary: issuance or configuration evidence alone is **not** a compromise claim. AI should not turn an isolated signal into a certainty. It can help an operator decide what to validate next.

---

## How the tool was developed with AI assistance

This is the practical implementation lesson:

- I began with the security outcome, existing collection logic, real operational constraints, and explicit safety boundaries.
- I separated the work into small contracts: collection schema, scrubbing, analysis rules, report layout, graphing, documentation, tests, and packaging.
- I supplied review feedback as a subject-matter expert: false-positive conditions, missing-evidence behavior, remediation accuracy, safe-data boundaries, usability, graph readability, and report wording.
- I used synthetic regression packages to make sure the tool was not tuned to one environment or one report sample.
- I required repeatable output and release gates rather than accepting a plausible-looking first result.

> “The human supplied the security model, constraints, and acceptance criteria. AI accelerated implementation and refinement inside those boundaries.”

---

## A concise live demonstration

Use synthetic data only.

1. Open CertifEye and show the interactive banner.
2. Run `doctor` to demonstrate readiness checks and no-data-change behavior.
3. Run `plan` or show `options` to explain the configured paths, stage, and safety mode.
4. Run offline analysis against a synthetic package.
5. Open the HTML report:
   - executive summary and coverage;
   - a finding with evidence, validation guidance, and remediation;
   - the attack-path graph;
   - the safe upload manifest.
6. Show the AI handoff structure or skill guidance—never a token map, salt, raw export, or client report.

Suggested transition:

> “The static report gives us a tested, repeatable baseline. The optional AI review is where we make that evidence more understandable and actionable for the person responsible for fixing it.”

---

## Guardrails worth emphasizing

- No raw identities, raw exports, token maps, salts, private manifests, or client data are needed for the demonstration.
- AI review is optional; local-only analysis remains supported.
- The collector does not modify Active Directory or perform offensive validation.
- Evidence quality is visible: confirmed, intended-policy-only, unreadable, not collected, and not evaluated are distinct states.
- Recommendations remain advisory until an authorized operator validates the environment and change impact.

---

## Close

> “The value is not simply that AI can write a report. The value is the combination of expert-designed evidence collection, privacy-preserving data handling, deterministic baseline analysis, and AI assistance that helps people understand what to validate and fix next.”

Close with the broader reuse opportunity:

- The same design can support ADmission Control, GPOsture, DNSense, and AuditAble.
- Each tool remains standalone, but they share a safe data contract and a consistent operator experience.
- The goal is to widen access to sound security assessment without lowering the bar for evidence or privacy.

---

## Q&A prompts

- *“Why not simply upload all domain data to an AI assistant?”*  Because the assessment is designed around data minimization, safe sharing, and operator choice.
- *“Can AI determine that a compromise happened?”*  No. It can summarize evidence and recommend validation; a qualified practitioner must evaluate context and corroboration.
- *“Does this require AI to run?”*  No. CertifEye produces its deterministic offline reports without AI. AI is an optional review layer.
- *“What made AI effective during development?”*  A clear subject-matter model, small verifiable tasks, fixtures, tests, and continuous human review.

