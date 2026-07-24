# CertifEye: A Privacy-Preserving AI-Assisted AD CS Assessment

## How to use this guide

This is a recovery script, not a script you must read word-for-word. Each slide has a natural passage, one short line to use if you lose your place, and a transition to the next slide. The deck is designed for a 12–15 minute talk followed by a short demonstration.

Use synthetic data only. Do not show client exports, tokens, token maps, salts, private manifests, screenshots, or report output from a real environment.

---

## Slide 1 — CertifEye

### Say this

> “I wanted to share a practical use case for AI in security work. CertifEye is an Active Directory Certificate Services assessment tool. It collects the evidence we need to review AD CS safely, keeps sensitive details local, and produces an offline report even if AI is never used.”

> “This is not an AI tool that connects to Active Directory and declares an environment secure. CertifEye is a security-engineered evidence pipeline. It collects the right AD CS evidence, keeps sensitive information local, produces deterministic findings, and—when appropriate—creates a structured scrubbed package that AI can help explain and prioritize. AI accelerates analysis; it does not replace security validation.”

### If you lose your place

> “The important point is that the security assessment comes first. AI is an optional layer on top of evidence we already collected and reviewed safely.”

### Transition

> “The reason that separation matters becomes clear when we look at the kind of data an AD CS assessment produces.”

---

## Slide 2 — Why the assessment is difficult to hand off

### Say this

> “Finding a risky certificate template or an overly broad permission is useful, but it is only the start. Someone still has to understand why it matters, determine who owns it, validate whether it is intentional, and decide how to remediate it without breaking a business process.”

> “The evidence can also be sensitive. Certificate history, access-control details, identity information, and infrastructure context are not things we should casually place into a broadly shared review process.”

> “Finally, not every administrator who needs to participate in remediation is a PKI specialist. The output needs to be detailed enough for a security engineer, but understandable enough that the right people can take action.”

### If you lose your place

> “The challenge is not just detection. It is turning sensitive technical evidence into something the right people can safely understand and act on.”

### Transition

> “CertifEye handles that by separating collection, private evidence, reporting, and optional AI review.”

---

## Slide 3 — How CertifEye handles assessment data

### Say this

> “The collector runs locally and read-only. It gathers AD CS evidence and stores the raw and private material locally. It then scrubs and correlates the information so the static analyzer can build a report, findings list, and attack-path graph.”

> “That offline report is already useful on its own. If a client or engagement allows AI-assisted review, we can use the scrubbed package instead of supplying raw environment data. If it does not, the same assessment can remain entirely local.”

> “The point is not to make every assessment use AI. The point is to have a safe option when AI can add value.”

### If you lose your place

> “Local collection and offline analysis are the default. AI review is optional and uses the scrubbed package.”

### Transition

> “That only works if we are clear about what stays on the local system.”

---

## Slide 4 — What stays local

### Say this

> “The sensitive pieces stay local: raw exports, salts, token maps, private manifests, and detailed evidence. Those are the parts that make it possible to map an assessment back to the real environment, so they are not included in the safe review package.”

> “The optional review package contains scrubbed tokens and relationships, schema and coverage information, and the deterministic evidence needed to explain the report. It is useful for analysis while avoiding raw identities and private mappings.”

> “The collector is also read-only. It does not change Active Directory, certificate templates, CAs, or the PKI environment.”

### If you lose your place

> “Raw data and the ability to reverse the tokens remain local. The review package is intentionally limited to scrubbed evidence.”

### Transition

> “With that boundary in place, the static report and AI review can each do the job they are best at.”

---

## Slide 5 — Deterministic analysis vs. AI assistance

### Say this

> “The deterministic offline report is the baseline. It runs the same rules against the same data, provides coverage states, produces a graph, and gives us a stable report we can test and compare over time.”

> “AI is useful after that baseline exists. It can explain a finding in terms that fit the audience, point out related evidence, help organize remediation work, and suggest what should be validated next.”

> “What it should not do is turn a single row or configuration signal into a claim that abuse happened. A finding is evidence to investigate. It still needs a qualified person to validate the surrounding context.”

### If you lose your place

> “The static report tells us what the evidence says. AI can help us work through what to look at next.”

### Transition

> “This same separation also shaped how I used AI while building the tool.”

---

## Slide 6 — How AI helped build CertifEye

### Say this

> “AI was helpful because I did not ask it to make the security decisions. I started with the security outcome: what evidence do we need, what should never be collected or shared, and what should count as missing evidence instead of a clean result?”

> “I then broke the work into pieces we could review and test separately: collection, scrubbing, analysis rules, reports, graphs, documentation, and synthetic fixtures. That made it possible to catch false positives, improve the report language, and refine the operator experience without losing the original security intent.”

> “I set the security rules, review criteria, and guardrails. AI helped turn that direction into code, tests, reports, and documentation. The quality came from the back-and-forth review, not from accepting a first draft.”

### If you lose your place

> “AI accelerated the implementation. The security requirements and the final review stayed with me.”

### Transition

> “Let me show the workflow in a safe way using synthetic data.”

---

## Slide 7 — Demo

### Say this

> “For the demo, I will use synthetic data only. First I will show the readiness checks and the collection plan, so it is clear what the tool expects before it touches assessment data.”

> “Then I will run the offline analysis and open the report. I will show one finding, the evidence behind it, the validation guidance, the remediation guidance, and the graph. Finally, I will show the structure of the optional AI handoff and what is deliberately excluded from it.”

### Presenter command cues

Run these as needed; they are not intended to be read from the slide:

```powershell
.\Invoke-ADCSAuditPipeline.ps1
doctor
options
plan
analyze
```

### If you lose your place

> “I am showing the same path an operator would use: check readiness, review the plan, analyze evidence, then decide whether a scrubbed AI review is useful.”

### Transition

> “The goal is not a one-off AD CS report. It is a repeatable way to handle security assessment evidence.”

---

## Slide 8 — Where this can go next

### Say this

> “The larger idea is simple. Security expertise defines what evidence matters. Sensitive data stays local. The tool produces clear reports, and AI can help when it is useful and approved.”

> “CertifEye is the first mature use case because AD CS assessments have a clear evidence model and real remediation value. Going forward, the same approach can support the broader work already underway: ADmission Control for Active Directory posture, GPOsture, DNSense, and AuditAble.”

> “The goal is not to hand security decisions to AI. The goal is to make expert security work easier to repeat, easier to explain, and easier for the right people to act on.”

### If you lose your place

> “CertifEye is the first example of a larger approach: strong evidence collection, safe handling of sensitive data, and optional AI help where it genuinely adds value.”

---

## Likely questions

### “Why not upload the whole assessment to an AI assistant?”

> “Because the goal is to minimize what leaves the local environment. CertifEye is designed so the raw exports, token maps, salts, and private evidence stay local. Optional AI review uses a scrubbed package with the relationships needed for analysis.”

### “Can AI tell us that a compromise occurred?”

> “No. The tool and AI can identify evidence that deserves investigation. A qualified security practitioner still has to validate context and corroborate any conclusion.”

### “Does the tool require AI?”

> “No. The collector and static report work fully offline. AI is an optional way to improve explanation, prioritization, and validation planning.”

### “What made AI useful during development?”

> “It was useful because the work had clear security requirements, test cases, and review gates. I supplied the security direction and reviewed the output; AI helped accelerate the implementation work.”
