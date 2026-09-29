# AccessLens — Architecture & Implementation Blueprint

## 1. Purpose

**AccessLens** is a security/GRC prototype that improves access reviews by combining:

- What access an employee has
- What activity they actually performed
- Whether access remains active after deprovisioning
- Evidence a reviewer/auditor can understand

### Core question

> Instead of only asking **“What access does this employee have?”**, AccessLens asks **“What access do they have, what did they actually use, and is there any access remaining after they left?”**

The system is human-controlled. It does **not** automatically revoke access.

---

## 2. Problem

Traditional access reviews can show permissions without enough runtime context.

Example:

```text
Bob
AWS AdministratorAccess
        ↓
Manager sees permission
        ↓
Approve / Reject
```

AccessLens adds activity evidence:

```text
Bob
AWS AdministratorAccess
        ↓
Actual activity analyzed
        ↓
Only a small subset observed
        ↓
High privilege / low observed utilization
        ↓
Evidence + safe review recommendation
```

A second problem is **ghost access**:

```text
HR
Employee terminated
        ↓
IdP
Account disabled
        ↓
Downstream token still produces activity
        ↓
AccessLens
GHOST ACCESS DETECTED
```

---

## 3. Product Scope

### Feature 1 — Normal Access Review

Display:

- Employee
- Identity status
- Roles
- Permissions
- Risk
- Review status

### Feature 2 — Telemetry-Informed Access Review

Correlate:

- Granted permissions
- Observed activity
- Last activity
- High-risk permissions
- Lookback window

Produce findings such as:

**HIGH PRIVILEGE / LOW OBSERVED USAGE**

This is a review recommendation, not automatic removal.

### Feature 3 — Break-Glass Protection

Some permissions may intentionally be unused for long periods.

Examples:

- Disaster recovery
- Emergency response
- Backup recovery
- Periodic operational processes

Therefore:

> **Unused does not automatically mean unnecessary.**

Protected/emergency roles must not receive unsafe pruning recommendations.

### Feature 4 — Ghost Access Detection

Compare:

- HR termination time
- IdP deactivation time
- Downstream activity

Detect activity occurring after deactivation and show the supporting timeline.

### Feature 5 — AI Trial Lawyer

AI receives structured findings and evidence.

AI can:

- Explain findings in plain English
- Summarize technical evidence
- Generate reviewer questions
- Challenge weak or missing evidence
- Draft auditor-facing explanations

AI must **not** make the underlying security decision.

**Python = security truth**  
**AI = explanation / investigation / challenge**  
**Human = final decision**

### Feature 6 — Evidence / Auditor Dossier

Generate:

- User
- Finding
- Evidence
- Timeline
- Rules triggered
- Recommendation
- AI explanation
- Review status

---

## 4. High-Level Architecture

```text
                         ACCESSLENS
                             │
              ┌──────────────┴──────────────┐
              │                             │
       INPUT DATA SOURCES              CONFIGURATION
              │                             │
       ┌──────┼────────┐              Lookback window
       │      │        │              Risk thresholds
       ▼      ▼        ▼              Protected roles
      HR     IdP    Entitlements
                       │
                       ▼
                Activity Logs
                       │
                       ▼
              ┌─────────────────┐
              │ DATA NORMALIZER │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ SECURITY ENGINE │
              │   Deterministic │
              └────────┬────────┘
                       │
          ┌────────────┼─────────────┐
          ▼            ▼             ▼
      Privilege     Break-Glass   Ghost Access
      Analysis      Protection    Detection
          │            │             │
          └────────────┼─────────────┘
                       ▼
                 FINDINGS + EVIDENCE
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        Review UI          AI TRIAL LAWYER
             │                   │
             └─────────┬─────────┘
                       ▼
              HUMAN REVIEW / DECISION
                       │
                       ▼
               AUDITOR DOSSIER
```

---

## 5. Data Sources / Integrations

### HR / Workforce Identity

Purpose:

- Employee identity
- Employment status
- Termination timestamp

Conceptual source: **Workday-style HR data**

Prototype:

`users_hr.json`

### Identity Provider

Purpose:

- Account status
- Groups
- Roles
- Deactivation timestamp

Conceptual source: **Okta**

Prototype:

`idp_state.json`

### Cloud / Application Entitlements

Purpose:

- Granted permissions
- Roles
- Access level

Examples:

- AWS IAM
- GitHub roles
- Application roles

Prototype:

`entitlements.json`

### Activity / Telemetry

Purpose:

- What the identity actually did
- Timestamp
- Action
- Resource
- Source

Examples:

- AWS CloudTrail-style events
- GitHub audit activity
- Zscaler/proxy events

Prototype:

`activity_logs.json`

**Important:** For this prototype, use realistic structured data first. Do not spend the two-day window building dozens of live connectors.

---

## 6. Normalized Event Model

Different systems produce different log formats. Normalize them into one common model.

```json
{
  "event_id": "evt_001",
  "timestamp": "2026-09-29T10:30:00Z",
  "actor_id": "carol",
  "source": "github",
  "action": "repo.clone",
  "resource": "payment-gateway",
  "source_ip": "10.10.10.20",
  "credential_id": "ghp_demo"
}
```

Core fields:

- `event_id`
- `timestamp`
- `actor_id`
- `source`
- `action`
- `resource`
- `source_ip`
- `credential_id` where available

---

## 7. Core Data Models

### User

```text
id
name
email
department
employment_status
```

### Identity

```text
user_id
provider
account_id
status
deactivated_at
```

### Entitlement

```text
user_id
source
role
permissions
risk_level
protected_role
```

### ActivityEvent

```text
event_id
actor_id
timestamp
source
action
resource
source_ip
credential_id
```

### Finding

```text
id
user_id
type
severity
status
summary
evidence
recommendation
created_at
```

### Evidence

```text
finding_id
source
timestamp
event
description
```

---

## 8. Deterministic Security Engine

The security engine is the core technical component and does not depend on an LLM.

### Rule A — Privilege Utilization

```text
granted capabilities
        ↓
observed capabilities
        ↓
compare
        ↓
observed utilization
```

Conceptually:

```text
Privilege Utilization =
Observed relevant actions / Granted relevant capabilities
```

This is **observed utilization**, not proof that unused access is unnecessary.

### Rule B — Low-Usage Privileged Access

```text
IF
  user has high-risk privilege
AND
  observed usage is very low
AND
  role is not protected
THEN
  create REVIEW_REQUIRED finding
```

### Rule C — Break-Glass Protection

```text
IF
  entitlement is classified as emergency / DR
THEN
  mark PROTECTED
  do not generate automatic removal recommendation
```

### Rule D — Ghost Access

```text
IF
  identity is deactivated
AND
  downstream activity occurs after deactivation
THEN
  create GHOST_ACCESS finding
```

Every ghost-access finding should contain the exact timeline and supporting evidence.

---

## 9. AI Layer

The AI receives structured findings rather than making raw security decisions.

Example input:

```text
User: Bob
Role: AWS AdministratorAccess
Observed actions:
- s3:GetObject
- ec2:DescribeInstances

Finding:
High privilege / low observed utilization

Evidence:
90-day activity window
```

Possible explanation:

> Bob’s observed activity during the selected period was limited to reading S3 objects and viewing EC2 information. No observed administrative modification actions were found. The evidence supports a manual review of whether the current administrator-level entitlement is broader than required.

### AI must NOT

- Automatically revoke permissions
- Modify IAM policies
- Disable accounts
- Invent evidence
- Claim unsupported actions occurred
- Treat lack of observed activity as proof that access is unnecessary

### AI SHOULD

- Explain evidence
- Identify uncertainty
- Ask adversarial review questions
- Highlight missing evidence
- Summarize findings
- Draft the evidence dossier

---

## 10. Trial Lawyer Review Mode

The AI should challenge the evidence:

```text
Why do we believe this permission is unnecessary?

What evidence supports that conclusion?

Could this be a break-glass or rarely used operational permission?

What period of activity was examined?

Could relevant logs be missing?

Is the identity mapping reliable?

What evidence would change this conclusion?
```

The AI is an **investigator/counsel layer**, not an autonomous security administrator.

---

## 11. User Interface

### Tab 1 — Smart Access Review

Show:

- Employee
- Role
- Risk
- Usage
- Last activity
- Finding
- Evidence
- Recommendation

Example:

```text
BOB
AWS AdministratorAccess

Privilege: HIGH
Observed utilization: LOW

⚠ Review required

[View Evidence]
[Generate Downscoped Policy]
```

### Tab 2 — Deprovisioning Forensics

Example:

```text
CAROL

Terminated:
Sep 25, 10:00

IdP disabled:
Sep 25, 10:04

GitHub activity:
Sep 26, 00:14

🚨 GHOST ACCESS DETECTED
```

### Tab 3 — Courtroom / Auditor Dossier

Show:

- Finding
- Timeline
- Evidence
- Security rule
- AI explanation
- Open questions
- Reviewer decision

---

## 12. Technology Stack

### Backend

**Python**

- Data loading
- Normalization
- Security rules
- Finding generation
- Evidence processing

### API

**FastAPI**

- Analysis endpoints
- Findings
- Trigger analysis
- Backend/frontend communication

### Database

**PostgreSQL** if practical.

**SQLite** is acceptable for a fast local prototype if database setup becomes a time sink.

### Frontend

**Next.js + TypeScript + Tailwind**

- Dashboard
- Access review
- Ghost-access investigation
- Evidence display
- AI explanation

### AI

Use one strong available LLM API.

Responsibilities:

- Explanation
- Evidence summarization
- Adversarial questions
- Auditor dossier drafting

### Testing

- pytest
- API tests
- Frontend checks
- End-to-end tests where useful

---

## 13. Tools / Integrations

### Development Tools

- VS Code / Antigravity / coding agent
- Git
- GitHub
- Python
- Node.js
- npm/pnpm

### Application Frameworks

- FastAPI
- Next.js
- TypeScript
- Tailwind CSS

### Data

- JSON fixtures
- SQLite or PostgreSQL

### AI

- One selected LLM API

### Security Data Models

Model these systems:

- HR / Workday-style events
- Okta-style identity events
- AWS IAM permissions
- AWS CloudTrail-style activity
- GitHub activity
- Zscaler/proxy-style activity

These are **conceptual integrations for the prototype**. We do not need live integrations for every source.

---

## 14. Repository Structure

```text
accesslens/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── engine/
│   │   │   ├── utilization.py
│   │   │   ├── ghost_access.py
│   │   │   ├── safety.py
│   │   │   └── analyzer.py
│   │   ├── ingestion/
│   │   ├── ai/
│   │   └── main.py
│   │
│   └── tests/
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/
│   └── types/
│
├── data/
│   ├── users_hr.json
│   ├── idp_state.json
│   ├── entitlements.json
│   └── activity_logs.json
│
├── reports/
├── docs/
│   └── architecture.md
├── README.md
└── .env.example
```

---

## 15. Demo Personas

### Bob — Privilege Review

```text
Role:
AWS AdministratorAccess

Observed:
Mostly read/describe operations

Expected:
HIGH_PRIVILEGE_LOW_USAGE

Action:
Manual review / safe downscoping suggestion
```

### Alice — Break-Glass

```text
Role:
Emergency / DR role

Observed:
No recent activity

Expected:
PROTECTED_BREAK_GLASS

Action:
Do not recommend automatic pruning
```

### Carol — Ghost Access

```text
Employment:
Terminated

IdP:
Disabled

Downstream:
GitHub credential activity after deactivation

Expected:
GHOST_ACCESS

Action:
Investigate / human-approved remediation
```

---

## 16. Testing Matrix

| Scenario | Expected Result |
|---|---|
| Normal user + normal activity | No finding |
| High privilege + low observed usage | Review required |
| Break-glass + no activity | Protected |
| Employee disabled + no later activity | No ghost access |
| Employee disabled + later activity | Ghost access |
| Missing activity logs | Insufficient evidence |
| Invalid timestamp | Validation error / insufficient evidence |
| Duplicate identity | Investigation required |
| Rarely used privileged permission | Review, not automatic removal |

---

## 17. Implementation Order

### Phase 1 — Foundation

1. Create repository
2. Create backend/frontend
3. Environment configuration
4. Data schemas
5. Realistic fixture data

### Phase 2 — Security Engine

1. Normalize events
2. Implement utilization analysis
3. Implement break-glass protection
4. Implement ghost-access detection
5. Produce structured findings
6. Write tests

### Phase 3 — API + UI

1. Analysis API
2. Dashboard
3. Access-review view
4. Ghost-access investigation
5. Evidence view

### Phase 4 — AI

1. Send structured findings to LLM
2. Generate explanation
3. Generate adversarial questions
4. Generate auditor dossier

### Phase 5 — Verification

1. Run tests
2. Test failure cases
3. Validate demo data
4. Review AI boundaries
5. Run end-to-end demo

### Phase 6 — Presentation

3-minute story:

```text
Existing access review
        ↓
What it sees
        ↓
Run AccessLens
        ↓
Runtime evidence
        ↓
Finding
        ↓
AI investigation
        ↓
Human decision
        ↓
Evidence / dossier
```

---

## 18. Engineering Principles

1. **Evidence before conclusions.**
2. **Deterministic security logic before AI.**
3. **Human approval before security-changing actions.**
4. **Unknown ≠ safe.**
5. **Unused ≠ unnecessary.**
6. **Every finding must be explainable.**
7. **Build the real workflow, not a fake AI demo.**

---

## 19. Final Product Definition

> **AccessLens is a telemetry-informed access review and deprovisioning investigation system that connects identity state, granted privileges, and observed activity to produce explainable security findings and audit-ready evidence.**

The prototype demonstrates:

```text
Security data
      +
Deterministic analysis
      +
Runtime evidence
      +
AI investigation
      +
Human decision
      =
Defensible access review
```

This document is the implementation source of truth for the project.
