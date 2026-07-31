CYBERWOLF SIEM

UI/UX Design Brief

Security Operations Center Interface • Hackathon MVPVersion 1.0 • 31 July 2026

Document ID

CWS-UX-001

Parent Documents

CWS-PRD-001, CWS-TRD-001, CWS-AF-001

Product

Cyberwolf SIEM

Platform

Desktop-first responsive web application

Primary Persona

SOC Analyst

Design Goal

Fast threat comprehension and evidence-driven investigation

1. Purpose

This brief defines the visual system, information architecture, screen requirements, interactions, states, accessibility, and frontend implementation expectations for Cyberwolf SIEM. The interface must help an analyst move from security posture awareness to evidence-backed incident investigation with minimal cognitive overhead.

2. Experience Objective

The product should feel like a professional Security Operations Center console rather than a decorative 'hacker' interface. Information density is acceptable when hierarchy is strong. Severity, risk, status, time, entities, and evidence must be recognizable at a glance.

Primary UX journey: Login → Dashboard → Detect change → Open alert/incident → Understand evidence timeline → Investigate → Update status → Return to prioritized queue.

3. Design Principles

Signal over decoration — prioritize security information over visual effects.

Evidence first — alerts and incidents always provide a route to supporting evidence.

Severity is immediately scannable — never rely on color alone.

Progressive disclosure — dashboard summarizes; detail pages reveal depth.

Consistency — shared terminology, badges, timestamps, tables, filters, and states.

Fast investigation — minimize clicks between incident, alert, event, user, IP, and asset context.

Safe operations — destructive/privileged actions require clear confirmation and permission.

Real data states — loading, empty, stale, offline, error, and unauthorized states are designed explicitly.

4. Target Personas

Persona

Primary Need

UX Priority

SOC Analyst

Find and investigate important incidents

Prioritized queue, evidence, timeline, filters

Security Administrator

Manage rules, users, assets, configuration

Clear controls, permissions, auditability

Security Manager

Understand security posture

Metrics, trends, severity and incident summaries

Viewer

Read approved security information

Simple read-only navigation

5. Information Architecture

CYBERWOLF├── Dashboard├── Events│   └── Event Detail├── Alerts│   └── Alert Detail├── Incidents│   └── Incident Investigation├── Rules├── Assets│   └── Asset Detail├── Reports└── Settings    ├── Users & Roles [Admin]    ├── Integrations [future/optional]    └── System Configuration [Admin]

Optional later navigation: MITRE ATT&CK, Threat Intelligence, AI Analyst.

6. Global Application Shell

Desktop layout uses a persistent left navigation rail/sidebar, a compact top bar, and a scrollable main workspace.

Region

Contents

Sidebar

Logo/product name, primary navigation, active state, collapse control

Top Bar

Page title/context, global time range where relevant, connection state, notifications optional, user menu

Main Workspace

Page-specific metrics, filters, tables, charts, timelines and details

Global Feedback

Toasts, banners, modal confirmations, connection/error state

Sidebar labels must remain visible in normal desktop mode. Icon-only navigation may be used only in a collapsed state with accessible labels/tooltips.

7. Visual Direction

Recommended visual language: dark security-operations interface, restrained accent use, high-contrast text, subtle borders, compact data tables, clear cards, and minimal decorative effects.

Token

Recommended Direction

Background

Near-black/navy, e.g. #070B14

Surface

Dark elevated surface, e.g. #111827

Primary accent

Electric cyan/blue for active/navigation/data emphasis

Critical

Red

High

Orange

Medium

Amber/yellow

Low/Healthy

Green where semantically appropriate

Primary text

Near-white

Secondary text

Cool gray

Borders

Low-contrast neutral separators

Exact implementation colors may be adjusted to meet contrast requirements. Severity must always include text/icon/label in addition to color.

8. Typography

Use a modern sans-serif interface family such as Inter, Geist, or system UI.

Page title: 24–32 px equivalent, strong weight.

Section heading: 16–20 px equivalent.

Body/UI: 14–16 px equivalent.

Tables/metadata: 12–14 px equivalent where readable.

Use tabular numerals for security metrics where supported.

Do not use decorative monospace everywhere; reserve monospace for IDs, IPs, hashes, code/log fragments.

9. Spacing & Layout

Use an 8-point spacing system. Cards should align to a consistent grid. Dashboard should prioritize laptop widths used during judging. Avoid excessive empty space while maintaining readable grouping.

Primary content max width may be fluid for SOC tables.

Metric cards align in a responsive grid.

Tables use sticky headers where practical.

Filter bars remain close to the data they control.

Detail pages use summary header + evidence sections rather than many disconnected cards.

10. Core Design Components

Component

Required Behavior

Severity Badge

Label + semantic icon/color; LOW/MEDIUM/HIGH/CRITICAL

Risk Score

0–100 value + severity band + optional explanation

Status Badge

NEW/ACKNOWLEDGED/INVESTIGATING/RESOLVED/FALSE POSITIVE

Metric Card

Label, value, optional delta/context; clickable only when navigation is meaningful

Data Table

Sort, pagination, filters, row selection, empty/loading/error states

Filter Bar

Time and field filters; active-filter visibility; reset

Timeline

Chronological evidence with event type, time, entity, severity, source link

Evidence Card

Rule/evidence summary with link to source event

Entity Chip

IP, username, hostname or asset with copy/open behavior

Toast/Banner

Action result, error, stale/offline warning

Confirmation Dialog

For privileged/destructive changes

Skeleton/Loader

Non-blocking loading feedback

11. Screen UX-01 — Login

Purpose: secure entry with minimal distraction.

Cyberwolf logo/name and concise product subtitle.

Email/username field and password field.

Show/hide password control.

Primary Sign In action.

Generic invalid-credentials message.

Rate-limit/retry feedback without revealing account existence.

Keyboard submission and visible focus states.

Do not display default demo credentials on the production-like login page. Hackathon demo credentials, if required, belong in controlled documentation/demo mode.

12. Screen UX-02 — SOC Dashboard

The dashboard answers: What is happening now? What is most important? Where should I investigate?

Recommended top section: overall security posture/risk, events in selected period, active alerts, open incidents, critical incidents, monitored assets.

Recommended middle section: event activity timeline and severity distribution.

Recommended lower section: recent/high-priority incidents, top detections, top source entities.

Example hierarchy:CYBERWOLF / Dashboard                   Live ●Security Posture: HIGH[18,420 Events] [17 Active Alerts] [4 Open Incidents] [2 Critical]Event Activity────────────────────────────────────────────                     timeline/chartSeverity Distribution        Top Detections──────────────────────        ──────────────Priority IncidentsID       Incident                    Risk   StatusCW-42    Potential Host Compromise   94     NEWCW-39    Credential Attack           82     INVESTIGATING

Clicking a metric or incident should navigate with relevant filters/context.

13. Screen UX-03 — Event Explorer

Purpose: investigate normalized telemetry without forcing analysts to inspect raw logs first.

Top: title + event count + time range. Next: filter/search bar. Main: paginated event table.

Column

Display

Time

Normalized timestamp

Severity

Badge

Event Type

Canonical type

Source

Source type

Source IP

Copy/open entity

Destination

IP/host

User

Username if available

Outcome

Success/failure/other

Selecting a row opens Event Detail. Filters: time, source, event type, severity, source/destination IP, hostname, username, outcome, optional search.

14. Screen UX-04 — Event Detail

Event ID and timestamp

Canonical event type and severity

Source/destination entities

Username/hostname/action/outcome

Safe metadata

Raw event/evidence section with readable formatting

Related alerts

Related incident if any

Raw evidence is secondary to normalized fields but must remain accessible for explainability.

15. Screen UX-05 — Alert Center

Purpose: triage detection output.

Column

Display

Time

Alert creation time

Severity

Semantic badge

Risk

0–100

Alert

Detection title

Rule

Rule ID

Source/Target

Key entities

Status

Lifecycle badge

Incident

Linked incident if present

Default ordering should prioritize active high-risk alerts while preserving user-selectable sorting.

16. Screen UX-06 — Alert Detail

Alert title, severity, risk and status

Rule ID/name and concise reason for trigger

Trigger conditions/threshold evidence

Source and target entities

MITRE metadata if available

Related normalized events

Related incident

Status controls for authorized roles

The page must answer 'Why did Cyberwolf create this alert?' without requiring guesswork.

17. Screen UX-07 — Incident Queue

Purpose: prioritize investigations rather than raw alert volume.

Column

Display

Incident

ID + title

Severity

Badge

Risk

Score

Affected Entity

Asset/user/target

Alerts

Linked count

First/Last Seen

Time context

Status

Lifecycle

Assignee

Optional analyst

Default sort: active incidents by risk/severity and recency. Provide status, severity, risk, time, and entity filters.

18. Screen UX-08 — Incident Investigation

This is the flagship screen for the hackathon demo.

Header:CW-INC-0042 — Potential Host CompromiseCRITICAL | Risk 94/100 | NEWAffected: SERVER-01 / adminSource: 192.168.1.50[ Acknowledge ] [ Investigate ] [ Resolve ]Summary / Why this mattersAttack Timeline10:30:01  Port Scan Detected    ↓10:31:14  Repeated Authentication Failures    ↓10:32:08  Successful Login    ↓10:33:17  Privilege EventEvidence / Related AlertsAffected EntitiesMITRE MappingAnalyst NotesRisk Explanation

Timeline entries are clickable and lead to alert/event evidence. Risk explanation should show contributing factors. Status changes provide immediate feedback and update dashboard/queue state.

19. Screen UX-09 — Detection Rules

Table fields: Rule ID, name, category, severity, threshold/window summary, MITRE mapping, enabled state. Admin can enable/disable with confirmation. Viewer/analyst permissions follow backend RBAC.

Do not expose arbitrary executable rule editing in MVP.

20. Screen UX-10 — Assets

Asset list: hostname, IP, OS/type, criticality, status, last seen, open incidents. Asset detail may show related events, alerts, incidents and criticality context.

21. Screen UX-11 — Reports

MVP reports may provide selected-period totals, severity distribution, top rules, incident status, top source entities, and trend summaries. Export is optional and should not delay the golden path.

22. Screen UX-12 — Settings

Settings are role-aware. Admin-only controls may include users/roles, system configuration, demo mode, and future integrations. Sensitive values must never be displayed in plaintext after storage.

23. Incident Timeline Design

Each timeline item must include timestamp, event/detection label, severity, important entities, short evidence summary, and source link. Use vertical chronology on desktop and mobile. The timeline is evidence, not decoration; do not invent missing attack stages.

24. Risk & Severity UX

Risk score and severity are related but distinct. Display the numeric risk where prioritization matters and a textual severity badge everywhere.

Risk

Severity

UX Meaning

0–24

LOW

Low-priority security context

25–49

MEDIUM

Review when appropriate

50–74

HIGH

Prioritized investigation

75–100

CRITICAL

Immediate analyst attention

Never communicate severity only through red/orange/green. Include labels and accessible semantics.

25. Status UX

Use stable status vocabulary across alerts/incidents. Active states should be distinguishable from terminal states. Mutations require backend confirmation before the UI treats them as persisted.

NEW

ACKNOWLEDGED

INVESTIGATING

RESOLVED

FALSE POSITIVE

26. Filter & Search Behavior

Filters should update visible results predictably.

Active filters remain visible and individually removable.

Provide Clear All.

Time range is explicit.

Persist useful filters while navigating to detail and back where practical.

Do not perform unbounded queries; UI respects backend pagination/page limits.

Empty results explain whether no data exists or filters removed all results.

27. Loading, Empty, Error & Offline States

State

Expected UX

Loading

Skeleton/progress; retain layout where possible

Empty

Explain no data and provide next action where meaningful

Filtered Empty

State that no records match current filters; offer clear filters

API Error

Concise error + retry

Unauthorized

Access denied; do not render protected content

Realtime Offline

Non-alarming connection banner; fallback/retry

Stale Data

Show last refresh/time where relevant

28. Notifications & Feedback

Use toasts for successful acknowledgement/status changes and non-critical failures. Use persistent banners for system-wide connectivity/health issues. Avoid excessive alert sounds/animations during the hackathon demo.

29. Confirmation Patterns

Confirmation is required for rule disablement, user/role changes, and other high-impact actions. Routine analyst actions such as acknowledging an alert should remain efficient but must provide undo/recovery where feasible.

30. Accessibility

Meet strong text/background contrast.

All interactive elements keyboard accessible.

Visible focus states.

Labels associated with form fields.

Icons have accessible names where needed.

Charts have textual summaries/legends.

Color is never the only carrier of security meaning.

Touch/click targets remain usable on smaller screens.

31. Responsive Behavior

Primary target is a laptop/desktop SOC console. Tablet/mobile should preserve investigation capability, but complex tables may convert to stacked cards or horizontally scroll with clear affordances.

Viewport

Behavior

Desktop

Expanded sidebar, multi-column dashboard, full tables

Tablet

Collapsed sidebar, reduced card columns, preserved filters

Mobile

Drawer navigation, stacked metrics, simplified tables/cards, vertical timeline

32. Motion

Use subtle motion only for state transitions, loading, panel expansion, and live-data arrival. Avoid flashing effects, constant glowing animations, fake terminal typing, or motion that competes with security information.

33. Data Visualization Rules

Charts must answer a security question, not fill space.

Always label axes/time ranges where applicable.

Provide tooltips for exact values.

Use consistent severity semantics.

Do not use 3D charts.

Prefer line/area charts for event trends and bars/donuts only where categorical comparison is clear.

Dashboard charts must derive from backend data.

34. Component States

Every reusable component should define default, hover, focus, selected, disabled, loading, error, and permission-restricted behavior where applicable.

35. Security UX Requirements

Do not expose tokens, secrets, passwords, stack traces, or sensitive configuration.

Generic authentication errors.

Role-aware UI plus mandatory backend authorization.

Privileged changes display actor-impact context.

Audit-sensitive actions should provide clear success/failure feedback.

Raw event rendering must escape unsafe content; never render event payload as executable HTML.

External URLs, if later supported, are treated as untrusted input.

36. Frontend Architecture Guidance

Recommended React organization: pages for route-level screens; components for reusable UI; services for typed API calls; hooks for shared query/realtime logic; types for API contracts; auth context/store for identity presentation only.

The backend remains authoritative for permissions and state. Avoid duplicating detection/correlation logic in the frontend.

37. Suggested Component Inventory

AppShell

Sidebar

TopBar

PageHeader

MetricCard

SecurityPostureCard

SeverityBadge

RiskScore

StatusBadge

FilterBar

TimeRangePicker

EventTable

AlertTable

IncidentTable

EvidenceTimeline

EvidenceCard

EntityChip

RuleBadge

EmptyState

ErrorState

LoadingSkeleton

ConfirmDialog

Toast

PermissionGate

ConnectionStatus

38. Dashboard Wireframe

┌──────────────────────────────────────────────────────────────┐│ CYBERWOLF    Dashboard                      Live ●   User ▾   │├────────────┬─────────────────────────────────────────────────┤│ Dashboard  │ Security Posture: HIGH                          ││ Events     │                                                 ││ Alerts     │ [Events] [Alerts] [Incidents] [Critical]       ││ Incidents  │                                                 ││ Rules      │ Event Activity                                  ││ Assets     │ ─────────────────────────────────────────────   ││ Reports    │                                                 ││ Settings   │ Severity              Top Detections            ││            │                                                 ││            │ Priority Incidents                              ││            │ CW-42  Host Compromise  94  CRITICAL  NEW      │└────────────┴─────────────────────────────────────────────────┘

39. Incident Investigation Wireframe

┌──────────────────────────────────────────────────────────────┐│ CW-INC-0042  Potential Host Compromise                      ││ CRITICAL   Risk 94/100   NEW                                ││ SERVER-01 • admin • 192.168.1.50                            ││                         [Acknowledge] [Investigate] [Resolve]│├──────────────────────────────────────────────────────────────┤│ WHY THIS INCIDENT EXISTS                                    ││ Related scan, authentication and privilege findings.        │├──────────────────────────────────────────────────────────────┤│ TIMELINE                                                     ││ 10:30:01  Port Scan                                         ││ 10:31:14  Failed Logins × N                                 ││ 10:32:08  Successful Login                                  ││ 10:33:17  Privilege Event                                   │├──────────────────────────────────────────────────────────────┤│ EVIDENCE      AFFECTED ENTITIES      RISK EXPLANATION       │└──────────────────────────────────────────────────────────────┘

40. Hackathon Demo UX

The demo must require minimal navigation and no manual database manipulation.

Start on Dashboard with known baseline data.

Trigger/replay controlled telemetry.

Show event/alert counters update.

Open newly generated critical incident directly.

Show timeline and evidence.

Show why risk is high.

Change incident status to INVESTIGATING.

Return to dashboard and show updated state.

41. UI Acceptance Criteria

UX-AC-01: All P0 routes render and use backend data.

UX-AC-02: Dashboard clearly prioritizes active high-risk incidents.

UX-AC-03: Events and alerts support filtering and pagination.

UX-AC-04: Alert detail explains why detection triggered.

UX-AC-05: Incident detail shows linked evidence and chronology.

UX-AC-06: Severity uses text plus semantic visual treatment.

UX-AC-07: Loading, empty, error and unauthorized states exist.

UX-AC-08: RBAC affects available controls while backend enforces permission.

UX-AC-09: Status mutations provide confirmation/feedback and persist.

UX-AC-10: Golden demo can be completed rapidly without developer-only UI.

42. Codex / Frontend Agent Handoff

Build the interface from the application flows and API contracts, not from placeholder visual assumptions. Prioritize Login, Dashboard, Events, Alerts, Incident Queue, and Incident Investigation before optional pages.

Use reusable typed components and one consistent design system.

Do not hard-code security findings that should come from backend APIs.

Do not calculate authoritative risk/detection logic in the browser.

Preserve filters/context when moving between queues and details where practical.

Escape raw event content.

Implement permission-aware controls but rely on backend authorization.

Make the golden demo path visually obvious and stable.

Do not add decorative complexity that reduces readability or demo reliability.

43. Design Definition of Done

The UI/UX is complete for the hackathon MVP when an authenticated analyst can understand current security posture, find high-priority incidents, inspect normalized events and alerts, understand exactly why an incident exists through linked evidence/timeline, update investigation status, and receive clear feedback across normal and failure states.