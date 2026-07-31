CYBERWOLF SIEM

Product Requirements Document (PRD)

Intelligent Security Information & Event Management PlatformVersion 1.0 — Hackathon MVP31 July 2026

Document ID

CWS-PRD-001

Project

Cyberwolf SIEM

Product Type

Security Information and Event Management Platform

Status

Development Specification

Purpose

Hackathon development, technical handoff, implementation and evaluation

Core Pipeline

Collect → Normalize → Detect → Correlate → Prioritize → Investigate

1. Executive Summary

Cyberwolf SIEM is a cybersecurity monitoring and incident-analysis platform designed to collect security telemetry from multiple sources, normalize heterogeneous events into a common schema, detect suspicious activity, correlate related alerts, calculate risk, and present actionable incidents through a centralized Security Operations Center (SOC) dashboard.

The hackathon MVP is built around one end-to-end security workflow: Raw Logs → Normalized Events → Detections → Correlated Alerts → Prioritized Incidents → Analyst Investigation.

2. Problem Statement

Modern environments generate security information from operating systems, authentication services, applications, servers, network devices, firewalls, IDS/IPS systems, endpoints, and APIs. Individual events often lack enough context to indicate an attack, while sequences of related events can reveal meaningful attacker behavior.

Cyberwolf addresses the challenge of centralizing heterogeneous security telemetry and converting it into explainable, prioritized security incidents while reducing the amount of raw information analysts must manually inspect.

3. Product Vision

Cyberwolf should evolve into a modular SIEM that provides visibility, detection, correlation, prioritization, investigation, and eventually controlled response capabilities.

Visibility — understand activity across monitored systems.

Detection — identify known suspicious behaviors.

Correlation — connect related events across time, users, IP addresses, hosts, and sources.

Prioritization — rank alerts and incidents by risk.

Investigation — retain evidence and context required for analyst decisions.

Response — future support for analyst-approved or automated response workflows.

4. Product Mission

The MVP must prove that Cyberwolf can ingest security telemetry and transform a sequence of suspicious events into an explainable, prioritized incident. The goal is not to reproduce every enterprise SIEM capability; it is to demonstrate a technically defensible, reliable end-to-end SIEM architecture.

5. Product Principles

Evidence before AI: Deterministic security logic forms the core of detection. AI may summarize evidence but must not invent findings.

Explainable detection: Every alert must identify what happened, why it triggered, when and where it occurred, the evidence involved, and its severity.

Modular architecture: Collectors, parsers, detection rules, correlation, storage, and UI should be independently extensible.

Security by design: Authentication, authorization, validation, audit logging, rate limiting, and secure secret handling are product requirements.

Demo reliability over unnecessary complexity: Hackathon features are prioritized by their contribution to the complete security workflow.

6. Target Users

SOC Analyst — monitors alerts, investigates incidents, searches events, reviews evidence, and manages incident status.

Security Administrator — manages users, integrations, assets, detection rules, and configuration.

Security Manager — reviews incident counts, security posture, severity distribution, trends, and reports.

Viewer — read-only access to approved dashboards and reports.

7. Primary User Story

As a SOC analyst, I want security events from multiple systems to be automatically collected, normalized, analyzed, and correlated so that I can identify and investigate important security incidents without manually inspecting every raw log.

8. Core Product Workflow

Data Sources → Ingestion → Parsing → Normalization → Enrichment → Detection → Correlation → Risk Scoring → Alert/Incident → SOC Dashboard → Investigation

9. Functional Requirements

FR-01 Authentication

Secure login/logout, authenticated sessions or tokens, password hashing, and safe invalid-login handling.

FR-02 Authorization

Role-Based Access Control with Admin, Analyst, and Viewer roles.

FR-03 Telemetry Ingestion

Accept security events through REST API, JSON, log files, and a synthetic event generator/replayer. Future sources include Linux, Windows, application, firewall, Suricata, Zeek, and cloud telemetry.

FR-04 Event Parsing

Convert incoming telemetry into structured fields such as event type, username, source IP, action, and outcome.

FR-05 Event Normalization

Map supported sources to a common Cyberwolf event schema.

FR-06 Event Enrichment

Add deterministic context such as asset identity, hostname, user information, rule metadata, and MITRE ATT&CK mapping where available.

FR-07 Detection Engine

Provide rule-based detection using rule ID, name, conditions, threshold, time window, severity, risk weight, MITRE mapping, and enabled state.

FR-08 Correlation Engine

Correlate related alerts by source/destination IP, hostname, username, asset, event type, and time window.

FR-09 Risk Scoring

Assign transparent deterministic risk scores from 0–100 using severity, frequency, correlations, asset importance, and compromise indicators.

FR-10 Alert Management

Generate alerts containing rule, severity, risk score, source, target, evidence, mapping, timestamp, and lifecycle status.

FR-11 Incident Management

Group related alerts into incidents with severity, risk, affected entities, evidence, and chronological timeline.

FR-12 SOC Dashboard

Display events, active alerts, open incidents, critical/high severity counts, monitored assets, trends, and recent incidents.

FR-13 Event Explorer

Filter/search normalized events by time, source, event type, severity, IPs, hostname, username, and outcome.

FR-14 Alert Center

Filter, sort, inspect, acknowledge, update, and navigate from alerts to incidents.

FR-15 Incident Investigation

Show incident summary, risk, severity, affected user/asset, source, timeline, alerts, evidence, MITRE mapping, notes, and status.

FR-16 Detection Rule Management

Authorized users can inspect, enable, and disable rules; creation/editing is optional for MVP.

FR-17 Asset Management

Maintain asset ID, hostname, IP, OS, type, criticality, status, and last-seen information.

FR-18 Audit Logging

Record sensitive actions including login failures, rule changes, alert acknowledgements, incident resolution, user creation, and role changes.

10. Common Event Schema

Field

Purpose

event_id

Unique event identifier

timestamp

Event time

source_type

Origin/source category

event_type

Normalized security event type

source_ip

Originating IP

destination_ip

Target IP

hostname

Related host

username

Related account

action

Observed action

outcome

Success/failure/other

severity

Event severity

raw_event

Original event for evidence

metadata

Extensible structured context

11. MVP Detection Content

CW-AUTH-001 — Repeated Authentication Failures

CW-AUTH-002 — Multiple Accounts Targeted

CW-NET-001 — Port Scan Pattern

CW-WEB-001 — Suspicious Web Request Pattern

CW-PRIV-001 — Privilege Escalation Event

CW-LOGIN-001 — Suspicious Login Sequence

CW-IDS-001 — High-Severity IDS Alert

The MVP should implement approximately 6–10 high-quality, testable detections rather than a large quantity of weak rules.

12. Correlation & Risk Model

Correlation associates related findings using entities and time. A representative golden path is: Port Scan → Repeated Authentication Failures → Successful Login → Privilege Event → Potential Host Compromise.

Risk scores use a 0–100 scale and must be explainable. Inputs may include rule severity, event frequency, number of correlated detections, asset criticality, successful compromise indicators, and correlation confidence.

13. Security Requirements

Password hashing; never store plaintext passwords.

Authentication and RBAC on protected functionality.

Input validation for event and API payloads.

Rate limiting on sensitive/exposed endpoints.

Audit logging for privileged and security-relevant actions.

Secrets stored outside source control; provide .env.example only.

Restricted CORS and secure configuration.

Safe error responses that do not expose internal secrets or stack details.

14. UI Requirements

Primary navigation: Dashboard, Events, Alerts, Incidents, Rules, Assets, Reports, Settings. Optional extensions include MITRE ATT&CK, AI Analyst, and Threat Intelligence.

The interface should resemble a professional SOC console with strong information hierarchy, readable tables, fast severity recognition, clear timelines, consistent status indicators, responsive layouts, and low cognitive overload.

15. MVP Scope

15.1 Must Have

Authentication and RBAC

Event ingestion and normalized event model

Event storage and explorer

Rule engine and detection rules

Alerts

Correlation and risk scoring

Incidents and timeline

SOC dashboard

Audit logging

Controlled demo event generator/replayer

15.2 Should Have

MITRE ATT&CK mapping

Asset management

Rule management

Live/WebSocket dashboard updates

Reports

15.3 Could Have

AI incident explanation

External threat intelligence

Sigma compatibility

Suricata integration

Zeek integration

Notifications

15.4 Not Required for Hackathon MVP

Kubernetes

Large-scale distributed streaming

Full SOAR

Production-scale machine learning

Hundreds of integrations

Endpoint EDR

Autonomous remediation

16. Non-Functional Requirements

Performance — demo workloads must not block the UI.

Reliability — malformed events must not crash the ingestion pipeline.

Security — protected APIs reject unauthorized access.

Maintainability — core components use clear interfaces and module boundaries.

Observability — backend errors and important operational events are logged.

Reproducibility — documented repository instructions start the system.

Explainability — detections retain enough evidence to explain triggers.

17. Product Modules

M01 Authentication & RBAC

M02 Telemetry Ingestion

M03 Parsing & Normalization

M04 Event Storage

M05 Detection Engine

M06 Correlation Engine

M07 Risk Engine

M08 Alert Management

M09 Incident Management

M10 SOC Dashboard

M11 Event Explorer

M12 Asset Management

M13 Audit & Security

M14 Demo/Test Infrastructure

Optional later modules: Threat Intelligence, AI Analyst, Reporting, and Response Automation.

18. Golden Demo Scenario

1. Replay or generate a controlled network scanning event.

2. Generate repeated authentication failures from the same source.

3. Generate a successful authentication event.

4. Generate a privilege-related event.

5. Allow individual detection rules to trigger.

6. Correlate related findings.

7. Create a Potential Host Compromise incident with CRITICAL severity and high risk.

8. Update the SOC dashboard.

9. Open the incident.

10. Display its evidence and chronological timeline.

19. Success Criteria

SC-01: A security event can enter through the ingestion interface.

SC-02: The event is normalized and persisted.

SC-03: A matching rule detects suspicious activity.

SC-04: An alert is generated with evidence.

SC-05: Related alerts can be correlated.

SC-06: Risk score and severity are calculated.

SC-07: An incident is generated.

SC-08: The incident appears on the dashboard.

SC-09: An analyst can inspect timeline and evidence.

SC-10: Protected functionality respects RBAC.

SC-11: The complete golden path can be reproduced during judging.

20. Hackathon Round Alignment

Round

Focus

Expected Product Evidence

1

PPT, Flow & Architecture

PRD, architecture, application flow, GitHub foundation

2

Base Code, Idea & Solution

Frontend, backend, database, authentication, basic telemetry pipeline

3

Code Verification

Detection, correlation, security controls, automated tests, reproducible setup

4

Output Validation

Controlled telemetry replay proving detection → correlation → incident generation

5

Progress & Presentation

Complete dashboard, golden-path demo, engineering metrics, final pitch

21. Definition of Done

Cyberwolf SIEM v1 Hackathon MVP is complete when a user can log in, view the dashboard, submit/replay telemetry, observe normalized events, trigger detections, generate alerts, correlate related alerts, calculate risk, create an incident, and inspect its timeline and evidence.

Backend tests pass.

Authentication and RBAC work.

Invalid events are handled safely.

No secrets are committed.

Repository setup is documented.

The golden demo is reproducible.

22. Development-Agent Handoff

Build a functioning, modular SIEM MVP. Do not expand scope until the complete event → detection → correlation → incident → investigation pipeline works.

Priority P0: Authentication → Database → Ingestion → Normalization → Detection → Alert → Correlation → Incident → Dashboard.

Priority P1: Event search → Assets → MITRE mapping → Audit logging → Live updates.

Priority P2: AI Analyst → Threat Intelligence → Advanced analytics → External integrations.

Every module must include implementation, validation, tests, error handling, and documentation. A module is not complete merely because its UI exists.

23. Approval / Handoff Notes

This PRD is the product-level source of truth for the Cyberwolf SIEM hackathon MVP. The Technical Requirements Document (TRD), Application Flow, UI/UX Design Brief, Backend Schema, and Implementation Plan must derive from this document and preserve its core pipeline and scope boundaries.