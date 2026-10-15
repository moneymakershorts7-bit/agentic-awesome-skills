# SRE On-Call Rotation Design, Scheduling & Sustainability Runbook

## Executive Overview & Operational Principles

This runbook outlines the comprehensive design, scheduling, and sustainability principles for SRE on-call rotations. The goal is to ensure a reliable and efficient incident response process, minimizing downtime and ensuring a healthy work-life balance for engineers.

### Key Principles

*   **Fair Scheduling**: Ensure that on-call duties are distributed fairly among team members, considering their preferences, availability, and workloads.
*   **Incident Response Efficiency**: Design the on-call rotation to minimize incident response times, ensuring that critical issues are addressed promptly.
*   **Engineer Well-being**: Prioritize engineer well-being by providing adequate rest time, minimizing night shifts, and promoting a healthy work-life balance.
*   **Scalability**: Design the on-call rotation to scale with the team's growth, ensuring that the process remains efficient and effective.

## Architecture & Concrete Configurations / Code Recipes

### Rotation Topologies & Schedules

#### Follow-the-Sun (Distributed Global Teams, Daylight-Only Rotations)

*   **Pros**:
    *   Global coverage
    *   Daylight-only rotations
    *   Reduced night shifts
*   **Cons**:
    *   Complexity in managing global teams
    *   Potential for timezone conflicts
*   **Minimum Team Size**: 4+ team members

#### Single-Team Weekly Rotations (Primary/Secondary Pairings)

*   **Pros**:
    *   Simplicity
    *   Easy to manage
    *   Rest time for engineers
*   **Cons**:
    *   Intensive on-call week
    *   Night shifts
*   **Minimum Team Size**: 2+ team members

#### Split-Shift Schedules

*   **Pros**:
    *   Reduced night shifts
    *   Improved work-life balance
*   **Cons**:
    *   Complexity in managing split shifts
    *   Potential for timezone conflicts
*   **Minimum Team Size**: 4+ team members

### On-Call Compensation & Incentives

#### Standard Industry Compensation Models

*   **Standby Stipend Rates**: $X per hour for on-call time
*   **Per-Incident Response Pay**: $Y per incident for response time
*   **Compensatory Time Off / Sleep Recovery Hours**: X hours of compensatory time off or sleep recovery hours for off-hours pages

#### Legal Compliance Considerations

*   **Fair Labor Standards Act (FLSA)**: Ensure compliance with FLSA regulations regarding overtime pay and compensatory time off.
*   **State and Local Laws**: Ensure compliance with state and local laws regarding on-call pay and compensatory time off.

### Shift Handoff Ritual

#### Complete Handoff Checklist

*   **Open Incidents**: List of open incidents, including incident ID, description, and status
*   **Active Mitigations**: List of active mitigations, including mitigation ID, description, and status
*   **Noisy Alerts**: List of noisy alerts, including alert ID, description, and status
*   **Upcoming Changes**: List of upcoming changes, including change ID, description, and status
*   **Maintenance Windows**: List of maintenance windows, including window ID, description, and status

### Overrides, Swaps & Escalation Policies

#### Workflow for Planned Swaps

*   **Request Swap**: Request swap from on-call engineer
*   **Approve Swap**: Approve swap request from manager
*   **Notify Team**: Notify team of swap

#### Workflow for Emergency Cover

*   **Emergency Page**: Receive emergency page
*   **Respond**: Respond to emergency page
*   **Escalate**: Escalate to backup engineer if necessary

#### Workflow for Unacknowledged Page Escalations

*   **Unacknowledged Page**: Receive unacknowledged page
*   **Escalate**: Escalate to backup engineer
*   **Notify Team**: Notify team of escalation

### Burnout Prevention & Health Metrics

#### Maximum Paging Thresholds per Shift

*   **Threshold**: X number of pages per shift
*   **Notification**: Notify team of threshold exceeded

#### Mandatory Off-Call Cool-Down Periods

*   **Cool-Down Period**: X hours of off-call time after on-call shift
*   **Notification**: Notify team of cool-down period

#### Shadow Onboarding for New Engineers

*   **Shadowing**: Shadow experienced engineers during on-call shifts
*   **Training**: Provide training on on-call procedures and tools

## Step-by-Step Production Procedures & Diagnostic Queries / Commands

### On-Call Rotation Design

1.  **Gather Team Preferences**: Gather team preferences, including timezone, regular working hours, and on-call preferences.
2.  **Design Rotation Topology**: Design rotation topology, considering team size, timezone, and on-call preferences.
3.  **Create On-Call Schedule**: Create on-call schedule, considering rotation topology and team preferences.
4.  **Test On-Call Schedule**: Test on-call schedule, ensuring that it meets team needs and is scalable.

### On-Call Compensation & Incentives

1.  **Determine Compensation Model**: Determine compensation model, considering team size, incident frequency, and severity.
2.  **Calculate Compensation**: Calculate compensation, considering compensation model and team size.
3.  **Notify Team**: Notify team of compensation model and calculation.

### Shift Handoff Ritual

1.  **Create Handoff Checklist**: Create handoff checklist, considering open incidents, active mitigations, noisy alerts, upcoming changes, and maintenance windows.
2.  **Conduct Handoff**: Conduct handoff, ensuring that all items on handoff checklist are completed.
3.  **Verify Handoff**: Verify handoff, ensuring that all items on handoff checklist are complete.

### Overrides, Swaps & Escalation Policies

1.  **Request Swap**: Request swap from on-call engineer.
2.  **Approve Swap**: Approve swap request from manager.
3.  **Notify Team**: Notify team of swap.

## Common Failure Modes, Anti-Patterns & Troubleshooting

### On-Call Rotation Design

*   **Insufficient Team Size**: Insufficient team size can lead to burnout and decreased incident response efficiency.
*   **Inadequate Rotation Topology**: Inadequate rotation topology can lead to night shifts and decreased work-life balance.
*   **Poor Communication**: Poor communication can lead to misunderstandings and decreased incident response efficiency.

### On-Call Compensation & Incentives

*   **Inadequate Compensation**: Inadequate compensation can lead to burnout and decreased incident response efficiency.
*   **Poor Communication**: Poor communication can lead to misunderstandings and decreased incident response efficiency.

### Shift Handoff Ritual

*   **Incomplete Handoff**: Incomplete handoff can lead to decreased incident response efficiency and increased downtime.
*   **Poor Communication**: Poor communication can lead to misunderstandings and decreased incident response efficiency.

### Overrides, Swaps & Escalation Policies

*   **Inadequate Swap Process**: Inadequate swap process can lead to decreased incident response efficiency and increased downtime.
*   **Poor Communication**: Poor communication can lead to misunderstandings and decreased incident response efficiency.

## Operational Checklist & Verification Gates

### On-Call Rotation Design

1.  **Verify Team Size**: Verify team size, ensuring that it is sufficient for on-call rotation.
2.  **Verify Rotation Topology**: Verify rotation topology, ensuring that it is adequate for team size and timezone.
3.  **Verify Communication**: Verify communication, ensuring that it is clear and effective.

### On-Call Compensation & Incentives

1.  **Verify Compensation Model**: Verify compensation model, ensuring that it is adequate for team size and incident frequency.
2.  **Verify Compensation Calculation**: Verify compensation calculation, ensuring that it is accurate and fair.
3.  **Verify Communication**: Verify communication, ensuring that it is clear and effective.

### Shift Handoff Ritual

1.  **Verify Handoff Checklist**: Verify handoff checklist, ensuring that it is complete and accurate.
2.  **Verify Handoff Completion**: Verify handoff completion, ensuring that all items on handoff checklist are complete.
3.  **Verify Communication**: Verify communication, ensuring that it is clear and effective.

### Overrides, Swaps & Escalation Policies

1.  **Verify Swap Process**: Verify swap process, ensuring that it is adequate and effective.
2.  **Verify Communication**: Verify communication, ensuring that it is clear and effective.
3.  **Verify Escalation Process**: Verify escalation process, ensuring that it is adequate and effective.

By following this runbook, you can design, implement, and maintain a comprehensive SRE on-call rotation process that ensures a reliable and efficient incident response process, minimizes downtime, and promotes a healthy work-life balance for engineers.
