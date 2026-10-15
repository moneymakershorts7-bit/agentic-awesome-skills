# SRE Incident Triage Playbook & Severity Response Operations

## Executive Overview & Operational Principles

Incident management is a critical process for any organization that aims to provide reliable service to its customers. The goal of incident management is to detect and resolve incidents quickly, communicate incidents to customers and stakeholders, and minimize any negative effects. This playbook outlines the incident triage process, severity classification, and response operations for SRE teams.

### Incident Command System (ICS) Roles and Responsibilities

The ICS roles and responsibilities are as follows:

* **Incident Commander (IC)**: Makes strategic decisions and provides overall direction for the incident response.
* **Operations Lead (OL)**: Oversees the technical aspects of the incident response and coordinates with the incident commander.
* **Communications Lead (CL)**: Handles communication with stakeholders, including customers, executives, and other teams.
* **Scribe**: Documents the incident response process, including decisions, actions, and outcomes.

### Severity Classification Matrix

The severity classification matrix is as follows:

| Severity | Description | Blast Radius | Response SLA | Page Targets |
| --- | --- | --- | --- | --- |
| SEV-0/P1 Critical Outage | Service is down for all users or customers | High | 5 minutes | Immediate |
| SEV-1/P2 Major Degradation | Significant part of core functionality is not working | Medium | 15 minutes | 30 minutes |
| SEV-2/P3 Moderate Issue | System issue causes slight inconvenience to users or customers | Low | 30 minutes | 1 hour |
| SEV-3/P4 Minor/Low | Bug creates minor inconvenience to customers | Very Low | 1 hour | 2 hours |

## Architecture & Concrete Configurations / Code Recipes

### Incident Management Tool Configuration

The incident management tool is configured to integrate with monitoring and reporting tools, including:

* Uptime monitor
* Support ticketing system
* Jira

The tool is also configured to send notifications to on-call personnel and stakeholders.

### Alerting and Notification Configuration

The alerting and notification configuration is as follows:

* Alerting is configured to send notifications to on-call personnel and stakeholders.
* Notifications are sent via email, Slack, and Teams.
* Notifications include incident details, including severity, impact, and resolution status.

### Status Page Configuration

The status page is configured to display incident information, including:

* Incident title and description
* Severity and impact
* Resolution status
* Estimated time to resolution

## Step-by-Step Production Procedures & Diagnostic Queries / Commands

### Triage Workflow

The triage workflow is as follows:

1. **Detect & Verify**: Detect the incident and verify its impact.
2. **Assess Impact**: Assess the impact of the incident and determine its severity.
3. **Declare Incident & Open War Room**: Declare the incident and open a war room to coordinate the response.
4. **Mitigate/Stabilize**: Mitigate and stabilize the incident to prevent further impact.
5. **Debug Root Cause**: Debug the root cause of the incident.
6. **Resolve**: Resolve the incident and restore normal service operations.

### Diagnostic Queries and Commands

The diagnostic queries and commands are as follows:

* `ps -ef | grep <process_name>`: Check process status.
* `netstat -tlnp | grep <port_number>`: Check port status.
* `df -h`: Check disk usage.
* `free -m`: Check memory usage.

## Common Failure Modes, Anti-Patterns & Troubleshooting

### Common Failure Modes

The common failure modes are as follows:

* **Insufficient monitoring**: Insufficient monitoring can lead to delayed detection of incidents.
* **Inadequate communication**: Inadequate communication can lead to delayed response and resolution.
* **Inadequate training**: Inadequate training can lead to inadequate response and resolution.

### Anti-Patterns

The anti-patterns are as follows:

* **Over-reliance on automation**: Over-reliance on automation can lead to inadequate response and resolution.
* **Under-reliance on human judgment**: Under-reliance on human judgment can lead to inadequate response and resolution.

### Troubleshooting

The troubleshooting steps are as follows:

1. **Gather information**: Gather information about the incident, including symptoms, impact, and error messages.
2. **Analyze data**: Analyze data to identify the root cause of the incident.
3. **Test hypotheses**: Test hypotheses to confirm the root cause of the incident.
4. **Implement fix**: Implement a fix to resolve the incident.

## Operational Checklist & Verification Gates

### Operational Checklist

The operational checklist is as follows:

* **Incident detection**: Ensure incident detection is working correctly.
* **Communication**: Ensure communication is working correctly.
* **Response**: Ensure response is working correctly.
* **Resolution**: Ensure resolution is working correctly.

### Verification Gates

The verification gates are as follows:

* **Incident detection**: Verify incident detection is working correctly.
* **Communication**: Verify communication is working correctly.
* **Response**: Verify response is working correctly.
* **Resolution**: Verify resolution is working correctly.

## Code Snippets

### YAML Configuration

```yml
incident_management:
  tool:
    name: Better Stack
    version: 1.0
  alerting:
    notification:
      email:
        to: oncall@example.com
      slack:
        channel: #oncall
      teams:
        channel: @oncall
  status_page:
    title: Incident Status
    description: Incident status page
```

### Python Script

```python
import requests

def send_notification(title, description):
    url = "https://betterstack.com/api/v1/incidents"
    headers = {"Authorization": "Bearer YOUR_API_KEY"}
    data = {"title": title, "description": description}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        print("Notification sent successfully")
    else:
        print("Error sending notification")

title = "Incident Title"
description = "Incident description"
send_notification(title, description)
```

### Go Script

```go
package main

import (
    "fmt"
    "net/http"
)

func sendNotification(title, description string) {
    url := "https://betterstack.com/api/v1/incidents"
    headers := map[string]string{"Authorization": "Bearer YOUR_API_KEY"}
    data := map[string]string{"title": title, "description": description}
    resp, err := http.Post(url, "application/json", data)
    if err != nil {
        fmt.Println(err)
        return
    }
    if resp.StatusCode == 201 {
        fmt.Println("Notification sent successfully")
    } else {
        fmt.Println("Error sending notification")
    }
}

func main() {
    title := "Incident Title"
    description := "Incident description"
    sendNotification(title, description)
}
```

Note: The code snippets are examples and may need to be modified to fit your specific use case.
