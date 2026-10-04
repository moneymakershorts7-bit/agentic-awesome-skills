# Google Jules REST API Reference (v1alpha)

Endpoint base: `https://jules.googleapis.com/v1alpha`
Authentication: Header `X-Goog-Api-Key: $JULES_API_KEY` (Generate up to 3 keys in https://jules.google.com -> Settings).

---

## 1. Core Resources

- **Source**: A connected input repository (e.g. GitHub repository where the Jules GitHub App is installed). Resource format: `sources/github/{owner}/{repo}`.
- **Session**: A continuous unit of autonomous work within a codebase context. Resource format: `sessions/{sessionId}`.
- **Activity**: An event, plan iteration, status change, or message exchanged within a session.

---

## 2. API Endpoints

### Sources

#### List Sources
Retrieve all repositories accessible by Jules.
```http
GET /v1alpha/sources?pageSize=20&pageToken={token}
X-Goog-Api-Key: $JULES_API_KEY
```
Response:
```json
{
  "sources": [
    {
      "name": "sources/github/octocat/hello-world",
      "id": "github/octocat/hello-world",
      "githubRepo": {
        "owner": "octocat",
        "repo": "hello-world"
      }
    }
  ],
  "nextPageToken": "string"
}
```

---

### Sessions

#### Create Session
Dispatch an autonomous coding task to Jules.
```http
POST /v1alpha/sessions
Content-Type: application/json
X-Goog-Api-Key: $JULES_API_KEY

{
  "prompt": "Fix flakiness in authentication tests and add retry logic",
  "title": "Fix auth tests",
  "sourceContext": {
    "source": "sources/github/octocat/hello-world",
    "githubRepoContext": {
      "startingBranch": "main"
    }
  },
  "automationMode": "AUTO_CREATE_PR",
  "requirePlanApproval": false
}
```

Parameters:
- `prompt` (string, required): Clear, actionable instructions for Jules.
- `title` (string, optional): Short identifier for the session.
- `sourceContext.source` (string, required): `sources/github/{owner}/{repo}`.
- `sourceContext.githubRepoContext.startingBranch` (string, optional): Default is `main`.
- `automationMode` (string, optional): Set to `"AUTO_CREATE_PR"` to have Jules automatically publish a GitHub PR upon successful test validation.
- `requirePlanApproval` (boolean, optional): If `true`, Jules pauses after generating the plan and waits for an explicit `:approvePlan` call.

#### Get Session
Poll progress, status, and PR outputs.
```http
GET /v1alpha/sessions/{sessionId}
X-Goog-Api-Key: $JULES_API_KEY
```
Response when PR created:
```json
{
  "name": "sessions/31415926535897932384",
  "id": "31415926535897932384",
  "title": "Fix auth tests",
  "outputs": [
    {
      "pullRequest": {
        "url": "https://github.com/octocat/hello-world/pull/42",
        "title": "Fix flakiness in authentication tests",
        "description": "Added exponential backoff retry to token verification."
      }
    }
  ]
}
```

#### List Sessions
```http
GET /v1alpha/sessions?pageSize=10
X-Goog-Api-Key: $JULES_API_KEY
```

#### Approve Plan
Required if `requirePlanApproval: true`.
```http
POST /v1alpha/sessions/{sessionId}:approvePlan
Content-Type: application/json
X-Goog-Api-Key: $JULES_API_KEY

{}
```

---

### Activities

#### List Activities
Inspect reasoning steps, plans, shell outputs, and agent thoughts.
```http
GET /v1alpha/sessions/{sessionId}/activities?pageSize=50
X-Goog-Api-Key: $JULES_API_KEY
```

#### Send User Feedback / Message
Send additional guidance or instructions to an active session.
```http
POST /v1alpha/sessions/{sessionId}/activities
Content-Type: application/json
X-Goog-Api-Key: $JULES_API_KEY

{
  "prompt": "Please also update docs/authentication.md with the new retry behavior."
}
```
