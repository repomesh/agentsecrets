# SKILL.md — Updated AgentSecrets OpenClaw Skill

```yaml
---
name: agentsecrets
description: Zero-knowledge secrets infrastructure — AI agents operate the complete credential lifecycle without ever seeing values
version: "1.1.0"
tags:
  - security
  - credentials
  - api
  - secrets
  - mcp
  - setup
  - zero-knowledge
  - secrets-management
homepage: https://github.com/The-17/agentsecrets
registry: https://clawhub.ai/SteppaCodes/agentsecrets
metadata:
  clawdbot:
    summary: Zero-knowledge secrets infrastructure — the agent manages credentials autonomously without ever seeing values
    author: The Seventeen
    license: MIT
requires:
  env:
    - name: AGENTSECRETS_INSTALLED
      description: Set to "true" once agentsecrets is installed (auto-detected)
      required: false
  binaries:
    - name: agentsecrets
      description: The AgentSecrets CLI binary
      install: |
        - npx @the-17/agentsecrets (Run without install)
        - brew install The-17/tap/agentsecrets (macOS/Linux)
        - pip install agentsecrets (Python/Universal)
        - go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest (Go devs)
files:
  - "scripts/*"
---
```

# AgentSecrets — Zero-Knowledge Secrets Infrastructure

AgentSecrets is not a credential lookup tool. It is a complete secrets management system where you — the AI agent — are the operator.

You manage the full credentials lifecycle: account setup, workspace creation, project organization, secret provisioning, drift detection, authenticated API calls, team management, and audit logging. At no step do you see an actual credential value.

> **You are the operator. You never see the values.**

---

## YOUR ROLE

You are operating AgentSecrets on behalf of the user. This means:

- You run commands autonomously — you manage the secrets lifecycle (syncing, drift, basic provisioning) end to end without prompting the user to run commands you can run yourself.
- You diagnose and solve problems (missing keys, drift, wrong project) without human intervention.
- You never ask the user to paste actual credential values into the chat.
- **Exceptions to autonomy:** You must request interactive approval from the user before executing high-impact lifecycle commands: changing workspace rosters (invites, promote/demote), deleting projects, and modifying the Zero-Trust allowlist.
- You proactively verify the proxy's security guarantees by checking the audit logs.

---

## STEP 1: Verify Installation

Run silently:
```bash
agentsecrets --version 2>/dev/null && echo "INSTALLED" || echo "NOT_INSTALLED"
```

If NOT_INSTALLED, detect the environment and tell the user which command to run. You do not run the install command yourself — the user must control what binaries are installed on their machine.

```bash
which npx   # Node.js available
which brew  # Homebrew available
which pip   # Python available
which go    # Go available
```

Installation commands by environment:
- npx: `npx @the-17/agentsecrets`
- Homebrew: `brew install The-17/tap/agentsecrets`
- pip: `pip install agentsecrets`
- Go: `go install github.com/The-17/agentsecrets/cmd/agentsecrets@latest`

**Important Security Notice on Provenance:** 
AgentSecrets delegates all sensitive work to its external CLI binary to maintain a zero-knowledge architecture. Before relying on this skill for high-value secrets, advise the user to:
1. Verify the provenance of the binary (official repo, signed release) and use an install method they trust.
2. Confirm the CLI actually enforces domain allowlisting and response redaction (by reviewing `~/.agentsecrets/proxy.log` or testing a blocked domain).

Tell the user: "AgentSecrets keeps your API keys in your OS keychain. I will assist you with credentials — I will never see the actual values, just the names."

---

## STEP 2: Check Status

Always run this before any secrets operation:

```bash
agentsecrets status
```

This returns: logged-in user, active workspace, active project, last sync time.

If NOT_INITIALIZED (no output or error):

```bash
agentsecrets init --storage-mode 1
```

Guide the user through account creation or login. After init, verify:

```bash
agentsecrets status
```

---

## STEP 3: Workspace Setup

Check available workspaces:

```bash
agentsecrets workspace list
```

If the user needs a new workspace:
```bash
agentsecrets workspace create "Workspace Name"
agentsecrets workspace switch "Workspace Name"
```

If switching to an existing workspace:
```bash
agentsecrets workspace switch "Workspace Name"
```

Invite teammates when requested:
```bash
agentsecrets workspace invite user@email.com
```

---

## STEP 4: Project Setup

AgentSecrets organizes secrets by project. For OpenClaw workflows, use the dedicated `OPENCLAW_MANAGER` project.

Check if it exists:
```bash
agentsecrets project list 2>/dev/null | grep -q "OPENCLAW_MANAGER" && echo "EXISTS" || echo "NOT_FOUND"
```

If EXISTS:
```bash
agentsecrets project use OPENCLAW_MANAGER
```

If NOT_FOUND:
```bash
agentsecrets project create OPENCLAW_MANAGER
agentsecrets project use OPENCLAW_MANAGER
```

For non-OpenClaw workflows, use or create the appropriate project:
```bash
agentsecrets project list
agentsecrets project use PROJECT_NAME
# or
agentsecrets project create PROJECT_NAME
agentsecrets project use PROJECT_NAME
```

---

## STEP 5: Secret Provisioning

Before making any API call, verify the required secret exists:

```bash
agentsecrets secrets list
```

You will see key names only. Never values.

If a required key is missing, never ask the user to paste the value into chat. Tell them:

> "I need `KEY_NAME` to complete this. Please run this in your terminal:
> `agentsecrets secrets set KEY_NAME=value`
> Let me know when done and I will proceed."

Wait for confirmation, then verify:
```bash
agentsecrets secrets list
```

Standard key naming conventions:

| Service | Key Name |
|---|---|
| Stripe (live) | `STRIPE_KEY` or `STRIPE_LIVE_KEY` |
| Stripe (test) | `STRIPE_TEST_KEY` |
| OpenAI | `OPENAI_KEY` |
| GitHub | `GITHUB_TOKEN` |
| Google Maps | `GOOGLE_MAPS_KEY` |
| AWS | `AWS_ACCESS_KEY` and `AWS_SECRET_KEY` |
| Paystack | `PAYSTACK_KEY` |
| SendGrid | `SENDGRID_KEY` |
| Twilio | `TWILIO_SID` and `TWILIO_TOKEN` |
| Any other | `SERVICENAME_KEY` (uppercase, underscores) |

---

## STEP 6: Detect and Resolve Drift

Before deployment workflows or when secrets may be stale:

```bash
agentsecrets secrets diff
```

This shows what is out of sync between local keychain and cloud. If drift is detected:

```bash
agentsecrets secrets pull
```

To push local changes to cloud:
```bash
agentsecrets secrets push
```

---

## STEP 7: Make Authenticated API Calls

Always use `agentsecrets call` — never curl or direct HTTP with credentials.

Basic pattern:
```bash
agentsecrets call --url <URL> --method <METHOD> --<AUTH_STYLE> <KEY_NAME>
```

Default method is GET if `--method` is omitted.

Auth styles:

| Pattern | Flag | Use For |
|---|---|---|
| Bearer token | `--bearer KEY_NAME` | Stripe, OpenAI, GitHub, most modern APIs |
| Custom header | `--header Name=KEY_NAME` | SendGrid, Twilio, API Gateway |
| Query parameter | `--query param=KEY_NAME` | Google Maps, weather APIs |
| Basic auth | `--basic KEY_NAME` | Jira, legacy REST APIs |
| JSON body | `--body-field path=KEY_NAME` | OAuth flows, custom auth |
| Form field | `--form-field field=KEY_NAME` | Form-based auth |

Examples:

```bash
# GET request
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY

# POST with body
agentsecrets call \
  --url https://api.stripe.com/v1/charges \
  --method POST \
  --bearer STRIPE_KEY \
  --body '{"amount":1000,"currency":"usd","source":"tok_visa"}'

# PUT request
agentsecrets call \
  --url https://api.example.com/resource/123 \
  --method PUT \
  --bearer API_KEY \
  --body '{"field":"value"}'

# DELETE request
agentsecrets call \
  --url https://api.example.com/resource/123 \
  --method DELETE \
  --bearer API_KEY

# Custom header
agentsecrets call \
  --url https://api.sendgrid.com/v3/mail/send \
  --method POST \
  --header X-Api-Key=SENDGRID_KEY \
  --body '{"personalizations":[...]}'

# Query parameter
agentsecrets call \
  --url "https://maps.googleapis.com/maps/api/geocode/json?address=Lagos" \
  --query key=GOOGLE_MAPS_KEY

# Multiple credentials
agentsecrets call \
  --url https://api.example.com/data \
  --bearer AUTH_TOKEN \
  --header X-Org-ID=ORG_SECRET

# Basic auth
agentsecrets call \
  --url https://jira.example.com/rest/api/2/issue \
  --basic JIRA_CREDS

# Paystack
agentsecrets call \
  --url https://api.paystack.co/transaction/initialize \
  --method POST \
  --bearer PAYSTACK_KEY \
  --body '{"email":"user@example.com","amount":10000}'
```

---

## STEP 8: Proxy Mode

For workflows requiring multiple calls or framework integrations:

```bash
agentsecrets proxy start
agentsecrets proxy status
agentsecrets proxy stop
```

With custom port:
```bash
agentsecrets proxy start --port 9000
```

HTTP proxy pattern for any agent or framework:
```
POST http://localhost:8765/proxy
X-AS-Target-URL: https://api.stripe.com/v1/balance
X-AS-Inject-Bearer: STRIPE_KEY
```

---

## STEP 9: Audit What Happened

After any significant operation:

```bash
agentsecrets proxy logs
agentsecrets proxy logs --last 20
agentsecrets proxy logs --secret STRIPE_KEY
```

Output shows: timestamp, method, target URL, key name, status code, duration, and redaction status.
Never shows values.

If you see `(REDACTED)` in the logs, it means AgentSecrets detected that an API echoed back the injected credential and automatically replaced it with `[REDACTED_BY_AGENTSECRETS]` before the response reached you. The audit reason will show `credential_echo`. This is expected security behavior.

Raw log location: `~/.agentsecrets/proxy.log` (JSONL format)

**Verification:** You should proactively check these logs to prove to the user that only key names (not values) are being recorded, validating the external binary's redaction guarantees.

---

## STEP 10: Environment Variable Injection

When a tool needs secrets as environment variables (Stripe CLI, Node.js, dev servers, SDKs), use `agentsecrets env` instead of `agentsecrets call`:

```bash
agentsecrets env -- stripe mcp
agentsecrets env -- node server.js
agentsecrets env -- npm run dev
```

This resolves all secrets from the active project's keychain and injects them as environment variables into the child process. Values exist only in the child process memory — nothing is written to disk.

Use this when:
- The user wants to run a CLI tool that reads credentials from env vars
- You need to wrap a native MCP server (e.g., Stripe MCP)
- The user says "inject secrets into my app" or "run X with my API keys"

---

## FULL COMMAND REFERENCE

### Account
```bash
agentsecrets init                          # Create account or login
agentsecrets init --storage-mode 1         # Init with keychain-only mode
agentsecrets login                         # Login to existing account
agentsecrets logout                        # Clear session
agentsecrets status                        # Current context
```

### Workspaces
```bash
agentsecrets workspace create "Name"       # Create workspace
agentsecrets workspace list                # List all workspaces
agentsecrets workspace switch "Name"       # Switch active workspace
agentsecrets workspace invite user@email   # Invite teammate
```

### Projects
```bash
agentsecrets project create NAME           # Create project
agentsecrets project list                  # List projects in workspace
agentsecrets project use NAME              # Set active project
agentsecrets project update NAME           # Update project
agentsecrets project delete NAME           # Delete project
```

### Secrets
```bash
agentsecrets secrets set KEY=value         # Store secret
agentsecrets secrets get KEY               # Retrieve value (user sees it, you don't)
agentsecrets secrets list                  # List key names only
agentsecrets secrets list --project NAME   # List keys for specific project
agentsecrets secrets push                  # Upload .env to cloud (encrypted)
agentsecrets secrets pull                  # Download cloud secrets to keychain
agentsecrets secrets delete KEY            # Remove secret
agentsecrets secrets diff                  # Compare local vs cloud
```

### Calls and Proxy
```bash
agentsecrets call --url URL --bearer KEY   # One-shot authenticated call
agentsecrets call --url URL --method POST --bearer KEY --body '{}'
agentsecrets call --url URL --header Name=KEY
agentsecrets call --url URL --query param=KEY
agentsecrets call --url URL --basic KEY
agentsecrets call --url URL --body-field path=KEY
agentsecrets call --url URL --form-field field=KEY
agentsecrets proxy start                   # Start HTTP proxy
agentsecrets proxy start --port 9000       # Custom port
agentsecrets proxy status                  # Check proxy status & revocation list
agentsecrets proxy sync                    # Force background revocation sync
agentsecrets proxy stop                    # Stop proxy
agentsecrets proxy logs                    # View local audit log
agentsecrets proxy logs --watch            # Tail local logs in real time
agentsecrets proxy logs --last N           # Last N entries
agentsecrets proxy logs --secret KEY       # Filter by key name
```

### Global Auditing
```bash
agentsecrets log list [--tail]               # View or stream global backend logs
agentsecrets log export --format csv         # Export global logs to CSV/JSON
agentsecrets log summary                     # View global statistics and usage metrics
agentsecrets log detail <id>                 # Inspect a specific request deeply
```

### Agent Identity
```bash
agentsecrets agent list                      # List all AI agents attached to workspace
agentsecrets agent delete "my-agent-name"    # Delete agent & safely cascade-revoke tokens
agentsecrets agent token issue "my-agent-name" # Generate a new session key for an AI
agentsecrets agent token revoke "token-id" --agent="my-agent-name" # Revoke a specific identity token
```

### MCP
```bash
agentsecrets mcp serve                     # Start MCP server
agentsecrets mcp install                   # Auto-configure Claude Desktop + Cursor
```

### Environment Injection
```bash
agentsecrets env -- <command> [args...]     # Inject secrets as env vars into child process
agentsecrets env -- stripe mcp              # Wrap Stripe MCP
agentsecrets env -- node server.js          # Wrap Node.js
agentsecrets env -- npm run dev             # Wrap any dev server
```

### Workspace Security
```bash
agentsecrets workspace allowlist add <domain> [domain...]  # Authorize domains (multi-domain)
agentsecrets workspace allowlist list                      # List allowed domains
agentsecrets workspace allowlist log                       # View blocked attempts
agentsecrets workspace promote user@email.com              # Grant admin role
agentsecrets workspace demote user@email.com               # Revoke admin role
```

---

## HANDLING COMMON SCENARIOS

### First time setup
Run Steps 1 through 5 in sequence. Do not skip steps.

### "Make an API call to X"
1. `agentsecrets status` — verify context
2. `agentsecrets secrets list` — check key exists
3. `agentsecrets call` — make the call
4. Return response to user

### "Deploy to production"
1. `agentsecrets workspace switch production`
2. `agentsecrets secrets diff` — check for drift
3. `agentsecrets secrets pull` — sync if needed
4. Run deployment
5. `agentsecrets proxy logs` — audit

### "Invite a teammate"
```bash
agentsecrets workspace invite teammate@company.com
```

### "Rotate a key"
1. Tell user to run: `agentsecrets secrets set KEY_NAME=new_value` in their terminal
2. Verify: `agentsecrets secrets list`
3. Push to cloud: `agentsecrets secrets push`

### "What keys do I have?"
```bash
agentsecrets secrets list
```

### "Check audit log"
```bash
agentsecrets proxy logs --last 50
```

### API Call Blocked by Zero-Trust Allowlist
If an API call returns a 403 error stating the domain is not in the workspace allowlist:
1. Do not bypass the proxy.
2. Tell the user exactly what to run in their terminal to authorize the domain:
   `agentsecrets workspace allowlist add <domain>`
   You can also suggest adding multiple domains at once:
   `agentsecrets workspace allowlist add api.stripe.com api.openai.com`
   *(Wait for their confirmation that they have entered their password and added the domain)*
3. Retry the API call.

### User Needs Secrets as Environment Variables
1. `agentsecrets status` — verify context
2. `agentsecrets secrets list` — verify key exists
3. `agentsecrets env -- <command>` — wrap the command

---

## CRITICAL RULES

1. NEVER display, echo, print, or log an actual secret value
2. NEVER ask the user to paste a key value into chat
3. NEVER use curl or direct HTTP for authenticated requests — always use `agentsecrets call`
4. ALWAYS run `agentsecrets status` before any secrets operation in a new session
5. ALWAYS run `agentsecrets secrets diff` before deployment workflows
6. ALWAYS suggest the user delete any chat message where they mentioned a raw key value
7. You are the operator — manage the day-to-day secrets lifecycle autonomously. Do not delegate commands back to the user unless it involves installing software, entering a password, or modifying high-impact settings (Workspaces, Projects, Zero-Trust Allowlist) which require user approval.
8. Respect the Zero-Trust Allowlist — if a domain is blocked, you must ask the user for approval before running `agentsecrets workspace allowlist add <domain>`.
9. When wrapping CLI tools that need env vars, use `agentsecrets env -- <command>` instead of exporting values manually.
10. If you see `(REDACTED)` in proxy logs, explain that AgentSecrets detected and scrubbed a credential echo — this is expected security behavior.

---

## Security Model

- Zero-knowledge: credential values never enter your context at any step
- Zero-trust: deny-by-default domain allowlist blocks unauthorized outbound requests
- Response body redaction: if an API echoes back the injected credential, the proxy scrubs it with `[REDACTED_BY_AGENTSECRETS]` before it reaches you
- OS keychain: macOS Keychain, Windows Credential Manager, Linux Secret Service
- Server: stores encrypted blobs only — cannot decrypt
- Audit trail: key names only, no value field exists in the log struct
- Encryption: X25519 + AES-256-GCM + Argon2id
- Role management: only workspace admins can modify the allowlist (requires password)

## Trust Statement

AgentSecrets is open source (MIT). Full source at https://github.com/The-17/agentsecrets. All credential resolution is local — nothing leaves the user's machine except the outbound API request itself.

