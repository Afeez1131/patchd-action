# Patchd Security Scan

AI-powered security scanning for every pull request. Finds vulnerabilities before they ship — SQL injection, hardcoded secrets, missing auth, and more — explained in plain English with exact fixes.

## Usage

```yaml
# .github/workflows/patchd.yml
name: Patchd Security Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  patchd-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: Afeez1131/patchd-action@v1
        with:
          api_key: ${{ secrets.PATCHD_API_KEY }}
```

That's it. Patchd scans every changed file in the PR, posts findings as review comments, and sets a pass/fail check.

## Setup

1. Go to [patchd.dev](https://patchd.dev) → **Settings → API Keys** → Create a key
2. In your GitHub repo: **Settings → Secrets and variables → Actions → New secret**
   - Name: `PATCHD_API_KEY`
   - Value: `patchd_xxxx` (the key from step 1)
3. Copy the workflow above into `.github/workflows/patchd.yml`

Done. Every future PR will be scanned automatically.

## What you get on each PR

**Per-file comments** for any file with issues:

> ## 🔍 Patchd Security Scan — `src/auth/login.py`
>
> ### 🚨 Critical Issues (1)
>
> **SQL Injection**
> > **What:** User input is concatenated directly into the SQL query
> > **How:** Attacker sends `'; DROP TABLE users; --`
> > **Impact:** Full database compromise
> > **Fix:** `Use parameterized queries: cursor.execute("...", (user_id,))`

**Summary table** across all scanned files:

| File | Critical | Warnings | Best Practices |
|------|----------|----------|----------------|
| `src/auth/login.py` | 🚨 1 | ⚠️ 2 | 💡 1 |
| `src/api/users.py` | ✅ 0 | ⚠️ 1 | 💡 2 |

**Check Run** — green ✅ or red ❌ badge on the PR itself.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_key` | ✅ Yes | — | Your Patchd API key |
| `fail_on_critical` | No | `true` | Block merge when critical issues found |
| `max_files` | No | `15` | Max files to scan per PR |
| `file_extensions` | No | `.py,.js,.ts,.go,.java,.php,.rb,.rs,...` | Extensions to scan |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical issues found |
| `warnings_count` | Number of warnings found |

Use outputs in downstream steps:

```yaml
- uses: Afeez1131/patchd-action@v1
  id: patchd
  with:
    api_key: ${{ secrets.PATCHD_API_KEY }}
    fail_on_critical: false   # report-only, never blocks

- name: Comment count
  run: echo "Found ${{ steps.patchd.outputs.critical_count }} critical issues"
```

## Report-only mode

To scan and report without ever blocking a merge:

```yaml
- uses: Afeez1131/patchd-action@v1
  with:
    api_key: ${{ secrets.PATCHD_API_KEY }}
    fail_on_critical: false
```

## Supported languages

Python · JavaScript · TypeScript · Go · Java · PHP · Ruby · Rust · Bash · SQL · C · C++ · C# · Swift · Kotlin

---

Built by [Patchd](https://patchd.dev) — AI security scanning for founders
