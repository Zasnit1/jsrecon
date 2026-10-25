# jsrecon

Pull the **endpoints, API paths and accidentally-leaked secrets** out of JavaScript files you already have on disk.

Front-end bundles are full of forgotten `/internal/...` routes and, too often, a hard-coded API key someone meant to remove. jsrecon finds both, fast.

- Single file, **Python standard library only** (3.9+). No installs, no API keys.
- **Offline.** It reads files (or stdin). It never connects to any host. *You* fetch the script; jsrecon parses it.
- Secrets are **redacted** in the output, so a report is safe to paste into a ticket.
- CI-friendly: `--fail-on-secret` returns a non-zero exit code, so it works as a pre-commit or pipeline guard.

> Only scan files from applications you own or are authorised to review.

## Quick start

```bash
git clone https://github.com/Zasnit1/jsrecon.git
cd jsrecon
python3 jsrecon.py app.min.js
```

```
POSSIBLE SECRETS (2) - verify and rotate if real:
  app.min.js:4  stripe_secret: Stripe live secret key  ->  sk_l***qrst
  app.min.js:5  github_token: GitHub token  ->  ghp_***yzAB

ENDPOINTS / PATHS (3):
  /api/v3/orders    (app.min.js:2)
  /internal/invoices/export    (app.min.js:3)
  https://api.shop.example/v3    (app.min.js:1)
```

You do the fetching; jsrecon stays offline:

```bash
curl -s https://your-site.example/main.js | python3 jsrecon.py -
```

## What it finds

**Endpoints & paths** — absolute URLs, quoted absolute paths (`"/api/v2/users"`), and the targets of `fetch`, `axios.*`, and `url:` / `baseURL:` assignments. Static assets (images, fonts, CSS, source maps) are filtered out so the list stays signal.

**Possible secrets** — specific patterns for AWS access keys, Google API keys, Slack and GitHub tokens, Stripe live/test keys, JWTs, private-key blocks, Google OAuth client ids, and generic `apiKey = "..."` / `secret: "..."` assignments.

Every secret hit is a **candidate to verify and rotate**, not a confirmed live credential. The patterns favour precision, but no regex is perfect — confirm before acting, and never paste a real key back into a public issue.

## Usage

```bash
python3 jsrecon.py FILE [FILE ...] [--kind all|endpoints|secrets] [--format text|json] [--fail-on-secret]
```

### Pre-commit guard

```bash
# fail the commit if a secret pattern appears in staged JS
python3 jsrecon.py $(git diff --cached --name-only --diff-filter=ACM -- '*.js') --kind secrets --fail-on-secret
```

## Tests

```bash
python3 -m pytest -q
```

## License

MIT, see [LICENSE](LICENSE).

Built by Ibrahim Maqtoush with AI assistance. Issues and pull requests welcome.
