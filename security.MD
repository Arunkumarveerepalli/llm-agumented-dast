Security notes

This project is a defensive research tool. It is designed to be pointed only at DVWA and OWASP Juice Shop instances the operator owns and runs locally (e.g. via Docker). Do not point it at any system you do not have explicit authorization to test.

Practices followed in this repo
Credentials are never passed as CLI arguments or hardcoded. They are read from environment variables (via .env, which is gitignored) so they never appear in shell history, ps aux output, or source control.
.env is gitignored; .env.example documents required variables without real values.
Session cookies are held in memory only (requests.Session) for the duration of a single run and are never written to disk or logged.
Verbose logging logs URLs and page counts, not request/response bodies, so credentials and session tokens are never written to log files.
Generated scan/recon output (data/*.json) is gitignored by default, since it reflects internal structure of the target application.
Before pushing to a public remote
Run git log --all --full-history -- .env — if this returns anything, .env was committed at some point and needs history rewritten (git filter-repo or BFG Repo-Cleaner), not just deleted going forward.
Run a secrets scanner over the full history, not just the working tree — e.g. gitleaks detect --source . -v or trufflehog git file://.
Run pip-audit against requirements.txt and address any known-vulnerable dependency versions before submission.
Not implemented, and why
Row-level security — this is a database access-control pattern for multi-tenant systems. This project has no shared database with per-user rows, so RLS has nothing to secure. Would become relevant only if a multi-user results dashboard is added later.
Encryption at rest for scan output — DVWA/Juice Shop are intentionally vulnerable practice applications with public, documented default credentials; the JSON output describes a test app's structure, not real user data, so at-rest encryption would add complexity without a real threat it defends against in this project's scope.