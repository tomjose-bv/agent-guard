# 60-second demo recording script

**Setup before recording:** run `scripts\setup.ps1` once. Delete `.agent-guard\` for a clean log. Open two terminals side by side, with the repo as the working directory and the venv activated. Use a large font.

| Time | On screen | Say (roughly) |
|---|---|---|
| 0:00–0:07 | `agent-guard.yaml` and `examples/policies/demo.yaml` in an editor | "AI agents with tool access can delete files or move money. agent-guard is an MCP proxy that enforces a YAML policy on every tool call." |
| 0:07–0:12 | Terminal A: `python examples\demo_agent.py --approve manual` | "Here's a scripted agent calling a files server and a fake payments server through agent-guard." |
| 0:12–0:22 | Output scrolls: ALLOWED write, DENIED `../escape.txt`, DENIED delete | "Normal writes go through. Writing outside `notes/` is denied, and delete is blocked outright. It isn't even listed to the agent." |
| 0:22–0:32 | REDACTED lines: card number on disk, customer lookup | "PII is redacted both ways: the card number never reaches the file, and phone and card numbers are stripped from results." |
| 0:32–0:38 | DENIED rate limit, refund 900, `DROP TABLE` customer id | "Rate limits, amount caps and regex constraints. The agent gets a clear reason as a normal tool error." |
| 0:38–0:50 | Agent pauses at "approval … pending". Terminal B: `agent-guard ui` → browser → click **Approve** (or `agent-guard approve <id>`) | "A 250 refund needs a human. It waits in the queue, I approve it in the local viewer, and the call completes. No answer before the timeout means deny." |
| 0:50–0:57 | Viewer table filtered by decision = denied; then Terminal B: `agent-guard verify-log` → "hash chain intact" | "Every decision is in an append-only, hash-chained log, so tampering is detectable." |
| 0:57–1:00 | README benchmark table | "It adds a few milliseconds per call; the numbers are measured and in the README. MIT licensed. Link below." |

**Tips:** if the viewer is open before the approval appears, it refreshes every 2 s. Use `--approve auto` for a hands-free take.
