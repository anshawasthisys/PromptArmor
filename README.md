# PromptArmor
Real-time inline firewall &amp; DOM interception proxy protecting AI web agents from indirect prompt injections.

Optional local semantic backend (Step 11): a localhost FastAPI service at `http://127.0.0.1:8000` may enrich already-flagged snippets. The in-page firewall remains authoritative for score, risk level, and sanitization. The backend is skipped when unavailable.
