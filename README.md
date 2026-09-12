# PromptArmor
Real-time inline firewall &amp; DOM interception proxy protecting AI web agents from indirect prompt injections.

Optional semantic backend (Step 11): FastAPI at `http://172.18.239.233:8000` (configurable in `extension/background.js`; falls back to `http://127.0.0.1:8000`). The in-page firewall remains authoritative for score, risk level, and sanitization. The backend is skipped when unavailable.
