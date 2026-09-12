/**
 * PromptArmor background network adapter (Step 11).
 * Dumb localhost proxy only: health + analyze. No DOM, scoring, sanitization, or storage.
 */

const BACKEND_ORIGIN = "http://127.0.0.1:8000";
const BACKEND_TIMEOUT_MS = 2000;
const BACKEND_MAX_ANALYZE_TEXT = 4000;

let analyzeAbortController = null;
let analyzeInFlight = false;

function buildResult(ok, extra) {
  const result = { ok: !!ok };
  if (extra && typeof extra === "object") {
    const keys = Object.keys(extra);
    for (let i = 0; i < keys.length; i++) {
      result[keys[i]] = extra[keys[i]];
    }
  }
  return result;
}

function capAnalyzeText(text) {
  if (typeof text !== "string") return "";
  if (text.length <= BACKEND_MAX_ANALYZE_TEXT) return text;
  return text.slice(0, BACKEND_MAX_ANALYZE_TEXT);
}

function normalizeAnalyzePayload(payload) {
  const body = payload && typeof payload === "object" ? payload : {};
  const localSignals = body.localSignals && typeof body.localSignals === "object"
    ? body.localSignals
    : {};
  return {
    text: capAnalyzeText(body.text),
    source: "webpage",
    localSignals: localSignals
  };
}

function abortInFlightAnalyze() {
  if (analyzeAbortController) {
    try { analyzeAbortController.abort(); } catch (_) {}
    analyzeAbortController = null;
  }
  analyzeInFlight = false;
}

function fetchAnalyze(url, options) {
  abortInFlightAnalyze();
  const controller = new AbortController();
  analyzeAbortController = controller;
  analyzeInFlight = true;

  const timer = setTimeout(() => {
    try { controller.abort(); } catch (_) {}
  }, BACKEND_TIMEOUT_MS);

  const fetchOptions = {
    method: options.method,
    headers: options.headers,
    body: options.body,
    signal: controller.signal
  };

  return fetch(url, fetchOptions)
    .then((res) => {
      return res.text().then((bodyText) => {
        if (!res.ok) {
          return buildResult(false, { error: "http_error", status: res.status });
        }
        let data = null;
        if (bodyText) {
          try {
            data = JSON.parse(bodyText);
          } catch (_) {
            return buildResult(false, { error: "malformed_json", status: res.status });
          }
        }
        return buildResult(true, { data: data, status: res.status });
      });
    })
    .catch((err) => {
      const aborted = !!(err && (err.name === "AbortError" || /abort/i.test(String(err && err.message || err))));
      return buildResult(false, { error: aborted ? "timeout" : "network_error" });
    })
    .then((result) => {
      clearTimeout(timer);
      if (analyzeAbortController === controller) {
        analyzeAbortController = null;
        analyzeInFlight = false;
      }
      return result;
    });
}

function handleAnalyze(payload) {
  const normalized = normalizeAnalyzePayload(payload);
  return fetchAnalyze(
    BACKEND_ORIGIN + "/analyze",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(normalized)
    }
  );
}

function handleAbort() {
  abortInFlightAnalyze();
  return buildResult(true, { aborted: true });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message !== "object" || typeof message.type !== "string") {
    sendResponse(buildResult(false, { error: "invalid_message" }));
    return false;
  }

  if (message.type === "PROMPTARMOR_ABORT") {
    sendResponse(handleAbort());
    return false;
  }

  if (message.type === "PROMPTARMOR_ANALYZE") {
    if (analyzeInFlight) {
      abortInFlightAnalyze();
    }
    handleAnalyze(message.payload).then(sendResponse);
    return true;
  }

  return false;
});
