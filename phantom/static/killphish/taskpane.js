/*
 * Kill Phish — Outlook Add-in Taskpane Logic
 *
 * Flow:
 *   1. Office.onReady() — loads email subject/from into preview
 *   2. reportPhishing() — gets full .eml via getAsFileAsync(), POSTs to Phantom
 *   3. setState('success') — shows confirmation + report ID
 *
 * Phantom endpoint: POST /api/webhook/phishing-report
 * Returns immediately with {report_id, status: "investigating"}
 * Investigation result is emailed to the reporter when complete.
 */

"use strict";

// Phantom base URL — injected at build time or set as a global by the manifest.
// Falls back to same-origin (works when taskpane is served from Phantom itself).
const PHANTOM_URL = window.PHANTOM_BASE_URL || "";
const FALLBACK_EMAIL = window.PHISHING_FALLBACK_EMAIL || "phishing@corp.com";

let _reporterEmail = "";
let _emailSubject  = "";
let _reportId      = "";

// ── Office initialisation ────────────────────────────────────────────────────

Office.onReady(function (info) {
  if (info.host !== Office.HostType.Outlook) {
    showError("This add-in only works in Outlook.", "");
    return;
  }

  document.getElementById("fallback-address").textContent = FALLBACK_EMAIL;

  const item = Office.context.mailbox.item;

  // Reporter = the logged-in user's email
  _reporterEmail = Office.context.mailbox.userProfile.emailAddress || "";

  // Populate preview
  _emailSubject = item.subject || "(no subject)";
  document.getElementById("preview-subject").textContent = _emailSubject;

  item.from.getAsync(function (result) {
    if (result.status === Office.AsyncResultStatus.Succeeded) {
      const from = result.value;
      document.getElementById("preview-from").textContent =
        from.displayName ? `${from.displayName} <${from.emailAddress}>` : from.emailAddress;
    }
  });
});


// ── State machine ─────────────────────────────────────────────────────────────

function setState(state) {
  ["idle", "sending", "success", "error"].forEach(function (s) {
    document.getElementById("state-" + s).classList.remove("active");
  });
  document.getElementById("state-" + state).classList.add("active");
}

function showError(message, detail) {
  document.getElementById("error-detail").textContent = detail || "";
  document.querySelector("#state-error p").innerHTML =
    message + ' Forward manually to <strong id="fallback-address">' + FALLBACK_EMAIL + "</strong>.";
  setState("error");
}

function showSuccess(reportId) {
  const el = document.getElementById("success-info");
  el.innerHTML = [
    row("Report ID",   reportId),
    row("Reported by", _reporterEmail || "unknown"),
    row("Status",      "Investigating…"),
  ].join("");
  setState("success");
}

function row(key, val) {
  return '<div class="row"><span class="key">' + key +
         '</span><span class="val">' + escHtml(val) + "</span></div>";
}

function escHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}


// ── Core reporting function ──────────────────────────────────────────────────

function reportPhishing() {
  setState("sending");
  document.getElementById("btn-report").disabled = true;

  const item = Office.context.mailbox.item;

  // Prefer getAsFileAsync (Requirement Set 1.9) — gives full RFC 2822 .eml
  if (item.getAsFileAsync) {
    item.getAsFileAsync({ asyncContext: null }, function (result) {
      if (result.status !== Office.AsyncResultStatus.Succeeded) {
        // Fall back to metadata-only report
        reportWithMetadata(item);
        return;
      }
      // result.value is a base64-encoded .eml string
      submitToPhantom({ email_base64: result.value });
    });
  } else {
    // Older Outlook — fall back to metadata + body
    reportWithMetadata(item);
  }
}


// Fallback: collect available fields if getAsFileAsync is not supported
function reportWithMetadata(item) {
  item.body.getAsync(Office.CoercionType.Html, function (bodyResult) {
    const body = bodyResult.status === Office.AsyncResultStatus.Succeeded
      ? bodyResult.value
      : "(body unavailable)";

    item.from.getAsync(function (fromResult) {
      const fromEmail = fromResult.status === Office.AsyncResultStatus.Succeeded
        ? fromResult.value.emailAddress
        : "";
      const fromName  = fromResult.status === Office.AsyncResultStatus.Succeeded
        ? fromResult.value.displayName
        : "";

      // Build a minimal RFC 2822-style email string
      const fakeEml = [
        "From: " + (fromName ? fromName + " <" + fromEmail + ">" : fromEmail),
        "To: " + (_reporterEmail || "unknown"),
        "Subject: " + _emailSubject,
        "Date: " + new Date().toUTCString(),
        "Content-Type: text/html; charset=utf-8",
        "",
        body,
      ].join("\r\n");

      submitToPhantom({ raw_email: fakeEml });
    });
  });
}


// POST to Phantom's webhook
function submitToPhantom(payload) {
  const endpoint = PHANTOM_URL + "/api/webhook/phishing-report";
  const body = Object.assign(
    {
      reported_by: _reporterEmail,
      source:      "kill-phish-outlook",
    },
    payload
  );

  fetch(endpoint, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  })
    .then(function (resp) {
      if (!resp.ok) {
        return resp.text().then(function (t) {
          throw new Error("HTTP " + resp.status + ": " + t.slice(0, 200));
        });
      }
      return resp.json();
    })
    .then(function (data) {
      _reportId = data.report_id || "";
      showSuccess(_reportId);
    })
    .catch(function (err) {
      showError(
        "Could not reach Phantom. Please forward the email manually to",
        err.message || String(err)
      );
    });
}
