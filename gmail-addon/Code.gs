/**
 * Kill Phish — Gmail Add-on
 * Powered by Phantom Security Platform
 *
 * When an employee clicks "Kill Phish" while reading an email, this add-on:
 *   1. Extracts the full raw email (headers + body) via getRawContent()
 *   2. POSTs it to Phantom's /api/webhook/phishing-report endpoint
 *   3. Shows a confirmation card — Phantom emails the verdict asynchronously
 *
 * Deploy via Google Workspace Admin:
 *   Admin Console → Apps → Google Workspace Marketplace → Deploy Private App
 *   Or: script.google.com → Deploy → New deployment → Add-on
 *
 * Configuration — set these Script Properties in Apps Script:
 *   PHANTOM_URL          — https://phantom.corp.com  (no trailing slash)
 *   PHANTOM_API_KEY      — optional bearer token (blank if no auth)
 *   PHISHING_LABEL       — Gmail label to apply after reporting (default: "Reported-Phishing")
 *   MOVE_TO_TRASH        — "true" to move email to trash after reporting (default: "false")
 */

// ── Configuration ─────────────────────────────────────────────────────────────

var CONFIG = {
  get PHANTOM_URL()   { return getScriptProp("PHANTOM_URL",    "https://phantom.corp.com"); },
  get API_KEY()       { return getScriptProp("PHANTOM_API_KEY", ""); },
  get LABEL_NAME()    { return getScriptProp("PHISHING_LABEL", "Reported-Phishing"); },
  get MOVE_TO_TRASH() { return getScriptProp("MOVE_TO_TRASH",  "false") === "true"; },
};

function getScriptProp(key, fallback) {
  var val = PropertiesService.getScriptProperties().getProperty(key);
  return val || fallback;
}


// ── Card builder — shown when reading any email ───────────────────────────────

function buildKillPhishCard(e) {
  var messageId = e.gmail ? e.gmail.messageId : null;
  var subject   = "";
  var fromAddr  = "";

  // Load preview metadata if we have a message ID
  if (messageId) {
    try {
      var accessToken = e.gmail.accessToken;
      GmailApp.setCurrentMessageAccessToken(accessToken);
      var msg = GmailApp.getMessageById(messageId);
      subject  = msg.getSubject()  || "(no subject)";
      fromAddr = msg.getFrom()     || "";
    } catch (err) {
      // Continue — preview is non-critical
    }
  }

  var header = CardService.newCardHeader()
    .setTitle("Kill Phish")
    .setSubtitle("Powered by Phantom")
    .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_white_48dp.png")
    .setImageAltText("Kill Phish");

  // Email preview section
  var previewSection = CardService.newCardSection();

  if (subject) {
    previewSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Email Subject")
        .setText(subject)
        .setWrapText(true)
    );
  }
  if (fromAddr) {
    previewSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("From")
        .setText(fromAddr)
        .setWrapText(true)
    );
  }

  // Warning
  previewSection.addWidget(
    CardService.newTextParagraph().setText(
      "<font color=\"#d97706\"><b>⚠️ Do not click any links or open attachments</b></font>" +
      "<br>Report this email and our security team will investigate immediately."
    )
  );

  // Report button
  var reportAction = CardService.newAction()
    .setFunctionName("onReportClicked")
    .setParameters({ messageId: messageId || "" });

  previewSection.addWidget(
    CardService.newTextButton()
      .setText("🎣  Report This Email")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor("#dc2626")
      .setOnClickAction(reportAction)
  );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(previewSection)
    .build();
}


// Homepage card (shown outside email context)
function buildHomepage(e) {
  var header = CardService.newCardHeader()
    .setTitle("Kill Phish")
    .setSubtitle("Phantom Security Platform")
    .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_white_48dp.png");

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Open any email you want to report, then click <b>Kill Phish</b> " +
        "to send it to the security team for investigation."
      )
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}


// ── Report action ─────────────────────────────────────────────────────────────

function onReportClicked(e) {
  var messageId = e.parameters.messageId;

  if (!messageId) {
    return _errorCard("No message selected.", "Open an email first, then click Kill Phish.");
  }

  var reporterEmail = Session.getEffectiveUser().getEmail();
  var rawEmail      = "";
  var subject       = "";
  var fromAddr      = "";
  var msgIdHeader   = "";
  var thread        = null;
  var gmailMsg      = null;

  // Fetch raw email content
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail ? e.gmail.accessToken : "");
    gmailMsg    = GmailApp.getMessageById(messageId);
    rawEmail    = gmailMsg.getRawContent();
    subject     = gmailMsg.getSubject()  || "";
    fromAddr    = gmailMsg.getFrom()     || "";
    msgIdHeader = gmailMsg.getHeader("Message-ID") || "";
    thread      = gmailMsg.getThread();
  } catch (err) {
    // getRawContent failed — fall back to structured fields
    try {
      gmailMsg  = GmailApp.getMessageById(messageId);
      subject   = gmailMsg.getSubject()  || "";
      fromAddr  = gmailMsg.getFrom()     || "";
      rawEmail  = _buildFallbackEml(gmailMsg);
    } catch (err2) {
      return _errorCard(
        "Could not read email content.",
        "Please forward the email manually to phishing@corp.com.\n\nError: " + err2.message
      );
    }
  }

  // POST to Phantom
  var payload = {
    raw_email:        rawEmail,
    reported_by:      reporterEmail,
    source:           "gmail-addon",
    message_id:       msgIdHeader,
    gmail_message_id: messageId,
  };

  var result = _callPhantom(payload);

  if (!result.success) {
    return _errorCard(
      "Could not reach Phantom.",
      result.error + "\n\nPlease forward to phishing@corp.com manually."
    );
  }

  // Apply label and optionally trash
  _applyPhishingLabel(gmailMsg, thread);

  return _successCard(result.data, subject, fromAddr, reporterEmail);
}


// ── Phantom API call ──────────────────────────────────────────────────────────

function _callPhantom(payload) {
  var url     = CONFIG.PHANTOM_URL + "/api/webhook/phishing-report";
  var headers = { "Content-Type": "application/json" };
  if (CONFIG.API_KEY) {
    headers["Authorization"] = "Bearer " + CONFIG.API_KEY;
  }

  try {
    var resp = UrlFetchApp.fetch(url, {
      method:             "post",
      contentType:        "application/json",
      payload:            JSON.stringify(payload),
      headers:            headers,
      muteHttpExceptions: true,
      followRedirects:    true,
    });

    var code = resp.getResponseCode();
    var body = resp.getContentText();

    if (code >= 200 && code < 300) {
      return { success: true, data: JSON.parse(body) };
    }
    return { success: false, error: "HTTP " + code + ": " + body.slice(0, 200) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}


// ── Gmail post-report actions ─────────────────────────────────────────────────

function _applyPhishingLabel(msg, thread) {
  if (!msg) return;
  try {
    var labelName = CONFIG.LABEL_NAME;
    var label = GmailApp.getUserLabelByName(labelName);
    if (!label) {
      label = GmailApp.createLabel(labelName);
    }
    if (thread) {
      thread.addLabel(label);
    }
    if (CONFIG.MOVE_TO_TRASH && thread) {
      thread.moveToTrash();
    }
  } catch (err) {
    // Non-fatal — labelling is a convenience, not required
    Logger.log("Label error: " + err.message);
  }
}


// ── Card helpers ──────────────────────────────────────────────────────────────

function _successCard(data, subject, fromAddr, reporter) {
  var reportId  = data.report_id  || "unknown";
  var statusUrl = CONFIG.PHANTOM_URL + "/api/webhook/phishing-report/" + reportId;

  var header = CardService.newCardHeader()
    .setTitle("✅ Email Reported!")
    .setSubtitle("Phantom is investigating");

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Your report has been received. Phantom is investigating now.\n\n" +
        "<b>We will email you the verdict and next steps.</b>"
      )
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Report ID")
        .setText(reportId)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Reported by")
        .setText(reporter)
    )
    .addWidget(CardService.newDivider())
    .addWidget(
      CardService.newTextParagraph().setText(
        "<font color=\"#166534\"><b>While you wait:</b></font>\n" +
        "• Do <b>not</b> click any links in that email\n" +
        "• Do <b>not</b> open any attachments\n" +
        "• Check your inbox for Phantom's investigation result"
      )
    );

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(
        CardService.newCardBuilder()
          .setHeader(header)
          .addSection(section)
          .build()
      )
    )
    .build();
}


function _errorCard(title, detail) {
  var header = CardService.newCardHeader()
    .setTitle("⚠️ " + title)
    .setSubtitle("Kill Phish");

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(detail))
    .addWidget(
      CardService.newTextButton()
        .setText("Forward manually to phishing@corp.com")
        .setOpenLink(
          CardService.newOpenLink()
            .setUrl("mailto:phishing@corp.com")
            .setOpenAs(CardService.OpenAs.OVERLAY)
        )
    );

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(
        CardService.newCardBuilder()
          .setHeader(header)
          .addSection(section)
          .build()
      )
    )
    .build();
}


// Reconstruct a minimal RFC 2822 email when getRawContent() fails
function _buildFallbackEml(msg) {
  var lines = [
    "From: "        + (msg.getFrom()    || ""),
    "To: "          + (msg.getTo()      || ""),
    "Subject: "     + (msg.getSubject() || ""),
    "Date: "        + (msg.getDate()    ? msg.getDate().toUTCString() : ""),
    "Message-ID: "  + (msg.getHeader("Message-ID") || ""),
    "Content-Type: text/html; charset=utf-8",
    "",
    msg.getBody() || "(body unavailable)",
  ];
  return lines.join("\r\n");
}
