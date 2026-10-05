"use strict";

const sanitizeForm = document.getElementById("sanitize-form");
const sanitizeButton = document.getElementById("sanitize-button");
const statusMessage = document.getElementById("status-message");
const securityTeamNotice = document.getElementById("security-team-notice");
const incidentReport = document.getElementById("incident-report");
const incidentReportText = document.getElementById("incident-report-text");
const copyReportButton = document.getElementById("copy-report-button");
const copyReportStatus = document.getElementById("copy-report-status");
const dropZone = document.getElementById("drop-zone");
const documentInput = document.getElementById("document-input");

function showStatus(message, type = "") {
  if (!statusMessage) return;
  statusMessage.textContent = message;
  statusMessage.className = `message ${type}`.trim();
  statusMessage.hidden = false;
}

function responseFilename(response) {
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return match ? match[1] : "clean-document";
}

function safeReportValue(value, fallback = "Unavailable") {
  const normalized = String(value || "").replace(/[\r\n]+/g, " ").trim();
  return normalized || fallback;
}

function showIncidentReport(report) {
  if (!incidentReport || !incidentReportText) return;
  incidentReportText.value = report;
  incidentReport.hidden = false;
  if (copyReportStatus) copyReportStatus.hidden = true;
}

if (copyReportButton && incidentReportText) {
  copyReportButton.addEventListener("click", async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(incidentReportText.value);
      } else {
        incidentReportText.select();
        if (!document.execCommand("copy")) throw new Error("Copy was not available");
      }
      if (copyReportStatus) {
        copyReportStatus.textContent = "Report copied.";
        copyReportStatus.hidden = false;
      }
    } catch (_error) {
      incidentReportText.focus();
      incidentReportText.select();
      if (copyReportStatus) {
        copyReportStatus.textContent = "Select the report and copy it manually.";
        copyReportStatus.hidden = false;
      }
    }
  });
}

function setDroppedFile(file) {
  if (!documentInput || !file) return;
  const transfer = new DataTransfer();
  transfer.items.add(file);
  documentInput.files = transfer.files;
  documentInput.dispatchEvent(new Event("change", { bubbles: true }));
}

if (dropZone && documentInput) {
  for (const eventName of ["dragenter", "dragover"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
      dropZone.classList.add("dragging");
    });
  }

  dropZone.addEventListener("dragleave", (event) => {
    event.preventDefault();
    if (!dropZone.contains(event.relatedTarget)) dropZone.classList.remove("dragging");
  });

  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
    setDroppedFile(event.dataTransfer?.files?.[0]);
  });
}

if (sanitizeForm && sanitizeButton) {
  sanitizeForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (statusMessage) statusMessage.hidden = true;
    if (securityTeamNotice) securityTeamNotice.hidden = true;
    if (incidentReport) incidentReport.hidden = true;
    if (incidentReportText) incidentReportText.value = "";
    if (copyReportStatus) copyReportStatus.hidden = true;
    sanitizeButton.disabled = true;
    sanitizeButton.textContent = "Scanning and rebuilding…";
    const originalFile = documentInput?.files?.[0];

    try {
      const response = await fetch(sanitizeForm.action, {
        method: "POST",
        body: new FormData(sanitizeForm),
      });

      if (!response.ok) {
        const errorPage = new DOMParser().parseFromString(await response.text(), "text/html");
        const serverMessage = errorPage.querySelector(".message")?.textContent?.trim();
        const discardNotice = errorPage.querySelector(".discard-notice")?.textContent?.trim();
        const securityTeamNoticeText = errorPage.querySelector(".security-team-notice:not([hidden])")?.textContent?.trim();
        const rejectionReport = errorPage.querySelector("#incident-report-text")?.value?.trim();
        if (securityTeamNoticeText && securityTeamNotice) securityTeamNotice.hidden = false;
        if (rejectionReport) showIncidentReport(rejectionReport);
        throw new Error(
          [serverMessage, discardNotice].filter(Boolean).join(" ") || "The document could not be sanitized.",
        );
      }

      const findings = response.headers.get("X-Sanitization-Findings")?.trim();
      const cleanFilename = responseFilename(response);
      const download = document.createElement("a");
      const objectUrl = URL.createObjectURL(await response.blob());
      download.href = objectUrl;
      download.download = cleanFilename;
      download.hidden = true;
      document.body.appendChild(download);
      download.click();
      download.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);

      sanitizeForm.reset();
      dropZone?.classList.remove("dragging");
      if (findings) {
        showStatus(`Document cleaned and downloaded. Issues found and removed: ${findings}.`, "success");
        if (securityTeamNotice) securityTeamNotice.hidden = false;
        showIncidentReport(
          [
            "Document Sanitizer Incident Report",
            `Detection time (UTC): ${safeReportValue(response.headers.get("X-Sanitization-Time"))}`,
            `Original filename: ${safeReportValue(originalFile?.name, "document")}`,
            `Original size: ${safeReportValue(response.headers.get("X-Original-Size"), String(originalFile?.size || "Unavailable"))} bytes`,
            `Original SHA-256: ${safeReportValue(response.headers.get("X-Original-SHA256"))}`,
            `Cleaned filename: ${safeReportValue(cleanFilename)}`,
            `Cleaned SHA-256: ${safeReportValue(response.headers.get("X-Clean-SHA256"))}`,
            "Outcome: Active or potentially unsafe elements were removed; a cleaned copy was downloaded",
            `Issues found and removed: ${safeReportValue(findings)}`,
            "Recommended action: The original document should be sent to your IT or security team for further analysis.",
          ].join("\n"),
        );
      } else {
        showStatus(
          "Document cleaned and downloaded. No active content was detected; the rebuilt document passed antivirus scanning.",
          "success",
        );
      }
    } catch (error) {
      showStatus(error instanceof Error ? error.message : "The document could not be sanitized.", "danger");
    } finally {
      sanitizeButton.disabled = false;
      sanitizeButton.textContent = "Clean and download";
    }
  });
}
