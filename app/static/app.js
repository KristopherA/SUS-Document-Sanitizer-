"use strict";

const sanitizeForm = document.getElementById("sanitize-form");
const sanitizeButton = document.getElementById("sanitize-button");
const statusMessage = document.getElementById("status-message");
const systemsNotice = document.getElementById("systems-notice");
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
    if (systemsNotice) systemsNotice.hidden = true;
    sanitizeButton.disabled = true;
    sanitizeButton.textContent = "Scanning and rebuilding…";

    try {
      const response = await fetch(sanitizeForm.action, {
        method: "POST",
        body: new FormData(sanitizeForm),
      });

      if (!response.ok) {
        const errorPage = new DOMParser().parseFromString(await response.text(), "text/html");
        const serverMessage = errorPage.querySelector(".message")?.textContent?.trim();
        const discardNotice = errorPage.querySelector(".discard-notice")?.textContent?.trim();
        const systemsNoticeText = errorPage.querySelector(".systems-notice:not([hidden])")?.textContent?.trim();
        if (systemsNoticeText && systemsNotice) systemsNotice.hidden = false;
        throw new Error(
          [serverMessage, discardNotice].filter(Boolean).join(" ") || "The document could not be sanitized.",
        );
      }

      const findings = response.headers.get("X-Sanitization-Findings")?.trim();
      const download = document.createElement("a");
      const objectUrl = URL.createObjectURL(await response.blob());
      download.href = objectUrl;
      download.download = responseFilename(response);
      download.hidden = true;
      document.body.appendChild(download);
      download.click();
      download.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);

      sanitizeForm.reset();
      dropZone?.classList.remove("dragging");
      if (findings) {
        showStatus(`Document cleaned and downloaded. Issues found and removed: ${findings}.`, "success");
        if (systemsNotice) systemsNotice.hidden = false;
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
