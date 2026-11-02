const typeEl = document.getElementById("type");
const valueEl = document.getElementById("value");
const extraEl = document.getElementById("extra");
const extraBox = document.getElementById("extraBox");
const valueLabel = document.getElementById("valueLabel");
const resultBox = document.getElementById("result");
const reportBox = document.getElementById("reportBox");
const checkButton = document.getElementById("checkBtn");
const formMessage = document.getElementById("formMessage");
const reportButton = document.getElementById("reportBtn");
const reportMessage = document.getElementById("reportMsg");
const certificateBox = document.getElementById("certificateBox");
const certificateImage = document.getElementById("certificateImage");
const certificateText = document.getElementById("certificateText");
const ocrStatus = document.getElementById("ocrStatus");
const imagePreviewBox = document.getElementById("imagePreviewBox");
const imagePreview = document.getElementById("imagePreview");
const imageName = document.getElementById("imageName");
let previewUrl = "";
let ocrSequence = 0;
let tesseractPromise;
let ocrConfidence = 100;

const fields = {
  url: {
    label: "Website address",
    placeholder: "e.g. company-careers.com",
    inputMode: "url"
  },
  email: {
    label: "Email address",
    placeholder: "e.g. recruiter@company.com",
    inputMode: "email"
  },
  certificate: {
    label: "Certificate ID",
    placeholder: "e.g. CERT-2025-1048",
    inputMode: "text"
  }
};

function resetCertificateImage() {
  ocrSequence += 1;
  checkButton.disabled = false;
  certificateImage.value = "";
  certificateText.value = "";
  ocrConfidence = 100;
  ocrStatus.textContent = "";
  imagePreviewBox.classList.add("hidden");
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = "";
}

function updateCheckFields() {
  const field = fields[typeEl.value];
  valueLabel.textContent = field.label;
  valueEl.placeholder = field.placeholder;
  valueEl.inputMode = field.inputMode;
  certificateBox.classList.toggle("hidden", typeEl.value !== "certificate");
}

typeEl.addEventListener("change", () => {
  valueEl.value = "";
  extraEl.value = "";
  resetCertificateImage();
  updateCheckFields();
  resultBox.classList.add("hidden");
  reportBox.classList.add("hidden");
  formMessage.textContent = "";
  reportMessage.textContent = "";
});
updateCheckFields();

function loadTesseract() {
  if (window.Tesseract) return Promise.resolve(window.Tesseract);
  if (tesseractPromise) return tesseractPromise;

  tesseractPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js";
    script.onload = () => resolve(window.Tesseract);
    script.onerror = () => {
      tesseractPromise = null;
      reject(new Error("The OCR library could not be loaded. Check your internet connection or enter the certificate ID manually."));
    };
    document.head.append(script);
  });
  return tesseractPromise;
}

function findCertificateId(text) {
  const labeled = text.match(/\b(?:certificate|cert|credential|verification)\s*(?:id|no\.?|number|#)\s*[:#-]?\s*([A-Z0-9][A-Z0-9/_-]{3,})\b/i);
  if (labeled) return labeled[1].replace(/[-_/]+$/, "");
  const genericLabel = text.match(/\b(?:ID|No\.?|Number)\s*[:#-]\s*([A-Z0-9][A-Z0-9/_-]{3,})\b/i);
  if (genericLabel) return genericLabel[1].replace(/[-_/]+$/, "");
  const prefixed = text.match(/\b(?:CERT(?:IFICATE)?|CRED|INTERN)[\s:#-]*[A-Z0-9][A-Z0-9/_-]{2,}\b/i);
  return prefixed ? prefixed[0].replace(/[:#\s]/g, "") : "";
}

certificateImage.addEventListener("change", async () => {
  const file = certificateImage.files && certificateImage.files[0];
  resetCertificateImage();
  if (!file) return;
  if (!["image/jpeg", "image/png", "image/webp"].includes(file.type)) {
    showError("Choose a JPG, PNG, or WebP image.");
    certificateImage.value = "";
    return;
  }
  if (file.size > 8 * 1024 * 1024) {
    showError("The image must be 8 MB or smaller.");
    certificateImage.value = "";
    return;
  }

  const sequence = ocrSequence;
  previewUrl = URL.createObjectURL(file);
  imagePreview.src = previewUrl;
  imageName.textContent = file.name;
  imagePreviewBox.classList.remove("hidden");
  formMessage.textContent = "";
  formMessage.classList.remove("error-message");
  checkButton.disabled = true;
  try {
    const tesseract = await loadTesseract();
    if (sequence !== ocrSequence) return;
    const worker = await tesseract.createWorker("eng", 1, {
      logger: (message) => {
        if (sequence !== ocrSequence || !message.status) return;
        const progress = Math.round((message.progress || 0) * 100);
        ocrStatus.textContent = message.status === "recognizing text"
          ? `Reading the certificate image… ${progress}%`
          : "Preparing the text recognition engine…";
      }
    });
    try {
      const { data } = await worker.recognize(file);
      if (sequence !== ocrSequence) return;
      certificateText.value = data.text.trim().slice(0, 10000);
      ocrConfidence = Number.isFinite(data.confidence) ? data.confidence : 0;
      const extractedId = findCertificateId(data.text);
      if (extractedId && !valueEl.value.trim()) valueEl.value = extractedId;
      ocrStatus.textContent = certificateText.value
        ? `Text recognized${extractedId ? ` · ID: ${extractedId}` : " · No clear ID found; review the text"}.`
        : "No text could be read from this image. Try a clearer photo or enter the ID manually.";
    } finally {
      await worker.terminate();
    }
  } catch (error) {
    if (sequence === ocrSequence) {
      ocrStatus.textContent = "The image could not be read. Try a clearer photo or enter the ID manually.";
      showError(error.message || "Text recognition failed. You can enter the ID manually.");
    }
  } finally {
    if (sequence === ocrSequence) checkButton.disabled = false;
  }
});

document.getElementById("removeImage").addEventListener("click", () => {
  resetCertificateImage();
  ocrStatus.textContent = "";
});

function showError(message) {
  formMessage.textContent = message;
  formMessage.classList.add("error-message");
}

function createResult(data) {
  const score = Math.max(0, Math.min(100, Number(data.score) || 0));
  const tone = score >= 60 ? "high" : score >= 30 ? "review" : "low";
  const title = document.createElement("h2");
  title.id = "resultTitle";
  title.className = `result-verdict ${tone}`;
  title.textContent = data.verdict;

  const summary = document.createElement("p");
  summary.className = "score-summary";
  summary.textContent = `Risk indicator: ${score} out of 100`;

  const progress = document.createElement("div");
  progress.className = "score-track";
  progress.setAttribute("role", "progressbar");
  progress.setAttribute("aria-label", "Risk indicator");
  progress.setAttribute("aria-valuemin", "0");
  progress.setAttribute("aria-valuemax", "100");
  progress.setAttribute("aria-valuenow", String(score));
  const fill = document.createElement("div");
  fill.className = `score-fill ${tone}`;
  fill.style.width = `${score}%`;
  progress.append(fill);

  const detailsHeading = document.createElement("h3");
  detailsHeading.className = "findings-heading";
  detailsHeading.textContent = "What we found — and why it matters";
  const findingList = document.createElement("div");
  findingList.className = "finding-list";
  const findings = Array.isArray(data.findings) ? data.findings : [];
  findings.forEach((finding) => {
    const card = document.createElement("article");
    card.className = `finding ${tone}`;
    const heading = document.createElement("h3");
    heading.textContent = finding.title || "Scanner signal";
    const evidence = document.createElement("p");
    const evidenceLabel = document.createElement("strong");
    evidenceLabel.textContent = "Evidence: ";
    evidence.append(evidenceLabel, document.createTextNode(finding.evidence || ""));
    const why = document.createElement("p");
    const whyLabel = document.createElement("strong");
    whyLabel.textContent = "Why it matters: ";
    why.append(whyLabel, document.createTextNode(finding.why || ""));
    const action = document.createElement("p");
    const actionLabel = document.createElement("strong");
    actionLabel.textContent = "What to do: ";
    action.append(actionLabel, document.createTextNode(finding.action || ""));
    card.append(heading, evidence, why, action);
    findingList.append(card);
  });

  const notice = document.createElement("p");
  notice.className = "result-notice";
  notice.textContent = data.notice || "A risk score is an indicator, not proof. Verify independently.";
  if (data.extracted_id) {
    const extracted = document.createElement("p");
    extracted.className = "score-summary";
    extracted.textContent = `Certificate ID read from image: ${data.extracted_id}`;
    resultBox.replaceChildren(title, summary, progress, extracted, detailsHeading, findingList, notice);
  } else {
    resultBox.replaceChildren(title, summary, progress, detailsHeading, findingList, notice);
  }
  resultBox.classList.remove("hidden");
}

checkButton.addEventListener("click", async () => {
  const value = valueEl.value.trim();
  const scannedText = typeEl.value === "certificate" ? certificateText.value.trim() : "";
  formMessage.textContent = "";
  formMessage.classList.remove("error-message");
  if (!value && !scannedText) {
    showError(typeEl.value === "certificate"
      ? "Enter the certificate ID above or upload a certificate image below."
      : "Enter something to check first.");
    valueEl.focus();
    return;
  }

  checkButton.disabled = true;
  checkButton.querySelector(".button-label").textContent = "Checking…";
  reportBox.classList.add("hidden");
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: typeEl.value,
        value,
        extra: extraEl.value.trim(),
        certificate_text: scannedText,
        ocr_confidence: scannedText ? ocrConfidence : 100
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The check could not be completed.");

    if (data.input_value) valueEl.value = data.input_value;
    createResult(data);
    reportBox.classList.remove("hidden");
    reportMessage.textContent = "";
    reportMessage.classList.remove("error-message");
    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    showError(error.message || "Unable to connect. Please try again.");
  } finally {
    checkButton.disabled = false;
    checkButton.querySelector(".button-label").textContent = "Check for warning signs";
  }
});

reportButton.addEventListener("click", async () => {
  reportMessage.textContent = "";
  reportMessage.classList.remove("error-message");
  reportButton.disabled = true;
  try {
    const response = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: typeEl.value,
        value: valueEl.value.trim(),
        description: document.getElementById("desc").value.trim()
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The report could not be saved.");
    reportMessage.textContent = data.message;
    document.getElementById("desc").value = "";
  } catch (error) {
    reportMessage.textContent = error.message || "Unable to submit the report. Please try again.";
    reportMessage.classList.add("error-message");
  } finally {
    reportButton.disabled = false;
  }
});
