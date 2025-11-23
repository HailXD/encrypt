const plainEl = document.getElementById("plain");
const cipherEl = document.getElementById("cipher");
const cipherInputEl = document.getElementById("cipherInput");
const decryptedTextEl = document.getElementById("decryptedText");
const encryptKeyEl = document.getElementById("encryptKey");
const decryptKeyEl = document.getElementById("decryptKey");
const toastContainer = document.getElementById("toastContainer");

const fileInput = document.getElementById("fileInput");
const encryptPngBtn = document.getElementById("encryptPng");
const downloadImageLink = document.getElementById("downloadImage");
const imagePreview = document.getElementById("imagePreview");
const imageInput = document.getElementById("imageInput");
const encryptCard = document.getElementById("encryptInputs");
const decryptCard = document.getElementById("decryptInputs");
const decryptImageBtn = document.getElementById("decryptImage");
const fileListEl = document.getElementById("fileList");
const downloadAllBtn = document.getElementById("downloadAll");
const encryptSelectionListEl = document.getElementById("encryptSelectionList");
const encryptSelectionDetailsEl = document.getElementById("encryptSelectionDetails");
const encryptSelectionSummaryEl = document.getElementById("encryptSelectionSummary");
const sizeReportEl = document.getElementById("sizeReport");

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const PACKAGE_MAGIC = "⃅Z⿠";
const LEGACY_PACKAGE_MAGICS = ["ENCFILE1"];
const PACKAGE_VERSION = 2;
const EMBED_MARKER = "⿠Z⃅";
const LEGACY_MARKERS = ["ENCPNG::DATA::", "ENCJPEG::DATA::"];
const SALT_LEN = 16;
const IV_LEN = 12;
const ACCEPTED_IMAGE_TYPES = ["image/png", "image/jpeg"];
const TOAST_DURATION = 4000;

function generateDownloadBasename() {
  return ((f) => f(f, Math.floor(Date.now() / 10)))(
    (s, n) =>
      n < 26
        ? String.fromCharCode(97 + (n % 26))
        : s(s, Math.floor(n / 26)) + String.fromCharCode(97 + (n % 26))
  );
}

function baseNameFromFilename(name) {
  if (!name) return "";
  const lastDot = name.lastIndexOf(".");
  return lastDot > 0 ? name.slice(0, lastDot) : name;
}

let currentImageUrl = null;
let currentFiles = [];
let currentDownloadBase = "";

function getToastLabel(type) {
  switch (type) {
    case "success":
      return "Success";
    case "error":
      return "Error";
    case "warn":
      return "Heads up";
    default:
      return "Info";
  }
}

function dismissToast(toastEl) {
  if (!toastEl || toastEl.classList.contains("dismiss")) return;
  toastEl.classList.add("dismiss");
  setTimeout(() => toastEl.remove(), 160);
}

function showToast(message, { type = "info", label } = {}) {
  if (!toastContainer) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;

  const labelEl = document.createElement("div");
  labelEl.className = "label";
  labelEl.textContent = label || getToastLabel(type);

  const messageEl = document.createElement("div");
  messageEl.className = "message";
  messageEl.textContent = message;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Dismiss notification");
  closeBtn.textContent = "x";
  closeBtn.addEventListener("click", () => dismissToast(toast));

  toast.append(labelEl, messageEl, closeBtn);
  toastContainer.appendChild(toast);

  setTimeout(() => dismissToast(toast), TOAST_DURATION);
}

function updateSizeReport(inputBytes = 0, outputBytes = 0, targetEl = sizeReportEl) {
  if (!targetEl) return;
  if (!inputBytes || !outputBytes) {
    targetEl.textContent = "Before & after sizes + change will appear here.";
    targetEl.style.color = "var(--muted)";
    targetEl.classList.add("empty");
    return;
  }

  const diff = outputBytes - inputBytes;
  const pct = inputBytes ? (diff / inputBytes) * 100 : 0;
  const pctText = `${diff >= 0 ? "+" : ""}${pct.toFixed(1)}%`;

  targetEl.textContent = `Input: ${formatBytes(inputBytes)} -> Output: ${formatBytes(outputBytes)} (${pctText})`;
  targetEl.style.color = diff > 0 ? "#ff9e9e" : diff < 0 ? "#a2f7d8" : "#d5d8e7";
  targetEl.classList.remove("empty");
}

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(str) {
  const bytes = Uint8Array.from(atob(str), c => c.charCodeAt(0));
  return bytes.buffer;
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** index;
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

async function deriveKey(keyText, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(keyText),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100_000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt() {
  const keyText = encryptKeyEl?.value || "";
  const text = plainEl.value;

  if (!text) {
    showToast("Enter text to encrypt.", { type: "warn" });
    plainEl.focus();
    return;
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(keyText, salt);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      textEncoder.encode(text)
    );

    const output = [
      bufferToBase64(salt.buffer),
      bufferToBase64(iv.buffer),
      bufferToBase64(encrypted)
    ].join(":");

    cipherEl.value = output;
    showToast("Text encrypted.", { type: "success", label: "Encrypted" });
  } catch (err) {
    console.error(err);
    showToast("Encryption failed.", { type: "error" });
  }
}

async function decrypt() {
  const keyText = decryptKeyEl?.value || "";
  const cipherText = (cipherInputEl?.value || cipherEl?.value || "").trim();

  if (!cipherText) {
    showToast("Paste encrypted text to decrypt.", { type: "warn" });
    (cipherInputEl || cipherEl)?.focus();
    return;
  }

  const parts = cipherText.split(":");
  if (parts.length !== 3) {
    showToast("Cipher text looks invalid.", { type: "warn" });
    (cipherInputEl || cipherEl)?.focus();
    return;
  }

  try {
    const [saltB64, ivB64, cipherB64] = parts;
    const salt = new Uint8Array(base64ToBuffer(saltB64));
    const iv = new Uint8Array(base64ToBuffer(ivB64));
    const data = base64ToBuffer(cipherB64);

    const key = await deriveKey(keyText, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    const plainText = textDecoder.decode(decrypted);
    setDecryptedText(plainText);
    showToast("Text decrypted.", { type: "success", label: "Decrypted" });
  } catch (err) {
    console.error(err);
    showToast("Incorrect key or corrupted data.", { type: "error" });
  }
}

function packFiles(fileList, buffers, messageBytes = null) {
  const magicBytes = textEncoder.encode(PACKAGE_MAGIC);
  const messageData = messageBytes ? new Uint8Array(messageBytes) : null;
  const messageLength = messageData?.byteLength || 0;

  const meta = {
    version: PACKAGE_VERSION,
    hasMessage: messageLength > 0,
    messageBytes: messageLength,
    messageType: messageLength ? "text/plain" : undefined,
    files: fileList.map((file, i) => ({
      name: file.name,
      type: file.type || "application/octet-stream",
      size: buffers[i].byteLength
    }))
  };

  const headerBytes = textEncoder.encode(JSON.stringify(meta));

  // Total = magic + header length + header + message length + message data + file blobs.
  let total = magicBytes.length + 4 + headerBytes.length + 4 + messageLength;
  for (const buf of buffers) {
    total += 4 + buf.byteLength;
  }

  const output = new Uint8Array(total);
  output.set(magicBytes, 0);
  const view = new DataView(output.buffer);
  let offset = magicBytes.length;

  view.setUint32(offset, headerBytes.length, false);
  offset += 4;
  output.set(headerBytes, offset);
  offset += headerBytes.length;

  view.setUint32(offset, messageLength, false);
  offset += 4;
  if (messageLength) {
    output.set(messageData, offset);
    offset += messageLength;
  }

  for (let i = 0; i < buffers.length; i++) {
    const buf = new Uint8Array(buffers[i]);
    view.setUint32(offset, buf.length, false);
    offset += 4;
    output.set(buf, offset);
    offset += buf.length;
  }

  return output;
}

// Accept both current and legacy package headers for backward compatibility.
function matchPackageMagic(bytes) {
  const magicOptions = [PACKAGE_MAGIC, ...LEGACY_PACKAGE_MAGICS].map(m => textEncoder.encode(m));
  for (const magic of magicOptions) {
    if (bytes.length < magic.length) continue;
    let matches = true;
    for (let i = 0; i < magic.length; i++) {
      if (bytes[i] !== magic[i]) {
        matches = false;
        break;
      }
    }
    if (matches) return magic;
  }
  return null;
}

function unpackFiles(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBytes = matchPackageMagic(bytes);
  if (!magicBytes) {
    throw new Error("Invalid package header.");
  }

  let offset = magicBytes.length;
  const headerLen = view.getUint32(offset, false);
  offset += 4;
  const headerStr = textDecoder.decode(bytes.slice(offset, offset + headerLen));
  offset += headerLen;

  const meta = JSON.parse(headerStr);
  const version = meta.version || 1;
  const files = [];
  let embeddedMessage = null;

  if (version >= 2) {
    if (offset + 4 > bytes.length) {
      throw new Error("Corrupt package (message length).");
    }
    const msgLen = view.getUint32(offset, false);
    offset += 4;
    if (msgLen > 0) {
      if (offset + msgLen > bytes.length) {
        throw new Error("Corrupt package (message body).");
      }
      embeddedMessage = bytes.slice(offset, offset + msgLen);
      offset += msgLen;
    }
  }

  for (const entry of meta.files || []) {
    if (offset + 4 > bytes.length) {
      throw new Error("Corrupt package (length).");
    }
    const len = view.getUint32(offset, false);
    offset += 4;
    const slice = bytes.slice(offset, offset + len);
    offset += len;
    files.push({
      name: entry.name || "file.bin",
      type: entry.type || "application/octet-stream",
      size: len,
      data: slice
    });
  }

  if (version < 2 && !embeddedMessage) {
    const messageFile = files.find(file => file.name === "message.txt" && isTextFileEntry(file));
    if (messageFile) {
      embeddedMessage = messageFile.data;
    }
  }

  return { files, message: embeddedMessage, meta };
}

async function payloadToPng(payloadBytes) {
  const width = 12;
  const height = 9; // tiny 4:3 canvas to keep PNG overhead low while still visible

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");

  const imageData = ctx.createImageData(width, height);
  const pixels = imageData.data;
  const len = payloadBytes.length || 1;

  for (let p = 0; p < width * height; p++) {
    const base = p * 4;
    const idx = (p * 3) % len;
    pixels[base] = payloadBytes[idx % len];
    pixels[base + 1] = payloadBytes[(idx + 1) % len];
    pixels[base + 2] = payloadBytes[(idx + 2) % len];
    pixels[base + 3] = 255;
  }

  ctx.putImageData(imageData, 0, 0);

  const baseBlob = await new Promise(resolve => canvas.toBlob(resolve, "image/png"));
  if (!baseBlob) throw new Error("Unable to create PNG blob.");

  const marker = textEncoder.encode(EMBED_MARKER);
  const lenBuf = new ArrayBuffer(4);
  new DataView(lenBuf).setUint32(0, payloadBytes.length, false);

  return new Blob([baseBlob, marker, lenBuf, payloadBytes], { type: "image/png" });
}

function findMarker(bytes, marker) {
  for (let i = bytes.length - marker.length; i >= 0; i--) {
    let match = true;
    for (let j = 0; j < marker.length; j++) {
      if (bytes[i + j] !== marker[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

function extractPayloadFromImage(buffer) {
  const bytes = new Uint8Array(buffer);
  const markers = [EMBED_MARKER, ...LEGACY_MARKERS].map(m => textEncoder.encode(m));

  let idx = -1;
  let markerUsed = null;
  for (const marker of markers) {
    const found = findMarker(bytes, marker);
    if (found !== -1 && found > idx) {
      idx = found;
      markerUsed = marker;
    }
  }

  if (idx === -1 || !markerUsed) throw new Error("No embedded payload found.");

  const lenStart = idx + markerUsed.length;
  if (lenStart + 4 > bytes.length) throw new Error("Corrupt payload length.");
  const view = new DataView(bytes.buffer, bytes.byteOffset + lenStart, 4);
  const payloadLen = view.getUint32(0, false);
  const payloadStart = lenStart + 4;
  if (payloadStart + payloadLen > bytes.length) throw new Error("Payload truncated.");

  return bytes.slice(payloadStart, payloadStart + payloadLen);
}

function getPlainTextBytes() {
  const text = plainEl?.value || "";
  return text ? textEncoder.encode(text).byteLength : 0;
}

function renderEncryptSelectionList(files, textBytes = 0) {
  const hasContent = files.length > 0 || textBytes > 0;
  encryptSelectionListEl.innerHTML = "";
  encryptSelectionListEl.classList.toggle("empty", !hasContent);
  if (encryptSelectionDetailsEl) {
    encryptSelectionDetailsEl.classList.toggle("empty", !hasContent);
    if (!hasContent) {
      encryptSelectionDetailsEl.open = false;
    }
  }

  if (encryptSelectionSummaryEl) {
    if (hasContent) {
      const totalBytes = files.reduce((sum, file) => sum + (file.size || 0), 0) + textBytes;
      const totalItems = files.length + (textBytes > 0 ? 1 : 0);
      encryptSelectionSummaryEl.textContent = `${totalItems} item${totalItems === 1 ? "" : "s"} selected (${formatBytes(totalBytes)}); click to expand`;
    } else {
      encryptSelectionSummaryEl.textContent = "No files or text selected.";
    }
  }

  if (!hasContent) {
    encryptSelectionListEl.textContent = "No files or text selected.";
    return;
  }

  if (textBytes > 0) {
    const row = document.createElement("div");
    row.className = "file-row";
    const info = document.createElement("div");
    info.className = "file-info";
    const nameEl = document.createElement("div");
    nameEl.className = "file-name";
    nameEl.textContent = "Embedded text";
    const metaEl = document.createElement("div");
    metaEl.className = "file-meta";
    metaEl.textContent = `text/plain - ${formatBytes(textBytes)}`;
    info.append(nameEl, metaEl);
    row.append(info);
    encryptSelectionListEl.appendChild(row);
  }

  files.forEach(file => {
    const row = document.createElement("div");
    row.className = "file-row";

    const info = document.createElement("div");
    info.className = "file-info";
    const nameEl = document.createElement("div");
    nameEl.className = "file-name";
    nameEl.textContent = file.name;
    const metaEl = document.createElement("div");
    metaEl.className = "file-meta";
    metaEl.textContent = `${file.type || "file"} - ${formatBytes(file.size)}`;
    info.append(nameEl, metaEl);

    row.append(info);
    encryptSelectionListEl.appendChild(row);
  });
}

function handleEncryptSelectionChange() {
  const files = Array.from(fileInput.files || []);
  renderEncryptSelectionList(files, getPlainTextBytes());
}

function handlePlainInputChange() {
  const files = Array.from(fileInput.files || []);
  renderEncryptSelectionList(files, getPlainTextBytes());
}

function setImageOutputs(blob) {
  if (currentImageUrl) URL.revokeObjectURL(currentImageUrl);
  currentImageUrl = URL.createObjectURL(blob);
  imagePreview.src = currentImageUrl;
  imagePreview.classList.add("has-image");
  currentDownloadBase = generateDownloadBasename();
  downloadImageLink.download = `${currentDownloadBase}.png`;
  downloadImageLink.href = currentImageUrl;
  downloadImageLink.classList.remove("disabled");
}

async function encryptFilesToImage() {
  const keyText = encryptKeyEl?.value || "";
  const files = Array.from(fileInput.files || []);
  const message = (plainEl?.value || "").trim();
  const messageBytes = message ? textEncoder.encode(message) : null;
  const totalItems = files.length + (messageBytes ? 1 : 0);

  if (!totalItems) {
    showToast("Add text or files to encrypt into a PNG.", { type: "warn" });
    fileInput.focus();
    return;
  }

  try {
    const buffers = [];
    for (const file of files) {
      buffers.push(await file.arrayBuffer());
    }

    const packed = packFiles(files, buffers, messageBytes);
    const totalInputBytes =
      buffers.reduce((sum, buf) => sum + buf.byteLength, 0) + (messageBytes?.byteLength || 0);

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(keyText, salt);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, packed);

    const payload = new Uint8Array(SALT_LEN + IV_LEN + encrypted.byteLength);
    payload.set(salt, 0);
    payload.set(iv, SALT_LEN);
    payload.set(new Uint8Array(encrypted), SALT_LEN + IV_LEN);

    const imageBlob = await payloadToPng(payload);
    setImageOutputs(imageBlob);
    updateSizeReport(totalInputBytes, imageBlob.size);
    showToast(`Encrypted ${totalItems} item${totalItems === 1 ? "" : "s"} to PNG.`, {
      type: "success",
      label: "Encrypted"
    });
  } catch (err) {
    console.error(err);
    updateSizeReport();
    showToast("File/text encryption failed.", { type: "error" });
  }
}

async function decryptImage() {
  const keyText = decryptKeyEl?.value || "";
  const file = imageInput.files?.[0];

  if (!file) {
    showToast("Choose an image to decrypt.", { type: "warn" });
    imageInput.focus();
    return;
  }

  currentDownloadBase = baseNameFromFilename(file.name) || generateDownloadBasename();

  try {
    const buffer = await file.arrayBuffer();
    const payload = extractPayloadFromImage(buffer);
    if (payload.length < SALT_LEN + IV_LEN + 1) {
      throw new Error("Payload too small.");
    }

    const salt = payload.slice(0, SALT_LEN);
    const iv = payload.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const cipher = payload.slice(SALT_LEN + IV_LEN);

    const key = await deriveKey(keyText, salt);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    const { files, message } = unpackFiles(new Uint8Array(decrypted));

    renderFileList(files);
    const { usedMessage, hasText } = applyDecryptedText(files, message);
    const fileCountText = `${files.length} file${files.length === 1 ? "" : "s"}`;
    const parts = [];
    if (usedMessage || hasText) parts.push("text");
    if (files.length) parts.push(fileCountText);
    const toastMessage = parts.length ? `Decrypted ${parts.join(" and ")}.` : "Decrypted.";

    showToast(toastMessage, {
      type: "success",
      label: "Decrypted"
    });
  } catch (err) {
    console.error(err);
    renderFileList([]);
    setDecryptedText("");
    showToast("Incorrect key or invalid image.", { type: "error" });
  }
}

function renderFileList(files) {
  currentFiles = files;
  fileListEl.innerHTML = "";
  fileListEl.classList.toggle("empty", files.length === 0);
  downloadAllBtn.disabled = files.length === 0;
  if (!files.length) {
    fileListEl.textContent = "No files decrypted yet.";
    return;
  }

  files.forEach(file => {
    const row = document.createElement("div");
    row.className = "file-row";

    const info = document.createElement("div");
    info.className = "file-info";
    const nameEl = document.createElement("div");
    nameEl.className = "file-name";
    nameEl.textContent = file.name;
    const metaEl = document.createElement("div");
    metaEl.className = "file-meta";
    metaEl.textContent = `${file.type || "file"} - ${formatBytes(file.data.length)}`;
    info.append(nameEl, metaEl);

    const downloadBtn = document.createElement("button");
    downloadBtn.className = "ghost";
    downloadBtn.textContent = "Download";
    downloadBtn.addEventListener("click", () => downloadSingle(file));

    row.append(info, downloadBtn);
    fileListEl.appendChild(row);
  });
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function downloadSingle(file) {
  const blob = new Blob([file.data], { type: file.type || "application/octet-stream" });
  downloadBlob(blob, file.name || "file.bin");
}

async function downloadAllZip() {
  if (!currentFiles.length) return;
  if (typeof JSZip === "undefined") {
    console.error("JSZip failed to load; cannot zip files.");
    return;
  }
  if (!currentDownloadBase) {
    currentDownloadBase = generateDownloadBasename();
  }
  const zip = new JSZip();
  currentFiles.forEach(file => {
    zip.file(file.name || "file.bin", file.data, { binary: true });
  });
  const blob = await zip.generateAsync({ type: "blob" });
  downloadBlob(blob, `${currentDownloadBase}.zip`);
}

function clearImagePreview() {
  if (currentImageUrl) {
    URL.revokeObjectURL(currentImageUrl);
    currentImageUrl = null;
  }
  imagePreview.src = "";
  imagePreview.classList.remove("has-image");
  downloadImageLink.href = "#";
  downloadImageLink.classList.add("disabled");
  downloadImageLink.removeAttribute("download");
}

function setDecryptedText(text) {
  if (decryptedTextEl) decryptedTextEl.value = text || "";
  if (plainEl) plainEl.value = text || "";
}

function isTextFileEntry(file) {
  const type = (file.type || "").toLowerCase();
  const name = (file.name || "").toLowerCase();
  return type.startsWith("text/") || /\.(txt|md|csv|json|log)$/i.test(name);
}

function populateDecryptedTextFromFiles(files) {
  if (!files.length) {
    setDecryptedText("");
    return false;
  }
  const textFile = files.find(isTextFileEntry);
  if (!textFile) {
    setDecryptedText("");
    return false;
  }

  try {
    const text = textDecoder.decode(textFile.data);
    setDecryptedText(text);
    return true;
  } catch (err) {
    console.error("Unable to decode text file", err);
    setDecryptedText("");
    return false;
  }
}

function decodeMessageBytes(bytes) {
  if (!bytes || !bytes.length) return null;
  try {
    return textDecoder.decode(bytes);
  } catch (err) {
    console.error("Unable to decode embedded text", err);
    return null;
  }
}

function applyDecryptedText(files, messageBytes) {
  const messageText = decodeMessageBytes(messageBytes);
  if (messageText !== null) {
    setDecryptedText(messageText);
    return { usedMessage: true, hasText: true };
  }

  const populated = populateDecryptedTextFromFiles(files);
  return { usedMessage: false, hasText: populated };
}

function resetUiState() {
  if (plainEl) plainEl.value = "";
  if (cipherEl) cipherEl.value = "";
  if (cipherInputEl) cipherInputEl.value = "";
  setDecryptedText("");
  if (encryptKeyEl) encryptKeyEl.value = "";
  if (decryptKeyEl) decryptKeyEl.value = "";
  if (fileInput) fileInput.value = "";
  if (imageInput) imageInput.value = "";
  currentDownloadBase = "";
  clearImagePreview();
  renderEncryptSelectionList([], 0);
  renderFileList([]);
  updateSizeReport();
}

function assignFilesToInput(inputEl, files) {
  if (typeof DataTransfer === "undefined") return;
  const dataTransfer = new DataTransfer();
  files.forEach(file => dataTransfer.items.add(file));
  inputEl.files = dataTransfer.files;
  inputEl.dispatchEvent(new Event("change", { bubbles: true }));
}

function pickImageFile(files) {
  return files.find(
    file =>
      ACCEPTED_IMAGE_TYPES.includes(file.type) ||
      /\.(png|jpe?g)$/i.test(file.name || "")
  );
}

function setupDropZone(zoneEl, onFiles) {
  if (!zoneEl) return;

  const setDragging = isDragging => zoneEl.classList.toggle("dragging", isDragging);

  ["dragenter", "dragover"].forEach(evt => {
    zoneEl.addEventListener(evt, event => {
      event.preventDefault();
      event.stopPropagation();
      setDragging(true);
      if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
    });
  });

  ["dragleave", "dragend"].forEach(evt => {
    zoneEl.addEventListener(evt, event => {
      event.preventDefault();
      event.stopPropagation();
      setDragging(false);
    });
  });

  zoneEl.addEventListener("drop", event => {
    event.preventDefault();
    event.stopPropagation();
    setDragging(false);
    const files = Array.from(event.dataTransfer?.files || []);
    if (files.length) onFiles(files);
  });
}

function isTextInput(el) {
  if (!el) return false;
  if (el.tagName === "TEXTAREA") return true;
  if (el.tagName === "INPUT") {
    const type = (el.type || "text").toLowerCase();
    return ["text", "search", "password", "email", "url", "tel", "number"].includes(type);
  }
  return false;
}

document.getElementById("encrypt").addEventListener("click", encrypt);
document.getElementById("decrypt").addEventListener("click", decrypt);
fileInput.addEventListener("change", handleEncryptSelectionChange);
plainEl.addEventListener("input", handlePlainInputChange);
encryptPngBtn.addEventListener("click", encryptFilesToImage);
decryptImageBtn.addEventListener("click", decryptImage);
downloadAllBtn.addEventListener("click", downloadAllZip);

setupDropZone(encryptCard, files => assignFilesToInput(fileInput, files));
setupDropZone(decryptCard, files => {
  const imageFile = pickImageFile(files);
  if (imageFile) assignFilesToInput(imageInput, [imageFile]);
});

window.addEventListener("paste", event => {
  const files = Array.from(event.clipboardData?.files || []);
  if (!files.length) return;
  if (isTextInput(event.target)) return;

  const imageFile = pickImageFile(files);
  if (files.length === 1 && imageFile) {
    assignFilesToInput(imageInput, [imageFile]);
  } else {
    assignFilesToInput(fileInput, files);
  }
  event.preventDefault();
});

window.addEventListener("pageshow", () => {
  resetUiState();
});

resetUiState();
