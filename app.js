const plainEl = document.getElementById("plain");
const cipherEl = document.getElementById("cipher");
const passwordEl = document.getElementById("password");
const statusEl = document.getElementById("status");

const fileInput = document.getElementById("fileInput");
const encryptFilesBtn = document.getElementById("encryptFiles");
const downloadJpegLink = document.getElementById("downloadJpeg");
const jpegPreview = document.getElementById("jpegPreview");
const fileStatusEl = document.getElementById("fileStatus");
const jpegInput = document.getElementById("jpegInput");
const decryptJpegBtn = document.getElementById("decryptJpeg");
const fileListEl = document.getElementById("fileList");
const downloadAllBtn = document.getElementById("downloadAll");

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const PACKAGE_MAGIC = "ENCFILE1";
const JPEG_MARKER = "ENCJPEG::DATA::";
const SALT_LEN = 16;
const IV_LEN = 12;

let currentJpegUrl = null;
let currentFiles = [];

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#ff9e9e" : "#a2f7d8";
}

function setFileStatus(message, isError = false) {
  fileStatusEl.textContent = message;
  fileStatusEl.style.color = isError ? "#ff9e9e" : "#a2f7d8";
}

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(str) {
  const bytes = Uint8Array.from(atob(str), c => c.charCodeAt(0));
  return bytes.buffer;
}

function fillRandom(view) {
  const target = view instanceof Uint8Array ? view : new Uint8Array(view);
  const max = 65_536;
  for (let offset = 0; offset < target.length; offset += max) {
    const slice = target.subarray(offset, Math.min(offset + max, target.length));
    crypto.getRandomValues(slice);
  }
  return target;
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** index;
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
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
  const password = passwordEl.value;
  const text = plainEl.value;

  if (!text) {
    setStatus("Enter something to encrypt.", true);
    plainEl.focus();
    return;
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(password, salt);
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
    setStatus(
      password
        ? "Encrypted. Copy the full salt:iv:cipher string."
        : "Encrypted with an empty password; anyone can decrypt."
    );
  } catch (err) {
    console.error(err);
    setStatus("Encryption failed.", true);
  }
}

async function decrypt() {
  const password = passwordEl.value;
  const cipherText = cipherEl.value.trim();

  const parts = cipherText.split(":");
  if (parts.length !== 3) {
    setStatus("Encrypted text should be salt:iv:cipher (base64).", true);
    cipherEl.focus();
    return;
  }

  try {
    const [saltB64, ivB64, cipherB64] = parts;
    const salt = new Uint8Array(base64ToBuffer(saltB64));
    const iv = new Uint8Array(base64ToBuffer(ivB64));
    const data = base64ToBuffer(cipherB64);

    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    plainEl.value = textDecoder.decode(decrypted);
    setStatus("Decrypted. Keep your password safe.");
  } catch (err) {
    console.error(err);
    setStatus("Decryption failed. Check password or input.", true);
  }
}

function packFiles(fileList, buffers) {
  const magicBytes = textEncoder.encode(PACKAGE_MAGIC);
  const meta = {
    version: 1,
    files: fileList.map((file, i) => ({
      name: file.name,
      type: file.type || "application/octet-stream",
      size: buffers[i].byteLength
    }))
  };
  const headerBytes = textEncoder.encode(JSON.stringify(meta));

  let total = magicBytes.length + 4 + headerBytes.length;
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

  for (let i = 0; i < buffers.length; i++) {
    const buf = new Uint8Array(buffers[i]);
    view.setUint32(offset, buf.length, false);
    offset += 4;
    output.set(buf, offset);
    offset += buf.length;
  }

  return output;
}

function unpackFiles(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBytes = textEncoder.encode(PACKAGE_MAGIC);

  for (let i = 0; i < magicBytes.length; i++) {
    if (bytes[i] !== magicBytes[i]) {
      throw new Error("Invalid package header.");
    }
  }

  let offset = magicBytes.length;
  const headerLen = view.getUint32(offset, false);
  offset += 4;
  const headerStr = textDecoder.decode(bytes.slice(offset, offset + headerLen));
  offset += headerLen;

  const meta = JSON.parse(headerStr);
  const files = [];

  for (const entry of meta.files) {
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

  return files;
}

async function payloadToJpeg(payloadBytes) {
  const pixelCount = Math.ceil(payloadBytes.length / 3);
  const idealWidth = Math.ceil(Math.sqrt(pixelCount * (4 / 3)));
  const width = Math.min(1024, Math.max(64, idealWidth));
  const height = Math.max(1, Math.ceil(pixelCount / width));

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  const imageData = ctx.createImageData(width, height);
  fillRandom(imageData.data);

  let pixel = 0;
  for (let i = 0; i < payloadBytes.length; i += 3) {
    const base = pixel * 4;
    imageData.data[base] = payloadBytes[i];
    imageData.data[base + 1] = payloadBytes[i + 1] ?? imageData.data[base + 1];
    imageData.data[base + 2] = payloadBytes[i + 2] ?? imageData.data[base + 2];
    imageData.data[base + 3] = 255;
    pixel++;
  }

  ctx.putImageData(imageData, 0, 0);

  const baseBlob = await new Promise(resolve => canvas.toBlob(resolve, "image/jpeg", 0.92));
  if (!baseBlob) throw new Error("Unable to create JPEG blob.");

  const marker = textEncoder.encode(JPEG_MARKER);
  const lenBuf = new ArrayBuffer(4);
  new DataView(lenBuf).setUint32(0, payloadBytes.length, false);

  return new Blob([baseBlob, marker, lenBuf, payloadBytes], { type: "image/jpeg" });
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

function extractPayloadFromJpeg(buffer) {
  const bytes = new Uint8Array(buffer);
  const marker = textEncoder.encode(JPEG_MARKER);
  const idx = findMarker(bytes, marker);
  if (idx === -1) throw new Error("No embedded payload found.");

  const lenStart = idx + marker.length;
  if (lenStart + 4 > bytes.length) throw new Error("Corrupt payload length.");
  const view = new DataView(bytes.buffer, bytes.byteOffset + lenStart, 4);
  const payloadLen = view.getUint32(0, false);
  const payloadStart = lenStart + 4;
  if (payloadStart + payloadLen > bytes.length) throw new Error("Payload truncated.");

  return bytes.slice(payloadStart, payloadStart + payloadLen);
}

function setJpegOutputs(blob) {
  if (currentJpegUrl) URL.revokeObjectURL(currentJpegUrl);
  currentJpegUrl = URL.createObjectURL(blob);
  jpegPreview.src = currentJpegUrl;
  jpegPreview.classList.add("has-image");
  downloadJpegLink.href = currentJpegUrl;
  downloadJpegLink.classList.remove("disabled");
}

async function encryptFilesToJpeg() {
  const password = passwordEl.value;
  const files = Array.from(fileInput.files || []);

  if (!files.length) {
    setFileStatus("Choose files to encrypt.", true);
    fileInput.focus();
    return;
  }

  try {
    setFileStatus("Encrypting files...");
    const buffers = await Promise.all(files.map(f => f.arrayBuffer()));
    const packed = packFiles(files, buffers);

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(password, salt);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, packed);

    const payload = new Uint8Array(SALT_LEN + IV_LEN + encrypted.byteLength);
    payload.set(salt, 0);
    payload.set(iv, SALT_LEN);
    payload.set(new Uint8Array(encrypted), SALT_LEN + IV_LEN);

    const jpegBlob = await payloadToJpeg(payload);
    setJpegOutputs(jpegBlob);
    setFileStatus(
      `Encrypted ${files.length} file(s) into JPEG (${formatBytes(jpegBlob.size)})${password ? "" : " using no password."}`
    );
  } catch (err) {
    console.error(err);
    setFileStatus("File encryption failed.", true);
  }
}

async function decryptJpeg() {
  const password = passwordEl.value;
  const file = jpegInput.files?.[0];

  if (!file) {
    setFileStatus("Select a JPEG to decrypt.", true);
    jpegInput.focus();
    return;
  }

  try {
    setFileStatus("Reading JPEG...");
    const buffer = await file.arrayBuffer();
    const payload = extractPayloadFromJpeg(buffer);
    if (payload.length < SALT_LEN + IV_LEN + 1) {
      throw new Error("Payload too small.");
    }

    const salt = payload.slice(0, SALT_LEN);
    const iv = payload.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const cipher = payload.slice(SALT_LEN + IV_LEN);

    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    const files = unpackFiles(new Uint8Array(decrypted));

    renderFileList(files);
    setFileStatus(`Decrypted ${files.length} file(s) from JPEG.`);
  } catch (err) {
    console.error(err);
    renderFileList([]);
    setFileStatus("Decryption failed. Check the JPEG or password.", true);
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
    setFileStatus("JSZip failed to load; cannot zip files.", true);
    return;
  }
  setFileStatus("Building zip...");
  const zip = new JSZip();
  currentFiles.forEach(file => {
    zip.file(file.name || "file.bin", file.data, { binary: true });
  });
  const blob = await zip.generateAsync({ type: "blob" });
  downloadBlob(blob, "files.zip");
  setFileStatus("Zip ready.");
}

function clearJpegPreview() {
  if (currentJpegUrl) {
    URL.revokeObjectURL(currentJpegUrl);
    currentJpegUrl = null;
  }
  jpegPreview.src = "";
  jpegPreview.classList.remove("has-image");
  downloadJpegLink.href = "#";
  downloadJpegLink.classList.add("disabled");
}

function resetUiState() {
  plainEl.value = "";
  cipherEl.value = "";
  passwordEl.value = "";
  fileInput.value = "";
  jpegInput.value = "";
  clearJpegPreview();
  renderFileList([]);
  setStatus("Ready. Uses PBKDF2 + AES-GCM locally.");
  setFileStatus("File tool ready.");
}

document.getElementById("encrypt").addEventListener("click", encrypt);
document.getElementById("decrypt").addEventListener("click", decrypt);
encryptFilesBtn.addEventListener("click", encryptFilesToJpeg);
decryptJpegBtn.addEventListener("click", decryptJpeg);
downloadAllBtn.addEventListener("click", downloadAllZip);

window.addEventListener("pageshow", event => {
  if (event.persisted) resetUiState();
});

resetUiState();
