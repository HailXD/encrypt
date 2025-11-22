const plainEl = document.getElementById("plain");
const cipherEl = document.getElementById("cipher");
const passwordEl = document.getElementById("password");
const statusEl = document.getElementById("status");

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#ff9e9e" : "#a2f7d8";
}

function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuffer(str) {
  const bytes = Uint8Array.from(atob(str), c => c.charCodeAt(0));
  return bytes.buffer;
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

  if (!password) {
    setStatus("Password required to encrypt.", true);
    passwordEl.focus();
    return;
  }

  if (!text) {
    setStatus("Enter something to encrypt.", true);
    plainEl.focus();
    return;
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
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
    setStatus("Encrypted. Copy the full salt:iv:cipher string.");
  } catch (err) {
    console.error(err);
    setStatus("Encryption failed.", true);
  }
}

async function decrypt() {
  const password = passwordEl.value;
  const cipherText = cipherEl.value.trim();

  if (!password) {
    setStatus("Password required to decrypt.", true);
    passwordEl.focus();
    return;
  }

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

document.getElementById("encrypt").addEventListener("click", encrypt);
document.getElementById("decrypt").addEventListener("click", decrypt);

plainEl.value = "This text never leaves your browser. Try encrypting it!";
setStatus("Ready. Uses PBKDF2 + AES-GCM locally.");
