import { sha256 } from "js-sha256";

export function toBase64Url(bytes: Uint8Array | ArrayBuffer): string {
  let binary = "";

  // Convert ArrayBuffer or Uint8Array to binary string
  if (bytes instanceof ArrayBuffer) {
    bytes = new Uint8Array(bytes);
  }

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  // Use btoa in browser, Buffer in Node if available
  let base64: string;
  if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
    base64 = Buffer.from(bytes).toString("base64");
  } else {
    base64 = btoa(binary);
  }

  // Convert to URL-safe Base64
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Generate PKCE code verifier
export function generateCodeVerifier(length = 32): string {
  let bytes: Uint8Array;

  if (typeof window === "undefined") {
    // Node.js
    const { randomBytes } = require("crypto");
    bytes = randomBytes(length);
  } else {
    // Browser
    bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
  }

  return toBase64Url(bytes);
}

/**
 * Generate PKCE code challenge (SHA-256) from a verifier
 * Fully synchronous, works in Node and browser
 */
export function generateCodeChallenge(verifier: string): string {
  const hashBytes = new Uint8Array(sha256.array(verifier));
  return toBase64Url(hashBytes);
}
