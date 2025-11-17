import { sha256 } from "js-sha256";
let nodeCrypto: typeof import("crypto") | undefined;

if (typeof window === "undefined") {
  nodeCrypto = await import("crypto");
}

export function toBase64Url(bytes: Uint8Array | Buffer): string {
  let base64: string;

  if (typeof Buffer !== "undefined" && Buffer.isBuffer(bytes)) {
    // Node.js: Buffer -> base64
    base64 = bytes.toString("base64");
  } else {
    // Browser: Uint8Array -> base64
    let binary = "";
    const chunkSize = 0x8000; // 32k chunks to avoid stack overflow
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode(...chunk);
    }
    base64 = btoa(binary);
  }

  // URL-safe Base64
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Generate PKCE code verifier
export function generateCodeVerifier(length = 32): string {
  let bytes: Uint8Array | Buffer;

  if (typeof window === "undefined") {
    bytes = nodeCrypto!.randomBytes(length);
  } else {
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
