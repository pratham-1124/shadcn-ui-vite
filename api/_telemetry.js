/**
 * _telemetry.js - NexusMind Telemetry Sender (Vercel Serverless Helper)
 *
 * Sends structured observability events to the NexusMind drain receiver at
 * POST /api/observability/drain/{connectionId}.
 *
 * SECURITY RULES enforced here:
 *  - VERCEL_DRAIN_SECRET is read once, trimmed (no print/log), used only for signing.
 *  - NEXUSMIND_CONNECTION_ID is read once, trimmed.
 *  - Each send() call (initial + every retry) generates a FRESH timestamp and HMAC
 *    signature over `{timestamp}:{serialized_body}`.  The serialized body bytes are
 *    identical across retries so receiver-side idempotency (event id deduplication)
 *    prevents duplicate ingestion when the original response was lost.
 *  - On HTTP rejection, ONLY the bounded HTTP status code and the receiver's JSON
 *    `detail` string (<=256 chars) are logged.  Credentials, auth headers, and
 *    event payload bodies are never logged.
 *  - Partial signatures are never logged.
 *
 * IDEMPOTENCY CONTRACT:
 *  - Every event carries a stable `id` field (caller-supplied or deterministic
 *    fingerprint computed here from timestamp + path + message).
 *  - The NexusMind receiver deduplicates by event id inside ObservabilityLogStore.
 *  - Replay protection uses per-request signatures (fresh ts+sig each attempt),
 *    so retries are never blocked by replay detection while still being
 *    deduplicated on the receiver side.
 */

import { createHmac } from 'crypto';

// ---------------------------------------------------------------------------
// Configuration - resolved once, trimmed, never logged or re-printed.
// ---------------------------------------------------------------------------

/**
 * Resolve and trim an environment variable without logging its value.
 * Returns null if the variable is absent or blank after trimming.
 * @param {string} name
 * @returns {string|null}
 */
function _readEnv(name) {
  const raw = process.env[name];
  if (!raw) return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

const DRAIN_SECRET = _readEnv('VERCEL_DRAIN_SECRET');
const CONNECTION_ID = _readEnv('NEXUSMIND_CONNECTION_ID');

// Receiver base URL - defaults to loopback for local dev; override via env.
const RECEIVER_BASE_URL = _readEnv('NEXUSMIND_RECEIVER_URL') || 'http://127.0.0.1:8000';

/** Maximum send attempts (1 initial + N-1 retries). */
const MAX_ATTEMPTS = 3;

/** Base delay in ms for exponential back-off between retries. */
const RETRY_BASE_DELAY_MS = 250;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Compute a deterministic, stable event ID from the supplied fields.
 * The ID is a truncated HMAC-SHA256 hex digest - stable across retries.
 * @param {number} epochMs
 * @param {string} path
 * @param {string} message
 * @returns {string}
 */
function _deterministicId(epochMs, path, message) {
  const fp = `${epochMs}:${path || ''}:${(message || '').slice(0, 200)}`;
  return 'drain_' + createHmac('sha256', 'nexusmind_id_v1').update(fp).digest('hex').slice(0, 20);
}

/**
 * Sign the payload for a single attempt.
 * Each call uses the current wall-clock time so retries get a fresh
 * timestamp and a fresh signature, avoiding replay-protection rejection
 * on the receiver side.
 *
 * @param {string} secret      - The drain secret (already trimmed, never logged).
 * @param {Buffer} bodyBuffer  - The serialized event body (identical across retries).
 * @returns {{ timestamp: string, signature: string }}
 */
function _signAttempt(secret, bodyBuffer) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const sigInput = Buffer.concat([Buffer.from(`${timestamp}:`, 'utf8'), bodyBuffer]);
  const signature = createHmac('sha256', secret).update(sigInput).digest('hex');
  return { timestamp, signature };
}

/**
 * Sleep for `ms` milliseconds.
 * @param {number} ms
 */
function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Send a telemetry event to the NexusMind drain receiver with retry and
 * receiver-side idempotency.
 *
 * - Retries up to MAX_ATTEMPTS times with fresh timestamp+signature per attempt.
 * - On rejection, logs only the HTTP status and bounded `detail` string from
 *   the receiver response.  Never logs the secret, auth headers, or event body.
 * - Returns true on success, false if all attempts fail.
 *
 * @param {Object} event
 * @param {string}  event.message       - Human-readable event description.
 * @param {string}  [event.id]          - Stable caller-supplied event ID (recommended).
 * @param {string}  [event.level]       - 'INFO'|'WARNING'|'ERROR'|'FATAL'. Default: 'INFO'.
 * @param {string}  [event.path]        - HTTP route / function path.
 * @param {number}  [event.statusCode]  - HTTP status code.
 * @param {string}  [event.source]      - 'runtime'|'build'|'request'. Default: 'runtime'.
 * @param {string}  [event.requestId]   - Optional request trace ID.
 * @param {string}  [event.deploymentId] - Optional Vercel deployment ID.
 * @param {number}  [event.timestamp]   - Epoch milliseconds. Defaults to Date.now().
 * @returns {Promise<boolean>}
 */
async function sendTelemetry(event) {
  if (!DRAIN_SECRET) {
    // Misconfiguration - log category only, never the missing value.
    console.warn('[NexusMindTelemetry] misconfiguration: VERCEL_DRAIN_SECRET is not set or blank; telemetry disabled.');
    return false;
  }
  if (!CONNECTION_ID) {
    console.warn('[NexusMindTelemetry] misconfiguration: NEXUSMIND_CONNECTION_ID is not set or blank; telemetry disabled.');
    return false;
  }

  const epochMs = event.timestamp ?? Date.now();

  // Assign a stable event ID before serialization so it is identical on every retry.
  const stableId =
    event.id ||
    _deterministicId(epochMs, event.path || '', event.message || '');

  const eventPayload = {
    id: stableId,
    timestamp: epochMs,
    source: event.source || 'runtime',
    level: event.level || 'INFO',
    message: event.message || '',
    ...(event.path && { path: event.path }),
    ...(event.statusCode !== undefined && { statusCode: event.statusCode }),
    ...(event.requestId && { requestId: event.requestId }),
    ...(event.deploymentId && { deploymentId: event.deploymentId }),
  };

  // Serialize once - body bytes are identical across all retry attempts.
  // This is required so the stable event ID enables receiver-side deduplication.
  const bodyBuffer = Buffer.from(JSON.stringify(eventPayload), 'utf8');
  const drainUrl = `${RECEIVER_BASE_URL}/api/observability/drain/${CONNECTION_ID}`;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    // Fresh timestamp + fresh signature for every attempt.
    // Replay protection (per-signature nonce window) never blocks retries.
    const { timestamp, signature } = _signAttempt(DRAIN_SECRET, bodyBuffer);

    let response;
    try {
      response = await fetch(drainUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Only the signature (not the secret) is sent in the header.
          // The signature value itself is never written to any log.
          'x-nexusmind-signature': signature,
          'x-nexusmind-timestamp': timestamp,
        },
        body: bodyBuffer,
        signal: AbortSignal.timeout(5000),
      });
    } catch (networkErr) {
      // Network-level error (timeout, DNS failure) - log category only.
      console.warn(
        `[NexusMindTelemetry] attempt=${attempt}/${MAX_ATTEMPTS} network_error=${networkErr.name || 'unknown'} event_id=${stableId}`
      );
      if (attempt < MAX_ATTEMPTS) {
        await _sleep(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
      }
      continue;
    }

    if (response.ok) {
      // Success - do not log anything from the response body.
      return true;
    }

    // Parse the bounded rejection reason from the receiver response.
    // Only the HTTP status and the receiver's own `detail` string are logged.
    // Never log credentials, auth headers, or the request body/payload.
    let detail = '';
    try {
      const body = await response.json();
      // `detail` is a short, receiver-generated string (never echoes secrets or bodies).
      detail = typeof body.detail === 'string' ? body.detail.slice(0, 256) : '';
    } catch {
      detail = '(could not parse receiver response)';
    }

    console.warn(
      `[NexusMindTelemetry] attempt=${attempt}/${MAX_ATTEMPTS} http_status=${response.status} rejection_detail=${JSON.stringify(detail)} event_id=${stableId}`
    );

    // 4xx errors (except 429) are non-retryable - the sender cannot fix them by retrying.
    const isRetryable = response.status === 429 || response.status >= 500;
    if (!isRetryable || attempt === MAX_ATTEMPTS) {
      return false;
    }

    await _sleep(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
  }

  return false;
}

export { sendTelemetry };
