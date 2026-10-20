import crypto from 'node:crypto';

const MAX_MESSAGE_LENGTH = 512;
const MAX_STACK_LENGTH = 1536;
const DEFAULT_TIMEOUT_MS = 2500;
const MAX_RETRIES = 2; // Total 3 attempts (initial + 2 retries)
const INITIAL_BACKOFF_MS = 150;

/**
 * Redact obvious credentials, tokens, and secrets from text.
 */
export function sanitizeText(text) {
  if (!text || typeof text !== 'string') return '';
  return text
    // Redact GitHub personal access tokens
    .replace(/gh[pousr]_[A-Za-z0-9_]{16,255}/g, 'ghp_***REDACTED***')
    // Redact Vercel tokens
    .replace(/vcp_[A-Za-z0-9_]{16,255}/g, 'vcp_***REDACTED***')
    // Redact Bearer tokens
    .replace(/(Bearer\s+)[A-Za-z0-9_\-\.]{12,}/gi, '$1***REDACTED***')
    // Redact password, secret, token, api_key assignments
    .replace(
      /(?:password|secret|token|api[_-]?key|auth(?:orization)?)\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{8,}['"]?/gi,
      '***REDACTED***'
    )
    // Redact OpenAI style keys
    .replace(/\bsk-[A-Za-z0-9_\-]{20,}\b/g, 'sk-***REDACTED***');
}

/**
 * Format and sanitize an application-level runtime exception.
 * Transmits only error metadata and path; never includes request bodies, cookies,
 * authorization headers, or environment variables.
 */
export function formatTelemetryEvent(error, req = null) {
  const rawMsg = error?.message || String(error || 'Unknown runtime error');
  const cleanMsg = sanitizeText(rawMsg).slice(0, MAX_MESSAGE_LENGTH);

  let stack = error?.stack ? sanitizeText(error.stack) : '';
  if (stack.length > MAX_STACK_LENGTH) {
    stack = stack.slice(0, MAX_STACK_LENGTH) + '\n...[truncated]';
  }

  // Combine message and stack into full message field for ingestion normalizer
  const fullMessage =
    stack && !stack.includes(cleanMsg) ? `${cleanMsg}\n${stack}` : stack || cleanMsg;

  // Extract path safely, stripping query parameters and potential secrets
  let routePath = '/api/error';
  let requestId = null;
  if (req) {
    if (req.url) {
      try {
        const parsed = new URL(req.url, 'http://localhost');
        routePath = parsed.pathname;
      } catch {
        routePath = typeof req.url === 'string' ? req.url.split('?')[0] : '/api/error';
      }
    }
    requestId = req.headers?.['x-vercel-id'] || req.headers?.['x-request-id'] || null;
  }

  const eventId = requestId
    ? `evt_${requestId}`
    : `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

  return {
    id: eventId,
    source: 'runtime',
    level: 'ERROR',
    message: fullMessage,
    statusCode: 500,
    path: routePath,
    timestamp: Date.now(),
    requestId: requestId,
  };
}

/**
 * Compute cryptographic HMAC-SHA256 signature over timestamp:rawBody.
 */
export function computeSignature(timestamp, rawBody, secret) {
  const contentToSign = `${timestamp}:${rawBody}`;
  return crypto.createHmac('sha256', secret).update(contentToSign, 'utf8').digest('hex');
}

/**
 * Send telemetry event to NexusMind ingestion gateway with bounded retries and timeout.
 * Guaranteed never to throw, never to cause secondary errors, and never to expose secrets.
 */
export async function reportError(error, req = null, options = {}) {
  try {
    // Read from server-only environment variables (not exposed to client Vite bundle)
    const drainUrl = options.drainUrl || process.env.NEXUSMIND_DRAIN_URL;
    const drainSecret = options.drainSecret || process.env.VERCEL_DRAIN_SECRET;

    // Gracefully skip if telemetry is not configured
    if (!drainUrl || !drainSecret) {
      return false;
    }

    const event = formatTelemetryEvent(error, req);
    const rawBody = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signature = computeSignature(timestamp, rawBody, drainSecret);

    const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    const maxRetries = typeof options.maxRetries === 'number' ? options.maxRetries : MAX_RETRIES;
    const fetchFn = options.fetchFn || globalThis.fetch;

    let attempt = 0;
    while (attempt <= maxRetries) {
      attempt++;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetchFn(drainUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-nexusmind-timestamp': timestamp,
            'x-nexusmind-signature': signature,
          },
          body: rawBody,
          signal: controller.signal,
        });

        clearTimeout(timer);

        // Success
        if (response.status >= 200 && response.status < 300) {
          return true;
        }

        // Permanent client error (400, 401, 403, 404, 413) -> do not retry
        if (response.status >= 400 && response.status < 500 && response.status !== 429) {
          console.warn(
            `[NexusMind Telemetry] Ingestion rejected with HTTP ${response.status}. Not retrying.`
          );
          return false;
        }

        // Retryable server error (500, 502, 503, 504, 429)
        if (attempt <= maxRetries) {
          const backoff = (options.backoffMs || INITIAL_BACKOFF_MS) * Math.pow(2, attempt - 1);
          await new Promise((res) => setTimeout(res, backoff));
        }
      } catch (err) {
        clearTimeout(timer);
        // Network failure or timeout
        if (attempt <= maxRetries) {
          const backoff = (options.backoffMs || INITIAL_BACKOFF_MS) * Math.pow(2, attempt - 1);
          await new Promise((res) => setTimeout(res, backoff));
        } else {
          console.warn(
            `[NexusMind Telemetry] Ingestion network delivery failed: ${err.name || 'NetworkError'}`
          );
          return false;
        }
      }
    }

    return false;
  } catch (fatalErr) {
    // Safety guard: Never throw, never crash host application
    console.warn(`[NexusMind Telemetry] Internal helper error: ${fatalErr.name || 'Error'}`);
    return false;
  }
}
