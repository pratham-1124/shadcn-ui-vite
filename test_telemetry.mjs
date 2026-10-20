import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  sanitizeText,
  formatTelemetryEvent,
  computeSignature,
  reportError,
} from './api/_telemetry.js';

test('1. Signature generation matches canonical timestamp:body contract', () => {
  const timestamp = '1729425600';
  const body = JSON.stringify({ message: 'Test error', statusCode: 500 });
  const secret = 'super_secret_test_key_123';

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}:${body}`, 'utf8')
    .digest('hex');

  const actualSig = computeSignature(timestamp, body, secret);
  assert.equal(actualSig, expectedSig);
  assert.equal(/^[a-f0-9]{64}$/.test(actualSig), true);
});

test('2. Sensitive tokens and credentials are redacted from error and stack', () => {
  const leaked = 
    'Error at handler: ghp_1234567890abcdefghijklmnopqrstuvwxyz failed\n' +
    'Vercel: vcp_0987654321zyxwvutsrqponmlkjihgfedcba\n' +
    'Authorization: Bearer my_jwt_token_1234567890\n' +
    'password="super_secret_password_123"\n' +
    'OpenAI: sk-proj-1234567890abcdef1234567890';

  const cleaned = sanitizeText(leaked);
  assert.ok(!cleaned.includes('ghp_123456'));
  assert.ok(cleaned.includes('ghp_***REDACTED***'));

  assert.ok(!cleaned.includes('vcp_098765'));
  assert.ok(cleaned.includes('vcp_***REDACTED***'));

  assert.ok(!cleaned.includes('my_jwt_token'));
  assert.ok(cleaned.includes('Bearer ***REDACTED***'));

  assert.ok(!cleaned.includes('super_secret_password'));
  assert.ok(!cleaned.includes('sk-proj-123456'));
  assert.ok(cleaned.includes('sk-***REDACTED***'));
});

test('3. formatTelemetryEvent bounds message length and strips query params from path', () => {
  const longMsg = 'X'.repeat(1000);
  const err = new Error(longMsg);
  const req = {
    url: '/api/error?token=secret_query_param_leak',
    headers: { 'x-vercel-id': 'iad1::abcde-12345' },
  };

  const event = formatTelemetryEvent(err, req);
  assert.equal(event.source, 'runtime');
  assert.equal(event.level, 'ERROR');
  assert.equal(event.statusCode, 500);
  assert.equal(event.path, '/api/error');
  assert.ok(!event.path.includes('token='));
  assert.equal(event.requestId, 'iad1::abcde-12345');
  assert.ok(event.message.length <= 512 + 1536 + 20);
});

test('4. Gracefully skips when environment variables are missing', async () => {
  const err = new Error('Test missing env');
  const result = await reportError(err, null, {
    drainUrl: '',
    drainSecret: '',
  });
  assert.equal(result, false);
});

test('5. Non-retryable HTTP 401/403/404 halts immediately without retrying', async () => {
  let callCount = 0;
  const mockFetch = async () => {
    callCount++;
    return { status: 401, ok: false };
  };

  const result = await reportError(new Error('Auth failed'), null, {
    drainUrl: 'https://test-drain.example.com/api/drain',
    drainSecret: 'secret123',
    fetchFn: mockFetch,
    maxRetries: 3,
    backoffMs: 10,
  });

  assert.equal(result, false);
  assert.equal(callCount, 1); // Exactly 1 call; no retries for 401
});

test('6. Bounded retry behavior for retryable 502/504 errors', async () => {
  let callCount = 0;
  const mockFetch = async () => {
    callCount++;
    return { status: 502, ok: false };
  };

  const result = await reportError(new Error('Gateway down'), null, {
    drainUrl: 'https://test-drain.example.com/api/drain',
    drainSecret: 'secret123',
    fetchFn: mockFetch,
    maxRetries: 2,
    backoffMs: 10,
  });

  assert.equal(result, false);
  assert.equal(callCount, 3); // 1 initial + 2 retries = 3 calls
});

test('7. Network failure isolation: Never throws even on fatal network crash', async () => {
  const fatalFetch = async () => {
    throw new TypeError('Fatal network connection refused');
  };

  // Must resolve gracefully to false and not throw
  const result = await reportError(new Error('Network failure test'), null, {
    drainUrl: 'https://test-drain.example.com/api/drain',
    drainSecret: 'secret123',
    fetchFn: fatalFetch,
    maxRetries: 1,
    backoffMs: 10,
  });

  assert.equal(result, false);
});

test('8. Successful delivery returns true and sends exact signed body and headers', async () => {
  let capturedUrl = null;
  let capturedHeaders = null;
  let capturedBody = null;

  const mockSuccessFetch = async (url, init) => {
    capturedUrl = url;
    capturedHeaders = init.headers;
    capturedBody = init.body;
    return { status: 200, ok: true };
  };

  const secret = 'prod_secret_test_999';
  const result = await reportError(new Error('Success event'), { url: '/api/error' }, {
    drainUrl: 'https://test-tunnel.example.com/api/observability/drain/conn_test',
    drainSecret: secret,
    fetchFn: mockSuccessFetch,
  });

  assert.equal(result, true);
  assert.equal(capturedUrl, 'https://test-tunnel.example.com/api/observability/drain/conn_test');
  assert.ok(capturedHeaders['x-nexusmind-timestamp']);
  assert.ok(capturedHeaders['x-nexusmind-signature']);
  assert.equal(capturedHeaders['Content-Type'], 'application/json');

  // Verify that the signature on capturedHeaders matches capturedBody exactly
  const ts = capturedHeaders['x-nexusmind-timestamp'];
  const sig = capturedHeaders['x-nexusmind-signature'];
  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${ts}:${capturedBody}`, 'utf8')
    .digest('hex');

  assert.equal(sig, expectedSig);
});

test('9. Generated event ID is stable and present even when requestId is missing', () => {
  const err = new Error('No requestId error');
  const event1 = formatTelemetryEvent(err, null);
  assert.ok(event1.id.startsWith('evt_'));
  assert.ok(event1.id.length > 8);

  const reqWithId = { headers: { 'x-vercel-id': 'req_xyz_123' } };
  const event2 = formatTelemetryEvent(err, reqWithId);
  assert.equal(event2.id, 'evt_req_xyz_123');
});
