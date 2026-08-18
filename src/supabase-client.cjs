'use strict';

// Minimal Supabase client: just enough of the Auth and REST/RPC surface for
// Neutron's account-based licensing (supabase/schema.sql). No SDK dependency
// -- Electron's bundled Node already has fetch, and the surface used here is
// four endpoints, not worth a package for.

const { SUPABASE_URL, SUPABASE_ANON_KEY } = require('./supabase-config.cjs');

const REQUEST_TIMEOUT_MS = 12_000;

async function request(path, { method = 'GET', body, accessToken, headers = {} } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${SUPABASE_URL}${path}`, {
      method,
      signal: controller.signal,
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${accessToken || SUPABASE_ANON_KEY}`,
        'Content-Type': 'application/json',
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch { data = text; }
    }
    if (!response.ok) {
      // Auth endpoints use {error_description|msg}, REST/RPC endpoints use
      // {message}. Neither is guaranteed present (a 5xx can come back with
      // an HTML body from the edge, not JSON), so this always falls through
      // to something readable instead of "[object Object]".
      const message = (data && (data.error_description || data.msg || data.message))
        || (typeof data === 'string' && data)
        || `Hesap hizmeti isteği başarısız (HTTP ${response.status}).`;
      const error = new Error(message);
      error.status = response.status;
      error.code = data && data.error_code;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') {
      const timeoutError = new Error('Neutron hesap hizmetine ulaşılamadı (zaman aşımı).');
      timeoutError.code = 'TIMEOUT';
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

// --- Auth ---------------------------------------------------------------

async function signUp(email, password, metadata) {
  return request('/auth/v1/signup', { method: 'POST', body: { email, password, data: metadata } });
}

async function signInWithPassword(email, password) {
  return request('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
}

async function refreshSession(refreshToken) {
  return request('/auth/v1/token?grant_type=refresh_token', {
    method: 'POST',
    body: { refresh_token: refreshToken },
  });
}

// --- Licenses table / RPCs ------------------------------------------------

// Creates the caller's own licenses row (RLS: user_id must equal auth.uid()).
// Fails with a 409-shaped Postgres error if the row already exists -- that
// is treated as success by the caller, not retried, since it means signup
// ran twice (e.g. the request succeeded but the response was lost).
async function createLicenseRequest(accessToken, customerName) {
  return request('/rest/v1/licenses', {
    method: 'POST',
    accessToken,
    headers: { Prefer: 'return=minimal' },
    body: { customer_name: customerName },
  });
}

// The one call the app makes on every launch and periodic revalidation.
// Licensing belongs to the approved account, not to a particular device.
async function heartbeat(accessToken, appVersion) {
  const rows = await request('/rest/v1/rpc/heartbeat', {
    method: 'POST',
    accessToken,
    // Keeps the deployed RPC signature stable while deliberately omitting any
    // device identity. Approved account status is the only access decision.
    body: { p_device_hash: null, p_version: appVersion },
  });
  // Postgres functions returning `table(...)` come back from PostgREST as an
  // array of rows even when there is exactly one -- heartbeat() always
  // returns 0 or 1 rows by construction (one licenses row per user_id).
  return Array.isArray(rows) ? rows[0] : rows;
}

// Display-only fields (customer_name/edition), read directly off the row via
// the licenses_select_own RLS policy. Deliberately not part of heartbeat()'s
// response -- the active/pending/revoked decision must never depend on a
// field that only exists to be shown in a UI card.
async function getOwnLicense(accessToken) {
  const rows = await request(
    '/rest/v1/licenses?select=customer_name,edition,status,expires_at&limit=1',
    { accessToken },
  );
  return Array.isArray(rows) ? rows[0] : rows;
}

module.exports = {
  signUp,
  signInWithPassword,
  refreshSession,
  createLicenseRequest,
  heartbeat,
  getOwnLicense,
};
