/**
 * @file worker.js
 * @brief Cloudflare Worker that relays Google OAuth token exchange/refresh
 *        requests so the client_secret never ships in extension code.
 *
 * Routes:
 *   POST /token    body: { code, redirect_uri, code_verifier }
 *   POST /refresh  body: { refresh_token }
 */

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

// Restrict which origins may call this relay.
// moz-extension:// origins are dynamic per-install, so we allow any moz-extension/chrome-extension origin.
function isAllowedOrigin(origin) {
  if (!origin) return false;
  return origin.startsWith('moz-extension://') || origin.startsWith('chrome-extension://');
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': isAllowedOrigin(origin) ? origin : 'null',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    if (!isAllowedOrigin(origin)) {
      return new Response(JSON.stringify({ error: 'forbidden_origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'method_not_allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    try {
      let body;
      if (url.pathname === '/token') {
        const { code, redirect_uri, code_verifier } = await request.json();
        if (!code || !redirect_uri || !code_verifier) {
          return jsonError('missing_parameters', origin);
        }
        body = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri,
          grant_type: 'authorization_code',
          code,
          code_verifier,
        });
      } else if (url.pathname === '/refresh') {
        const { refresh_token } = await request.json();
        if (!refresh_token) {
          return jsonError('missing_parameters', origin);
        }
        body = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          grant_type: 'refresh_token',
          refresh_token,
        });
      } else {
        return jsonError('not_found', origin, 404);
      }

      const googleResponse = await fetch(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });

      const data = await googleResponse.json();

      return new Response(JSON.stringify(data), {
        status: googleResponse.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    } catch (err) {
      return jsonError('relay_error: ' + err.message, origin, 500);
    }

    function jsonError(message, origin, status = 400) {
      return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
  },
};