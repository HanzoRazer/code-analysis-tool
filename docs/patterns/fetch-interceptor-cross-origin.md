# Fetch Interceptor for Cross-Origin API Calls

## Problem

When deploying a frontend (Vue, React, etc.) separately from its API backend:
- Frontend at: `https://myapp-client.railway.app`
- API at: `https://myapp-api.railway.app`

All hardcoded `fetch('/api/...')` calls fail because they resolve to the client domain, not the API domain.

**Symptom:** Console shows `SyntaxError: Unexpected token '<'` because the client returns HTML 404 instead of JSON.

## Solution

Add a global fetch interceptor in `main.ts` that rewrites `/api/*` URLs to use the API base URL.

### TypeScript/Vue Implementation

```typescript
// main.ts - Add BEFORE createApp()

const API_BASE = import.meta.env.VITE_API_BASE || '';

if (API_BASE) {
  const originalFetch = window.fetch;
  window.fetch = function(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    let url: string;
    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof URL) {
      url = input.href;
    } else if (input instanceof Request) {
      url = input.url;
    } else {
      url = String(input);
    }

    // Rewrite /api/* URLs to use API_BASE
    if (url.startsWith('/api/') || url.startsWith('/api?')) {
      const newUrl = `${API_BASE}${url}`;
      if (typeof input === 'string') {
        return originalFetch.call(this, newUrl, init);
      } else if (input instanceof Request) {
        return originalFetch.call(this, new Request(newUrl, input), init);
      } else {
        return originalFetch.call(this, newUrl, init);
      }
    }

    return originalFetch.call(this, input, init);
  };
  console.info('[fetch-interceptor] API calls routed to', API_BASE);
}
```

### Environment Configuration

```env
# .env.production
VITE_API_BASE=https://myapp-api.railway.app
```

### React Implementation

Same code, add to `index.tsx` before `ReactDOM.render()`.

## Why This Works

1. **Single point of fix** - No need to modify 100+ files with hardcoded paths
2. **Transparent** - Existing code continues to work unchanged
3. **Dev-friendly** - Only activates when `VITE_API_BASE` is set (production)
4. **Handles all fetch variants** - string URLs, URL objects, Request objects

## When to Use

- Deploying frontend/backend to separate domains (Railway, Vercel, etc.)
- Migrating from monolith to microservices
- Legacy codebases with many hardcoded `/api/` paths

## Alternatives Considered

| Approach | Pros | Cons |
|----------|------|------|
| Fix each file | Precise | 84+ files to modify |
| Proxy in nginx | Clean separation | Requires infrastructure |
| **Fetch interceptor** | **Single fix, works everywhere** | Slightly magical |

## Testing

1. Deploy with `VITE_API_BASE` set
2. Open browser console
3. Look for: `[fetch-interceptor] API calls routed to https://...`
4. Verify API calls succeed (no "unexpected token" errors)

## Origin

Developed for luthiers-toolbox Railway deployment (Feb 2026).
Fixed 84+ files with hardcoded `/api/` paths in one commit.
