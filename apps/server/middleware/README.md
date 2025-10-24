# Middleware Directory

This directory contains Express middleware for the Multi-Agent Dashboard server.

## Available Middleware

### x402-payment.js

**HTTP 402 Payment Required** middleware voor cryptocurrency betalingen.

**Status:** ⚠️ **DISABLED by default** - Klaar voor toekomstig gebruik

**Gebruik:**
```javascript
const { x402Middleware } = require('./middleware/x402-payment');
app.use(x402Middleware);
```

**Configuratie:**
Zie `/apps/server/x402-integration-guide.md` voor complete setup instructies.

**Use Cases:**
- Premium API endpoints ($0.01 - $1.00 per request)
- Agent-to-Agent marketplace betalingen
- Micropayments voor real-time data streams
- Cloud-hosted SaaS model

**Documentatie:**
- Setup guide: `/apps/server/x402-integration-guide.md`
- Protocol docs: https://www.x402.org/

---

## Future Middleware

Andere middleware die hier kunnen worden toegevoegd:
- Rate limiting
- API key authentication
- Request logging
- Error handling
- CORS configuration
