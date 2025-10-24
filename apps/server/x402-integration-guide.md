# 🚀 x402 Payment Integration Guide

Dit bestand legt uit hoe je x402 cryptocurrency payments activeert in je Multi-Agent Dashboard.

## 📋 Wat is x402?

x402 is een open standaard voor instant cryptocurrency betalingen via HTTP 402 status code. Perfect voor:
- **AI Agent-to-Agent betalingen** (agents betalen elkaar automatisch)
- **Micropayments** ($0.001 - $1.00 per request)
- **Premium API endpoints** (analytics, exports, etc.)
- **Agent marketplace** (code reviews, testing, deployment services)

**Voordelen:**
- ✅ 0% fees (geen Stripe/PayPal commissies)
- ✅ Instant settlement (geld binnen 2 seconden)
- ✅ Geen account registratie nodig
- ✅ Blockchain agnostic (Base, Ethereum, Polygon, etc.)

## 🔧 Installatie Stappen

### Stap 1: Installeer x402 Package

```bash
cd apps/server
npm install x402
```

### Stap 2: Configureer Environment Variables

Voeg toe aan `apps/server/.env`:

```env
# x402 Payment Configuration
X402_ENABLED=true
X402_WALLET_ADDRESS=0xYourWalletAddressHere
X402_NETWORK=base
X402_CURRENCY=USDC
X402_DEBUG=true
```

**Hoe krijg je een wallet address?**
- Gebruik MetaMask, Coinbase Wallet, of andere Web3 wallet
- Zorg dat het wallet Base/Ethereum network ondersteunt
- Kopieer je wallet address (begint met 0x...)

### Stap 3: Activeer Middleware in index.js

Open `apps/server/index.js` en voeg toe:

```javascript
// Importeer x402 middleware (voeg toe aan top van bestand)
const { x402Middleware, getPricingInfo } = require('./middleware/x402-payment');

// Voeg middleware toe VOOR je protected routes
app.use(x402Middleware);

// Optioneel: Public pricing endpoint
app.get('/api/pricing', (req, res) => {
  res.json(getPricingInfo());
});
```

**Volledige voorbeeld integratie:**

```javascript
const express = require('express');
const { x402Middleware, getPricingInfo } = require('./middleware/x402-payment');

const app = express();

// Basic middleware
app.use(express.json());

// x402 payment middleware (checks before protected routes)
app.use(x402Middleware);

// Your existing routes
app.get('/api/analytics/advanced', (req, res) => {
  // Deze endpoint kost $0.10 (zie pricing config)
  res.json({ data: 'Advanced analytics...' });
});

app.get('/api/historical-data', (req, res) => {
  // Deze endpoint kost $0.05
  res.json({ data: 'Historical data...' });
});

// Public pricing info
app.get('/api/pricing', (req, res) => {
  res.json(getPricingInfo());
});

app.listen(3001);
```

### Stap 4: Pas Pricing Aan (Optioneel)

Edit `apps/server/middleware/x402-payment.js` en pas de `PRICING` object aan:

```javascript
const PRICING = {
  // Jouw custom pricing hier
  '/api/premium-feature': 0.25,
  '/api/export-data': 0.10,

  // Laat endpoints weg die gratis moeten blijven
};
```

### Stap 5: Test de Integratie

**Test met curl:**

```bash
# Test zonder betaling (verwacht 402)
curl -i http://localhost:3001/api/analytics/advanced

# Output:
# HTTP/1.1 402 Payment Required
# X-Accept-Payment: USDC
# X-Payment-Amount: 0.10
# X-Payment-Address: 0xYourWallet...
```

**Test met betaling (mock):**

```bash
curl -i http://localhost:3001/api/analytics/advanced \
  -H "X-Payment-Proof: mock_signature_123" \
  -H "X-Payment-Amount: 0.10" \
  -H "X-Payment-Tx: 0xmocktransactionhash..."

# Output:
# HTTP/1.1 200 OK
# { "data": "Advanced analytics..." }
```

## 🎯 Use Cases voor Multi-Agent Dashboard

### Use Case 1: Premium Analytics Dashboard

```javascript
const PRICING = {
  '/api/analytics/advanced': 0.10,        // Geavanceerde metrics
  '/api/analytics/team-insights': 0.15,   // Team performance
  '/api/export/full-report': 0.25,        // Complete export
};
```

### Use Case 2: Agent Marketplace

```javascript
const PRICING = {
  '/api/agent/code-review': 0.50,      // AI agent doet code review
  '/api/agent/testing': 0.25,          // AI agent draait tests
  '/api/agent/optimization': 0.75,     // AI agent optimaliseert code
  '/api/agent/deployment': 1.00,       // AI agent deployed naar prod
};
```

**Agent-to-Agent betaling flow:**
1. Developer's agent wil code review
2. Agent stuurt request naar `/api/agent/code-review`
3. Server antwoordt: "402 - $0.50 required"
4. Agent's wallet betaalt automatisch $0.50 USDC
5. Agent retries request met payment headers
6. Code review wordt uitgevoerd
7. Geld staat binnen 2 seconden in jouw wallet

### Use Case 3: Real-time Event Streaming (Micropayments)

```javascript
const PRICING = {
  '/api/events/stream': 0.001,  // $0.001 per event
  '/api/realtime/updates': 0.001,
};
```

### Use Case 4: Cloud-Hosted Dashboard (SaaS model)

```javascript
const PRICING = {
  '/api/session/start': 0.01,        // $0.01 per sessie
  '/api/dashboard/load': 0.005,      // $0.005 per dashboard load
  '/api/data/sync': 0.002,           // $0.002 per sync
};
```

## 🔐 Productie Implementatie

**BELANGRIJK:** De huidige implementatie is een **starter template**. Voor productie moet je:

### 1. Echte Blockchain Verificatie Implementeren

```javascript
// Installeer Web3 library
npm install web3

// Update verifyPayment() functie in x402-payment.js
const Web3 = require('web3');
const web3 = new Web3('https://base-mainnet.infura.io/v3/YOUR-API-KEY');

async function verifyPayment(paymentData) {
  const { txHash, amount, expectedAmount, walletAddress } = paymentData;

  // Haal transactie op van blockchain
  const tx = await web3.eth.getTransaction(txHash);

  if (!tx) {
    throw new Error('Transaction not found');
  }

  // Verifieer recipient
  if (tx.to.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error('Wrong recipient');
  }

  // Verifieer amount (convert from wei)
  const paidAmount = parseFloat(web3.utils.fromWei(tx.value, 'mwei')); // USDC heeft 6 decimalen
  if (paidAmount < expectedAmount) {
    throw new Error('Insufficient payment');
  }

  // Check confirmations
  const currentBlock = await web3.eth.getBlockNumber();
  const confirmations = currentBlock - tx.blockNumber;

  if (confirmations < 1) {
    throw new Error('Transaction not confirmed');
  }

  return true;
}
```

### 2. Replay Attack Preventie

Voeg database tracking toe:

```javascript
// In database.js, voeg toe:
db.run(`CREATE TABLE IF NOT EXISTS used_payments (
  tx_hash TEXT PRIMARY KEY,
  used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`);

// In verifyPayment(), check:
const used = await db.get('SELECT * FROM used_payments WHERE tx_hash = ?', [txHash]);
if (used) {
  throw new Error('Payment already used');
}

// Na succesvolle payment:
await db.run('INSERT INTO used_payments (tx_hash) VALUES (?)', [txHash]);
```

### 3. Payment Analytics Dashboard

Voeg tracking toe voor inkomsten:

```javascript
// In database.js
db.run(`CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint TEXT,
  amount REAL,
  currency TEXT,
  tx_hash TEXT,
  user_id TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`);

// In logPayment()
db.run(`INSERT INTO payments (endpoint, amount, currency, tx_hash, user_id)
        VALUES (?, ?, ?, ?, ?)`,
        [endpoint, amount, X402_CONFIG.currency, txHash, req.user?.id]);
```

### 4. Rate Limiting

Prevent abuse:

```javascript
const rateLimit = require('express-rate-limit');

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuut
  max: 100, // Max 100 betaalde requests per minuut per IP
  skip: (req) => !X402_CONFIG.enabled // Skip als x402 disabled
});

app.use(paymentLimiter);
```

## 📊 Monitoring & Analytics

### View Payments Log

```bash
# Check debug logs
tail -f apps/server/logs/x402-payments.log

# Of in Node.js console
[x402] Payment accepted: {
  endpoint: '/api/analytics/advanced',
  amount: 0.10,
  txHash: '0x123...',
  timestamp: '2025-10-24T10:30:00Z'
}
```

### Database Queries

```sql
-- Total revenue vandaag
SELECT SUM(amount) FROM payments
WHERE DATE(timestamp) = DATE('now');

-- Top earning endpoints
SELECT endpoint, COUNT(*), SUM(amount)
FROM payments
GROUP BY endpoint
ORDER BY SUM(amount) DESC;

-- Revenue per dag
SELECT DATE(timestamp), SUM(amount)
FROM payments
GROUP BY DATE(timestamp);
```

## 🧪 Testing

### Unit Tests

```javascript
// test/x402-payment.test.js
const { x402Middleware, getPricingInfo } = require('../middleware/x402-payment');

describe('x402 Payment Middleware', () => {
  test('Should return 402 for unpaid premium endpoint', async () => {
    const req = { path: '/api/analytics/advanced', headers: {} };
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };

    x402Middleware(req, res, () => {});

    expect(res.status).toHaveBeenCalledWith(402);
  });

  test('Should allow free endpoints without payment', async () => {
    const req = { path: '/api/public/data', headers: {} };
    const next = jest.fn();

    x402Middleware(req, {}, next);

    expect(next).toHaveBeenCalled();
  });
});
```

### Integration Tests met echte wallet

```bash
# Test met echte Base testnet
X402_NETWORK=base-goerli \
X402_WALLET_ADDRESS=0xYourTestWallet \
npm test
```

## 🚨 Troubleshooting

### Problem: "Payment system misconfigured"
**Oplossing:** Check dat `X402_WALLET_ADDRESS` is ingesteld in .env

### Problem: "Invalid payment"
**Oplossing:**
- Check dat transaction hash correct is
- Verify dat amount >= required amount
- Check blockchain confirmation

### Problem: Geen 402 responses
**Oplossing:**
- Check dat `X402_ENABLED=true` in .env
- Verify dat middleware VOOR routes staat
- Check dat endpoint in PRICING object staat

### Problem: "Transaction not found"
**Oplossing:**
- Wacht op blockchain confirmatie (1-2 blocks)
- Check dat je op correct network zit
- Verify RPC endpoint werkt

## 📚 Resources

- **x402 Protocol:** https://www.x402.org/
- **x402 Whitepaper:** https://www.x402.org/x402-whitepaper.pdf
- **GitHub:** https://github.com/coinbase/x402
- **Coinbase Developer Platform:** https://www.coinbase.com/developer-platform
- **Base Network:** https://base.org/

## 🤝 Support

Vragen over x402 integratie?
- GitHub Issues: https://github.com/TheAIuniversity/multi-agent-dashboard/issues
- Email: support@theaiuniversity.com

---

**Ready to enable instant crypto payments?** Follow de stappen hierboven en je bent binnen 10 minuten live! 🚀
