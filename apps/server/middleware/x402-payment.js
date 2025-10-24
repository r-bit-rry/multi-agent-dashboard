/**
 * x402 Payment Middleware
 *
 * Implements HTTP 402 Payment Required standard for instant cryptocurrency payments.
 *
 * IMPORTANT: This is DISABLED by default. To enable:
 * 1. Set X402_ENABLED=true in .env
 * 2. Set X402_WALLET_ADDRESS in .env
 * 3. Install x402 package: npm install x402
 * 4. Enable in index.js (see x402-integration-guide.md)
 *
 * @see https://www.x402.org/ for protocol documentation
 */

const crypto = require('crypto');

// Configuration from environment variables
const X402_CONFIG = {
  enabled: process.env.X402_ENABLED === 'true',
  walletAddress: process.env.X402_WALLET_ADDRESS || '',
  network: process.env.X402_NETWORK || 'base', // base, ethereum, polygon, etc.
  currency: process.env.X402_CURRENCY || 'USDC',
  debug: process.env.X402_DEBUG === 'true'
};

// Pricing configuration - customize these based on your monetization strategy
const PRICING = {
  // Premium API endpoints
  '/api/analytics/advanced': 0.10,
  '/api/historical-data': 0.05,
  '/api/ai-recommendations': 0.02,

  // Agent-to-Agent marketplace (future feature)
  '/api/agent/code-review': 0.50,
  '/api/agent/testing': 0.25,
  '/api/agent/deployment': 1.00,

  // Premium dashboard features
  '/api/dashboard/export': 0.10,
  '/api/dashboard/team-analytics': 0.15,

  // High-volume endpoints (micro-payments)
  '/api/events/stream': 0.001, // per event
  '/api/realtime/updates': 0.001 // per update
};

/**
 * x402 Payment Middleware
 * Checks if payment is required and validates payment headers
 */
function x402Middleware(req, res, next) {
  // Skip if x402 is disabled
  if (!X402_CONFIG.enabled) {
    return next();
  }

  // Skip if no pricing configured for this endpoint
  const price = getEndpointPrice(req.path);
  if (price === null) {
    return next();
  }

  // Check if wallet address is configured
  if (!X402_CONFIG.walletAddress) {
    console.error('[x402] ERROR: X402_WALLET_ADDRESS not configured');
    return res.status(500).json({
      error: 'Payment system misconfigured',
      message: 'Contact administrator'
    });
  }

  // Extract payment proof from headers
  const paymentProof = req.headers['x-payment-proof'];
  const paymentAmount = req.headers['x-payment-amount'];
  const paymentTx = req.headers['x-payment-tx'];

  // If no payment headers, return 402 Payment Required
  if (!paymentProof || !paymentAmount || !paymentTx) {
    return sendPaymentRequired(res, req.path, price);
  }

  // Verify payment
  verifyPayment({
    proof: paymentProof,
    amount: parseFloat(paymentAmount),
    expectedAmount: price,
    txHash: paymentTx,
    walletAddress: X402_CONFIG.walletAddress,
    network: X402_CONFIG.network
  })
  .then(isValid => {
    if (isValid) {
      // Payment verified, log and continue
      logPayment(req, price, paymentTx);
      next();
    } else {
      // Payment invalid
      return sendPaymentRequired(res, req.path, price, 'Invalid payment');
    }
  })
  .catch(error => {
    console.error('[x402] Payment verification error:', error);
    return res.status(402).json({
      error: 'Payment verification failed',
      message: error.message
    });
  });
}

/**
 * Get the price for a specific endpoint
 */
function getEndpointPrice(path) {
  // Exact match
  if (PRICING[path]) {
    return PRICING[path];
  }

  // Pattern matching for dynamic routes
  for (const [pattern, price] of Object.entries(PRICING)) {
    if (matchPattern(path, pattern)) {
      return price;
    }
  }

  return null; // No payment required
}

/**
 * Match dynamic route patterns
 */
function matchPattern(path, pattern) {
  // Convert pattern to regex (simple implementation)
  // e.g., /api/agent/:id -> /api/agent/[^/]+
  const regex = new RegExp('^' + pattern.replace(/:[^/]+/g, '[^/]+') + '$');
  return regex.test(path);
}

/**
 * Send HTTP 402 Payment Required response
 */
function sendPaymentRequired(res, endpoint, price, reason = null) {
  const paymentInfo = {
    status: 402,
    message: 'Payment Required',
    payment: {
      amount: price,
      currency: X402_CONFIG.currency,
      recipient: X402_CONFIG.walletAddress,
      network: X402_CONFIG.network,
      endpoint: endpoint
    },
    instructions: {
      howToPay: 'Send payment via x402-compatible wallet',
      documentation: 'https://www.x402.org/docs',
      headers: {
        'X-Payment-Proof': 'Payment signature',
        'X-Payment-Amount': 'Amount paid in USD',
        'X-Payment-Tx': 'Transaction hash'
      }
    }
  };

  if (reason) {
    paymentInfo.reason = reason;
  }

  if (X402_CONFIG.debug) {
    console.log('[x402] Payment required:', paymentInfo);
  }

  return res.status(402)
    .header('X-Accept-Payment', X402_CONFIG.currency)
    .header('X-Payment-Amount', price.toString())
    .header('X-Payment-Address', X402_CONFIG.walletAddress)
    .header('X-Payment-Network', X402_CONFIG.network)
    .json(paymentInfo);
}

/**
 * Verify payment on blockchain
 *
 * NOTE: This is a placeholder implementation.
 * In production, you need to integrate with actual blockchain verification:
 * - Check transaction exists on blockchain
 * - Verify amount matches
 * - Verify recipient is your wallet
 * - Check transaction is confirmed
 * - Prevent replay attacks
 */
async function verifyPayment(paymentData) {
  const { proof, amount, expectedAmount, txHash, walletAddress, network } = paymentData;

  // TODO: Implement actual blockchain verification
  // This would typically involve:
  // 1. Query blockchain for transaction
  // 2. Verify signature
  // 3. Check amount and recipient
  // 4. Verify transaction is confirmed
  // 5. Check transaction hasn't been used before (prevent replay)

  if (X402_CONFIG.debug) {
    console.log('[x402] Verifying payment:', {
      txHash,
      amount,
      expectedAmount,
      walletAddress,
      network
    });
  }

  // Placeholder: Accept any payment with valid structure
  // REPLACE THIS WITH ACTUAL VERIFICATION
  if (!txHash || !proof || amount < expectedAmount) {
    return false;
  }

  // In production, use x402 SDK or Web3 libraries:
  // const Web3 = require('web3');
  // const web3 = new Web3(networkRpcUrl);
  // const tx = await web3.eth.getTransaction(txHash);
  // ... verify transaction details

  return true; // Placeholder
}

/**
 * Log successful payment
 */
function logPayment(req, amount, txHash) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    endpoint: req.path,
    amount: amount,
    currency: X402_CONFIG.currency,
    txHash: txHash,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  };

  if (X402_CONFIG.debug) {
    console.log('[x402] Payment accepted:', logEntry);
  }

  // TODO: Store in database for analytics
  // Example:
  // db.run(`INSERT INTO payments (endpoint, amount, tx_hash, timestamp)
  //         VALUES (?, ?, ?, ?)`,
  //         [logEntry.endpoint, logEntry.amount, logEntry.txHash, logEntry.timestamp]);
}

/**
 * Get pricing information (public endpoint)
 */
function getPricingInfo() {
  return {
    enabled: X402_CONFIG.enabled,
    currency: X402_CONFIG.currency,
    network: X402_CONFIG.network,
    endpoints: PRICING,
    wallet: X402_CONFIG.enabled ? X402_CONFIG.walletAddress : 'Not configured'
  };
}

// Export middleware and utilities
module.exports = {
  x402Middleware,
  getPricingInfo,
  PRICING,
  X402_CONFIG
};
