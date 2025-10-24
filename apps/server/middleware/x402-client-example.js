/**
 * x402 Client Example
 *
 * This shows how a client (browser, AI agent, or Node.js app) would make
 * a payment-required API request using the x402 protocol.
 *
 * This is for REFERENCE ONLY - not used by the server.
 */

// ============================================================================
// EXAMPLE 1: Browser/Frontend Integration
// ============================================================================

/**
 * Example: Browser fetch with x402 payment
 * Requires Web3 wallet like MetaMask
 */
async function fetchWithPayment(endpoint, options = {}) {
  const API_URL = 'http://localhost:3001';

  // Step 1: Try request without payment
  const response = await fetch(`${API_URL}${endpoint}`, options);

  // Step 2: If 402 Payment Required, handle payment
  if (response.status === 402) {
    const paymentInfo = await response.json();

    console.log('Payment required:', paymentInfo);
    console.log(`Amount: ${paymentInfo.payment.amount} ${paymentInfo.payment.currency}`);
    console.log(`Recipient: ${paymentInfo.payment.recipient}`);

    // Step 3: Show payment UI to user or auto-pay with agent wallet
    const paymentProof = await makePayment(paymentInfo.payment);

    // Step 4: Retry request with payment headers
    const paidResponse = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        'X-Payment-Proof': paymentProof.signature,
        'X-Payment-Amount': paymentProof.amount.toString(),
        'X-Payment-Tx': paymentProof.txHash
      }
    });

    return paidResponse.json();
  }

  // Step 5: If payment successful or not required, return data
  return response.json();
}

/**
 * Make payment via Web3 wallet (MetaMask example)
 */
async function makePayment(paymentInfo) {
  // Check if Web3 is available (MetaMask, Coinbase Wallet, etc.)
  if (typeof window.ethereum === 'undefined') {
    throw new Error('No Web3 wallet found. Install MetaMask or similar.');
  }

  // Request wallet connection
  await window.ethereum.request({ method: 'eth_requestAccounts' });

  // Get Web3 provider
  const provider = new ethers.providers.Web3Provider(window.ethereum);
  const signer = provider.getSigner();

  // Convert USD to USDC amount (USDC has 6 decimals)
  const amountInUSDC = ethers.utils.parseUnits(
    paymentInfo.amount.toString(),
    6 // USDC decimals
  );

  // Get USDC contract address for network
  const USDC_ADDRESSES = {
    'base': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    'ethereum': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    'polygon': '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174'
  };

  const usdcAddress = USDC_ADDRESSES[paymentInfo.network];

  // USDC ERC20 contract ABI (minimal)
  const USDC_ABI = [
    'function transfer(address to, uint256 amount) returns (bool)',
    'function balanceOf(address account) view returns (uint256)'
  ];

  // Create USDC contract instance
  const usdcContract = new ethers.Contract(usdcAddress, USDC_ABI, signer);

  // Check balance
  const balance = await usdcContract.balanceOf(await signer.getAddress());
  if (balance.lt(amountInUSDC)) {
    throw new Error('Insufficient USDC balance');
  }

  // Send USDC payment
  const tx = await usdcContract.transfer(paymentInfo.recipient, amountInUSDC);

  // Wait for confirmation
  const receipt = await tx.wait();

  // Create payment proof
  const message = `Payment of ${paymentInfo.amount} USDC for ${paymentInfo.endpoint}`;
  const signature = await signer.signMessage(message);

  return {
    signature: signature,
    amount: paymentInfo.amount,
    txHash: receipt.transactionHash,
    blockNumber: receipt.blockNumber
  };
}

/**
 * Usage example in React component
 */
async function exampleReactUsage() {
  try {
    // Fetch premium analytics (costs $0.10)
    const analytics = await fetchWithPayment('/api/analytics/advanced');
    console.log('Analytics data:', analytics);

    // Fetch historical data (costs $0.05)
    const historical = await fetchWithPayment('/api/historical-data');
    console.log('Historical data:', historical);

  } catch (error) {
    console.error('Payment or request failed:', error);
    alert('Payment failed: ' + error.message);
  }
}

// ============================================================================
// EXAMPLE 2: AI Agent Integration (Node.js)
// ============================================================================

/**
 * Example: AI Agent with autonomous payments
 * The agent has its own wallet and can pay for API access automatically
 */
class AIAgentWithWallet {
  constructor(privateKey, walletAddress) {
    this.privateKey = privateKey;
    this.walletAddress = walletAddress;
    this.provider = new ethers.providers.JsonRpcProvider(
      'https://base-mainnet.infura.io/v3/YOUR-API-KEY'
    );
    this.wallet = new ethers.Wallet(privateKey, this.provider);
  }

  /**
   * Agent makes API request and auto-pays if needed
   */
  async requestAPI(endpoint) {
    const API_URL = 'http://localhost:3001';

    // Try request
    let response = await fetch(`${API_URL}${endpoint}`);

    // If payment required, auto-pay
    if (response.status === 402) {
      const paymentInfo = await response.json();

      console.log(`[Agent] Payment required: $${paymentInfo.payment.amount}`);
      console.log('[Agent] Auto-paying from agent wallet...');

      // Make payment autonomously
      const proof = await this.payWithAgentWallet(paymentInfo.payment);

      // Retry with payment
      response = await fetch(`${API_URL}${endpoint}`, {
        headers: {
          'X-Payment-Proof': proof.signature,
          'X-Payment-Amount': proof.amount.toString(),
          'X-Payment-Tx': proof.txHash
        }
      });

      console.log('[Agent] Payment successful, got data');
    }

    return response.json();
  }

  /**
   * Agent pays with its own wallet
   */
  async payWithAgentWallet(paymentInfo) {
    const USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // Base USDC
    const USDC_ABI = [
      'function transfer(address to, uint256 amount) returns (bool)'
    ];

    const usdcContract = new ethers.Contract(
      USDC_ADDRESS,
      USDC_ABI,
      this.wallet
    );

    // Convert USD to USDC (6 decimals)
    const amount = ethers.utils.parseUnits(paymentInfo.amount.toString(), 6);

    // Send payment
    const tx = await usdcContract.transfer(paymentInfo.recipient, amount);
    const receipt = await tx.wait();

    // Sign proof
    const message = `Agent payment: ${paymentInfo.amount} USDC`;
    const signature = await this.wallet.signMessage(message);

    return {
      signature,
      amount: paymentInfo.amount,
      txHash: receipt.transactionHash
    };
  }
}

/**
 * Usage: AI Agent autonomously pays for services
 */
async function exampleAgentUsage() {
  // Agent has its own wallet
  const agent = new AIAgentWithWallet(
    'agent-private-key-here',
    '0xAgentWalletAddress'
  );

  // Agent needs code review - automatically pays $0.50
  const codeReview = await agent.requestAPI('/api/agent/code-review');
  console.log('Code review result:', codeReview);

  // Agent needs testing - automatically pays $0.25
  const testResults = await agent.requestAPI('/api/agent/testing');
  console.log('Test results:', testResults);

  // Agent is autonomous - no human interaction needed!
}

// ============================================================================
// EXAMPLE 3: Simple curl-style client (for testing)
// ============================================================================

/**
 * Simple Node.js client for testing x402
 */
async function simpleX402Client(endpoint, walletAddress, privateKey) {
  const API_URL = 'http://localhost:3001';

  // Step 1: Try without payment
  const response = await fetch(`${API_URL}${endpoint}`);

  if (response.status === 402) {
    const paymentInfo = await response.json();

    console.log(`💰 Payment required: $${paymentInfo.payment.amount}`);
    console.log(`   Recipient: ${paymentInfo.payment.recipient}`);
    console.log(`   Network: ${paymentInfo.payment.network}`);

    // For testing, you can mock the payment
    const mockPayment = {
      signature: 'mock_signature_' + Date.now(),
      amount: paymentInfo.payment.amount,
      txHash: '0xmock' + Date.now()
    };

    // Retry with mock payment
    const paidResponse = await fetch(`${API_URL}${endpoint}`, {
      headers: {
        'X-Payment-Proof': mockPayment.signature,
        'X-Payment-Amount': mockPayment.amount.toString(),
        'X-Payment-Tx': mockPayment.txHash
      }
    });

    const data = await paidResponse.json();
    console.log('✅ Got data:', data);
    return data;
  }

  return response.json();
}

// ============================================================================
// TESTING COMMANDS
// ============================================================================

/*
# Test with curl (expects 402)
curl -i http://localhost:3001/api/analytics/advanced

# Test with mock payment
curl -i http://localhost:3001/api/analytics/advanced \
  -H "X-Payment-Proof: mock_sig_123" \
  -H "X-Payment-Amount: 0.10" \
  -H "X-Payment-Tx: 0xmocktxhash123"

# Check pricing info
curl http://localhost:3001/api/pricing
*/

// ============================================================================
// EXPORTS (for use in your app)
// ============================================================================

module.exports = {
  fetchWithPayment,
  makePayment,
  AIAgentWithWallet,
  simpleX402Client
};
