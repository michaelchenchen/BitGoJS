/**
 * Fee validation utilities for detecting unreasonable or dangerous fee amounts
 * 
 * These checks prevent common user errors that lead to loss of funds:
 * - Fat-finger attacks (user pays massive fee by accident)
 * - Arithmetic overflow bugs
 * - Fees exceeding the coin's total supply
 */

import { Network, NetworkName } from '../networks';

export interface FeeValidationOptions {
  /**
   * Maximum allowed fee in base units (satoshis for BTC, litoshis for LTC, etc.)
   * Default: Varies by network (0.1 BTC, 1 LTC, 100 DOGE, etc.)
   */
  maxFee?: bigint;

  /**
   * Maximum percentage of input that can go to fees
   * Default: 50 (50%)
   */
  maxFeePercentage?: number;
}

// Int64 maximum (applies to all coins)
export const MAX_INT64 = BigInt('9223372036854775807'); // 2^63 - 1

// Maximum money supply by network (in base units)
// Dogecoin has no hard cap, so we use a very high limit
const MAX_MONEY_BY_NETWORK: Record<string, bigint> = {
  bitcoin: BigInt('2100000000000000'),          // 21M BTC
  testnet: BigInt('2100000000000000'),          // 21M BTC
  bitcoinPublicSignet: BigInt('2100000000000000'),
  bitcoinTestnet4: BigInt('2100000000000000'),
  bitcoinBitGoSignet: BigInt('2100000000000000'),
  bitcoincash: BigInt('2100000000000000'),      // 21M BCH
  bitcoincashTestnet: BigInt('2100000000000000'),
  ecash: BigInt('21000000000000000'),           // 21M XEC (but 2 more decimals)
  ecashTest: BigInt('21000000000000000'),
  bitcoingold: BigInt('2100000000000000'),      // 21M BTG
  bitcoingoldTestnet: BigInt('2100000000000000'),
  bitcoinsv: BigInt('2100000000000000'),        // 21M BSV
  bitcoinsvTestnet: BigInt('2100000000000000'),
  dash: BigInt('1900000000000000'),             // ~19M DASH
  dashTest: BigInt('1900000000000000'),
  litecoin: BigInt('8400000000000000'),         // 84M LTC (4x Bitcoin)
  litecoinTest: BigInt('8400000000000000'),
  zcash: BigInt('2100000000000000'),            // 21M ZEC
  zcashTest: BigInt('2100000000000000'),
  dogecoin: BigInt('100000000000000000000'),    // 100B DOGE (no cap, but reasonable upper bound)
  dogecoinTest: BigInt('100000000000000000000'),
};

// Default maximum fee by network (in base units)
// Based on typical transaction values and network fee markets
const DEFAULT_MAX_FEE_BY_NETWORK: Record<string, bigint> = {
  bitcoin: BigInt('10000000'),           // 0.1 BTC (Bitcoin Core default)
  testnet: BigInt('10000000'),
  bitcoinPublicSignet: BigInt('10000000'),
  bitcoinTestnet4: BigInt('10000000'),
  bitcoinBitGoSignet: BigInt('10000000'),
  bitcoincash: BigInt('10000000'),       // 0.1 BCH
  bitcoincashTestnet: BigInt('10000000'),
  ecash: BigInt('1000000'),              // 0.01 XEC (2 extra decimals)
  ecashTest: BigInt('1000000'),
  bitcoingold: BigInt('10000000'),       // 0.1 BTG
  bitcoingoldTestnet: BigInt('10000000'),
  bitcoinsv: BigInt('10000000'),         // 0.1 BSV
  bitcoinsvTestnet: BigInt('10000000'),
  dash: BigInt('10000000'),              // 0.1 DASH
  dashTest: BigInt('10000000'),
  litecoin: BigInt('100000000'),         // 1 LTC (worth ~1/4 of BTC, but 4x supply)
  litecoinTest: BigInt('100000000'),
  zcash: BigInt('10000000'),             // 0.1 ZEC
  zcashTest: BigInt('10000000'),
  dogecoin: BigInt('10000000000'),       // 100 DOGE (typical fee is 1-5 DOGE)
  dogecoinTest: BigInt('10000000000'),
};

export const DEFAULT_MAX_FEE_PERCENTAGE = 50; // 50% of input

/**
 * Get maximum money supply for a network
 */
export function getMaxMoney(network: Network): bigint {
  const networkName = getNetworkName(network);
  return MAX_MONEY_BY_NETWORK[networkName] || BigInt('2100000000000000');
}

/**
 * Get default maximum fee for a network
 */
export function getDefaultMaxFee(network: Network): bigint {
  const networkName = getNetworkName(network);
  return DEFAULT_MAX_FEE_BY_NETWORK[networkName] || BigInt('10000000');
}

/**
 * Get network name from Network object
 * Uses the deprecated 'coin' property as a fallback identifier
 */
function getNetworkName(network: Network): string {
  // Try to find the network by matching properties
  // This is a bit hacky but necessary since Network doesn't have a name property
  const coinMap: Record<string, string> = {
    'btc': 'bitcoin',
    'bch': 'bitcoincash',
    'bcha': 'ecash',
    'bsv': 'bitcoinsv',
    'btg': 'bitcoingold',
    'ltc': 'litecoin',
    'zec': 'zcash',
    'dash': 'dash',
    'doge': 'dogecoin',
  };
  return coinMap[network.coin] || 'bitcoin';
}

/**
 * Validate transaction fee for reasonableness and safety
 * 
 * Throws if the fee is dangerous or likely a mistake:
 * - Negative fees (outputs > inputs)
 * - Exceeds coin's total supply
 * - Exceeds int64 maximum (overflow risk)
 * - Exceeds configured maximum (defaults vary by network)
 * - Exceeds percentage of input (default 50%)
 * 
 * @param fee - Fee amount in base units (satoshis, litoshis, etc.)
 * @param inputAmount - Total input amount in base units
 * @param network - Network to get appropriate limits
 * @param options - Validation options (overrides network defaults)
 * @throws Error if fee is invalid or dangerous
 */
export function validateFee(
  fee: bigint,
  inputAmount: bigint,
  network: Network,
  options: FeeValidationOptions = {}
): void {
  const maxMoney = getMaxMoney(network);
  const maxFee = options.maxFee ?? getDefaultMaxFee(network);
  const maxFeePercentage = options.maxFeePercentage ?? DEFAULT_MAX_FEE_PERCENTAGE;

  // 1. Negative fee (outputs > inputs)
  if (fee < 0) {
    throw new Error(`Fee cannot be negative: ${fee}. Outputs exceed inputs.`);
  }

  // 2. Fee exceeds coin's total supply
  if (fee > maxMoney) {
    const coinAmount = Number(fee) / 1e8;
    const maxCoinAmount = Number(maxMoney) / 1e8;
    throw new Error(
      `Fee of ${fee} (${coinAmount.toFixed(8)}) exceeds coin's maximum supply (${maxMoney} / ${maxCoinAmount.toFixed(0)}). ` +
      `This is physically impossible.`
    );
  }

  // 3. Fee exceeds int64 max (overflow risk)
  if (fee > MAX_INT64) {
    throw new Error(`Fee of ${fee} exceeds int64 maximum. Potential overflow.`);
  }

  // 4. Fee exceeds configured maximum
  if (fee > maxFee) {
    const feeAmount = Number(fee) / 1e8;
    const maxAmount = Number(maxFee) / 1e8;
    throw new Error(
      `Fee of ${fee} (${feeAmount.toFixed(8)}) exceeds maximum allowed fee of ${maxFee} (${maxAmount.toFixed(8)}). ` +
      `This is likely a mistake. If this is intentional, use options.maxFee to override the limit.`
    );
  }

  // 5. Fee exceeds percentage of input
  if (inputAmount > 0) {
    const feePercentage = Number((fee * BigInt(100)) / inputAmount);
    if (feePercentage > maxFeePercentage) {
      throw new Error(
        `Fee of ${fee} is ${feePercentage.toFixed(2)}% of input (${inputAmount}), ` +
        `exceeding ${maxFeePercentage}% limit. This is likely a mistake. ` +
        `If this is intentional, use options.maxFeePercentage to override the limit.`
      );
    }
  }
}

/**
 * Check if a fee amount is considered "dust" (uneconomical to spend)
 * 
 * @param amount - Amount in satoshis
 * @param scriptType - Type of script (affects dust threshold)
 * @returns true if amount is dust
 */
export function isDust(amount: bigint, scriptType: 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2wsh' | 'p2tr' = 'p2pkh'): boolean {
  // Dust thresholds from Bitcoin Core
  const dustThresholds: Record<string, bigint> = {
    p2pkh: BigInt(546),
    p2sh: BigInt(540),
    p2wpkh: BigInt(294),
    p2wsh: BigInt(330),
    p2tr: BigInt(330),
  };

  return amount < dustThresholds[scriptType];
}
