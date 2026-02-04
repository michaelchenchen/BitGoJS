/**
 * Fee validation utilities for detecting unreasonable or dangerous fee amounts
 * 
 * These checks prevent common user errors that lead to loss of funds:
 * - Fat-finger attacks (user pays massive fee by accident)
 * - Arithmetic overflow bugs
 * - Fees exceeding Bitcoin's total supply
 */

export interface FeeValidationOptions {
  /**
   * Maximum allowed fee in satoshis
   * Default: 10,000,000 (0.1 BTC) - following Bitcoin Core's -maxtxfee default
   */
  maxFee?: bigint;

  /**
   * Maximum percentage of input that can go to fees
   * Default: 50 (50%)
   */
  maxFeePercentage?: number;
}

// Bitcoin constants
export const MAX_MONEY = BigInt('2100000000000000'); // 21M BTC in satoshis
export const MAX_INT64 = BigInt('9223372036854775807'); // 2^63 - 1

// Default fee thresholds (following Bitcoin Core standards)
// Bitcoin Core's default -maxtxfee is 0.1 BTC to prevent accidental high fees
export const DEFAULT_MAX_FEE = BigInt('10000000'); // 0.1 BTC
export const DEFAULT_MAX_FEE_PERCENTAGE = 50; // 50% of input

/**
 * Validate transaction fee for reasonableness and safety
 * 
 * Throws if the fee is dangerous or likely a mistake:
 * - Negative fees (outputs > inputs)
 * - Exceeds Bitcoin's total supply (21M BTC)
 * - Exceeds int64 maximum (overflow risk)
 * - Exceeds configured maximum (default 0.1 BTC)
 * - Exceeds percentage of input (default 50%)
 * 
 * @param fee - Fee amount in satoshis
 * @param inputAmount - Total input amount in satoshis
 * @param options - Validation options
 * @throws Error if fee is invalid or dangerous
 */
export function validateFee(
  fee: bigint,
  inputAmount: bigint,
  options: FeeValidationOptions = {}
): void {
  const maxFee = options.maxFee ?? DEFAULT_MAX_FEE;
  const maxFeePercentage = options.maxFeePercentage ?? DEFAULT_MAX_FEE_PERCENTAGE;

  // 1. Negative fee (outputs > inputs)
  if (fee < 0) {
    throw new Error(`Fee cannot be negative: ${fee} satoshis. Outputs exceed inputs.`);
  }

  // 2. Fee exceeds Bitcoin's total supply
  if (fee > MAX_MONEY) {
    throw new Error(
      `Fee of ${fee} satoshis exceeds Bitcoin's maximum supply (${MAX_MONEY} satoshis / 21M BTC). This is physically impossible.`
    );
  }

  // 3. Fee exceeds int64 max (overflow risk)
  if (fee > MAX_INT64) {
    throw new Error(`Fee of ${fee} satoshis exceeds int64 maximum. Potential overflow.`);
  }

  // 4. Fee exceeds configured maximum
  if (fee > maxFee) {
    const btcAmount = Number(fee) / 1e8;
    const maxBtc = Number(maxFee) / 1e8;
    throw new Error(
      `Fee of ${fee} satoshis (${btcAmount} BTC) exceeds maximum allowed fee of ${maxFee} satoshis (${maxBtc} BTC). ` +
      `This is likely a mistake. If this is intentional, use options.maxFee to override the limit.`
    );
  }

  // 5. Fee exceeds percentage of input
  if (inputAmount > 0) {
    const feePercentage = Number((fee * BigInt(100)) / inputAmount);
    if (feePercentage > maxFeePercentage) {
      throw new Error(
        `Fee of ${fee} satoshis is ${feePercentage.toFixed(2)}% of input (${inputAmount} satoshis), ` +
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
