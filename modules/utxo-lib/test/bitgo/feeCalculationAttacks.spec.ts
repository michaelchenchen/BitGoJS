import * as assert from 'assert';
import { describe, it } from 'mocha';
import { networks } from '../../src/networks';
import { 
  UtxoPsbt, 
  getTransactionAmountsFromPsbt,
  createPsbtForNetwork,
  MAX_MONEY,
} from '../../src/bitgo';

/**
 * Critical Security Tests: Fee Calculation Edge Cases & Attack Vectors
 * 
 * Fee = sum(inputs) - sum(outputs)
 * 
 * Attack scenarios:
 * 1. Negative fees (outputs > inputs)
 * 2. Overflow attacks (sum > int64 max)
 * 3. Absurd fees (user pays everything to miners)
 * 4. Missing UTXO data (calculation impossible)
 * 5. Exceeding Bitcoin's max supply (21M BTC)
 * 
 * Historical bugs:
 * - CVE-2018-17144: Amount overflow allowed creating Bitcoin from nothing
 * - Various wallets: Fee calculation bugs leading to loss of funds
 */

describe('Fee Calculation Edge Cases (Security Critical)', function () {
  this.timeout(10000);
  
  const network = networks.bitcoin;
  const MAX_INT64 = BigInt('9223372036854775807'); // 2^63 - 1

  function createPsbtWithAmounts(
    inputAmounts: bigint[],
    outputAmounts: bigint[]
  ): UtxoPsbt<bigint> {
    const psbt = createPsbtForNetwork({ network });
    
    // Add dummy inputs with specified amounts
    inputAmounts.forEach((amount, i) => {
      const dummyTx = Buffer.alloc(32, i);
      dummyTx[0] = 0x01; // Not coinbase
      
      psbt.addInput({
        hash: dummyTx,
        index: 0,
        witnessUtxo: {
          script: Buffer.alloc(20), // dummy script
          value: amount,
        },
      });
    });
    
    // Add outputs with specified amounts
    outputAmounts.forEach((amount) => {
      psbt.addOutput({
        script: Buffer.alloc(20), // dummy script
        value: amount,
      });
    });
    
    return psbt;
  }

  describe('Normal fee calculations', function () {
    it('should calculate fee correctly for simple transaction', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(10000)],
        [BigInt(9000)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.inputAmount, BigInt(10000));
      assert.strictEqual(amounts.outputAmount, BigInt(9000));
      assert.strictEqual(amounts.fee, BigInt(1000));
    });

    it('should handle multiple inputs and outputs', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(5000), BigInt(3000), BigInt(2000)],
        [BigInt(8000), BigInt(1500)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.inputAmount, BigInt(10000));
      assert.strictEqual(amounts.outputAmount, BigInt(9500));
      assert.strictEqual(amounts.fee, BigInt(500));
    });

    it('should handle 1 satoshi amounts', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(1)],
        [BigInt(1)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.fee, BigInt(0));
    });

    it('should allow skipping fee validation', function () {
      // Create transaction with absurdly high fee
      const psbt = createPsbtWithAmounts(
        [BigInt(100000000)], // 1 BTC input
        [BigInt(1000)]       // Tiny output - 0.999 BTC fee!
      );
      
      // Should throw by default
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds maximum allowed fee/
      );
      
      // Should work with skipFeeValidation
      const amounts = getTransactionAmountsFromPsbt(psbt, { skipFeeValidation: true });
      assert.strictEqual(amounts.fee, BigInt(99999000));
    });
  });

  describe('Negative fee attacks', function () {
    it('should reject negative fee (outputs > inputs)', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(10000)],
        [BigInt(10001)]
      );
      
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /Fee cannot be negative/,
        'Should throw on negative fee'
      );
    });

    it('should reject large negative fee', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(100000)],
        [BigInt(200000)]
      );
      
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /Fee cannot be negative/,
        'Should throw on large negative fee'
      );
    });
  });

  describe('Absurd fee attacks', function () {
    it('should reject absurdly high fee (99% of input)', function () {
      const input = BigInt(100000000); // 1 BTC
      const output = BigInt(1000000);  // 0.01 BTC
      
      const psbt = createPsbtWithAmounts([input], [output]);
      
      // Fee is 0.99 BTC - should be rejected (exceeds both 0.1 BTC limit and 50% percentage limit)
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds maximum allowed fee|exceeding 50% limit/,
        'Should reject fee >50% of input or >0.1 BTC'
      );
    });

    it('should reject fee exceeding Bitcoin total supply', function () {
      // Create input larger than all Bitcoin that will ever exist
      const psbt = createPsbtWithAmounts(
        [MAX_MONEY + BigInt(1000000)],
        [BigInt(500000)] // Fee will be MAX_MONEY + 500000
      );
      
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds Bitcoin's maximum supply/,
        'Should reject fee exceeding MAX_MONEY'
      );
    });

    it('should reject all funds going to fee', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(50000000)],
        [BigInt(1)] // Almost nothing to recipient
      );
      
      // 99.99998% going to miners - should be rejected by both limits
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds maximum allowed fee|exceeding 50% limit/,
        'Should reject when >99% goes to fee'
      );
    });

    it('should allow configuring higher fee limits', function () {
      const input = BigInt(100000000); // 1 BTC
      const output = BigInt(1000000);  // 0.01 BTC
      
      const psbt = createPsbtWithAmounts([input], [output]);
      
      // Should throw with default limits
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds maximum allowed fee|exceeding 50% limit/
      );
      
      // Should work with custom limits (both maxFee and percentage)
      const amounts = getTransactionAmountsFromPsbt(psbt, { 
        maxFee: BigInt('100000000'), // 1 BTC
        maxFeePercentage: 99 
      });
      assert.strictEqual(amounts.fee, BigInt(99000000)); // 0.99 BTC fee
    });
  });

  describe('Amount overflow attacks', function () {
    it('should handle input sum near MAX_SAFE_INTEGER', function () {
      const largeAmount = BigInt(Number.MAX_SAFE_INTEGER) - BigInt(1000);
      
      const psbt = createPsbtWithAmounts(
        [largeAmount],
        [largeAmount - BigInt(500)]
      );
      
      // Fee is 500 sats - well under limits, should pass
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.fee, BigInt(500));
    });

    it('should reject multiple inputs with fee near int64 max', function () {
      const amount = BigInt('4611686018427387903'); // ~2^62
      
      const psbt = createPsbtWithAmounts(
        [amount, amount], // Sum approaches int64 max
        [BigInt(1000000)]
      );
      
      // Fee would be astronomically high - should be rejected
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds Bitcoin's maximum supply|exceeds int64 maximum/,
        'Should reject fee near int64 max'
      );
    });

    it('should detect sum exceeding MAX_MONEY', function () {
      // Create a fee that exceeds MAX_MONEY
      // Input: MAX_MONEY + 1M, Output: 100, Fee: MAX_MONEY + 999,900
      const input = MAX_MONEY + BigInt(1000000);
      const output = BigInt(100);
      
      const psbt = createPsbtWithAmounts([input], [output]);
      
      // Without validation, we can see the calculation
      const amounts = getTransactionAmountsFromPsbt(psbt, { skipFeeValidation: true });
      assert.ok(amounts.fee > MAX_MONEY, `Fee ${amounts.fee} should exceed MAX_MONEY ${MAX_MONEY}`);
      
      // With validation, should be rejected
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds Bitcoin's maximum supply/,
        'Should reject when fee exceeds MAX_MONEY'
      );
    });

    it('should detect very large fees', function () {
      const veryLarge = BigInt('18446744073709551615'); // 2^64 - 1 (uint64 max)
      
      const psbt = createPsbtWithAmounts(
        [veryLarge],
        [BigInt(1000)]
      );
      
      // Without validation, we can see the calculation
      const amounts = getTransactionAmountsFromPsbt(psbt, { skipFeeValidation: true });
      assert.ok(amounts.fee > MAX_MONEY, 'Fee exceeds MAX_MONEY');
      assert.ok(amounts.fee > BigInt('9223372036854775807'), 'Fee exceeds int64 max');
      
      // With validation, should be rejected
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds int64 maximum|exceeds Bitcoin's maximum supply/,
        'Should reject fee exceeding int64 max'
      );
    });

    it('should allow large amounts with skipFeeValidation', function () {
      const veryLarge = BigInt('18446744073709551615'); // 2^64 - 1 (uint64 max)
      
      const psbt = createPsbtWithAmounts(
        [veryLarge],
        [BigInt(1000)]
      );
      
      // Should work when validation is skipped
      const amounts = getTransactionAmountsFromPsbt(psbt, { skipFeeValidation: true });
      assert.strictEqual(amounts.inputAmount, veryLarge);
      assert.ok(amounts.fee > MAX_MONEY, 'Fee exceeds MAX_MONEY');
    });
  });

  describe('Missing UTXO data (error paths)', function () {
    it('should throw when witnessUtxo is missing', function () {
      const psbt = createPsbtForNetwork({ network });
      
      // Add input WITHOUT witnessUtxo or nonWitnessUtxo
      psbt.addInput({
        hash: Buffer.alloc(32, 1),
        index: 0,
        // No witnessUtxo or nonWitnessUtxo!
      });
      
      psbt.addOutput({
        script: Buffer.alloc(20),
        value: BigInt(9000),
      });
      
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /missing witnessUtxo and nonWitnessUtxo/,
        'Should throw when UTXO data is missing'
      );
    });

    it('should handle multiple witnessUtxo inputs correctly', function () {
      const psbt = createPsbtForNetwork({ network });
      
      // Input 1: witnessUtxo
      psbt.addInput({
        hash: Buffer.alloc(32, 1),
        index: 0,
        witnessUtxo: {
          script: Buffer.alloc(20),
          value: BigInt(5000),
        },
      });
      
      // Input 2: also witnessUtxo
      psbt.addInput({
        hash: Buffer.alloc(32, 2),
        index: 0,
        witnessUtxo: {
          script: Buffer.alloc(20),
          value: BigInt(10000),
        },
      });
      
      psbt.addOutput({
        script: Buffer.alloc(20),
        value: BigInt(14000),
      });
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.inputAmount, BigInt(15000)); // 5000 + 10000
      assert.strictEqual(amounts.outputAmount, BigInt(14000));
      assert.strictEqual(amounts.fee, BigInt(1000));
    });
  });

  describe('Edge case amounts', function () {
    it('should handle zero-value input (if somehow created)', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(0)],
        [BigInt(0)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.inputAmount, BigInt(0));
      assert.strictEqual(amounts.outputAmount, BigInt(0));
      assert.strictEqual(amounts.fee, BigInt(0));
    });

    it('should handle transaction with no fee', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(10000)],
        [BigInt(10000)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.fee, BigInt(0));
    });

    it('should handle many small inputs', function () {
      // 100 inputs of 1000 sats each
      const inputs = Array(100).fill(BigInt(1000));
      
      const psbt = createPsbtWithAmounts(
        inputs,
        [BigInt(99000)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.inputAmount, BigInt(100000));
      assert.strictEqual(amounts.fee, BigInt(1000));
    });

    it('should handle single satoshi precision', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(100000)],
        [BigInt(99999)]
      );
      
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.strictEqual(amounts.fee, BigInt(1), 'Should handle 1-sat fee');
    });
  });

  describe('Bitcoin MAX_MONEY validation', function () {
    it('should reject single input with fee exceeding MAX_MONEY', function () {
      // Create input large enough that fee exceeds MAX_MONEY
      // Input: MAX_MONEY + 1M, Output: 100, Fee: MAX_MONEY + 999,900
      const input = MAX_MONEY + BigInt(1000000);
      const output = BigInt(100);
      
      const psbt = createPsbtWithAmounts([input], [output]);
      
      // Calculate fee without validation to verify it exceeds MAX_MONEY
      const amounts = getTransactionAmountsFromPsbt(psbt, { skipFeeValidation: true });
      assert.ok(amounts.fee > MAX_MONEY, `Fee ${amounts.fee} should exceed MAX_MONEY ${MAX_MONEY}`);
      
      // With validation enabled, should throw
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds Bitcoin's maximum supply/,
        'Should reject fee exceeding MAX_MONEY'
      );
    });

    it('should reject output with fee exceeding MAX_MONEY', function () {
      // Create transaction where fee exceeds MAX_MONEY
      // Input: 2 * MAX_MONEY, Output: MAX_MONEY - 1M, Fee: MAX_MONEY + 1M
      const input = MAX_MONEY * BigInt(2);
      const output = MAX_MONEY - BigInt(1000000);
      
      const psbt = createPsbtWithAmounts([input], [output]);
      
      // Calculate fee without validation to verify it exceeds MAX_MONEY
      const amounts = getTransactionAmountsFromPsbt(psbt, { skipFeeValidation: true });
      assert.ok(amounts.fee > MAX_MONEY, `Fee ${amounts.fee} should exceed MAX_MONEY ${MAX_MONEY}`);
      
      // With validation enabled, should throw
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds Bitcoin's maximum supply/,
        'Should reject fee exceeding MAX_MONEY'
      );
    });

    it('should allow amounts just under MAX_MONEY with reasonable fee', function () {
      const justUnder = MAX_MONEY - BigInt(1000);
      
      const psbt = createPsbtWithAmounts(
        [justUnder],
        [justUnder - BigInt(546)] // Minus dust threshold
      );
      
      // Fee is 546 sats - reasonable, should pass
      const amounts = getTransactionAmountsFromPsbt(psbt);
      assert.ok(amounts.inputAmount < MAX_MONEY, 'Should allow amounts under MAX_MONEY');
      assert.strictEqual(amounts.fee, BigInt(546));
    });

    it('should reject default max fee of 0.1 BTC', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(11000000)], // 0.11 BTC input
        [BigInt(1000)]      // Tiny output - fee will be 0.10999 BTC
      );
      
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds maximum allowed fee of 10000000 satoshis \(0\.1 BTC\)/,
        'Should reject fee exceeding default 0.1 BTC limit'
      );
    });

    it('should allow custom max fee', function () {
      const psbt = createPsbtWithAmounts(
        [BigInt(50000000)], // 0.5 BTC input
        [BigInt(10000000)]  // 0.1 BTC output - fee is 0.4 BTC
      );
      
      // Should fail with default limit (0.1 BTC and 50% percentage)
      assert.throws(
        () => getTransactionAmountsFromPsbt(psbt),
        /exceeds maximum allowed fee|exceeding 50% limit/
      );
      
      // Should pass with custom maxFee of 0.5 BTC and 90% percentage
      const amounts = getTransactionAmountsFromPsbt(psbt, { 
        maxFee: BigInt(50000000),  // 0.5 BTC
        maxFeePercentage: 90        // 90%
      });
      assert.strictEqual(amounts.fee, BigInt(40000000)); // 0.4 BTC (80% of input)
    });
  });
});
