import { UtxoPsbt } from './UtxoPsbt';
import { createTransactionFromBuffer } from './transaction';
import { validateFee, FeeValidationOptions } from './feeValidation';

export interface TransactionAmounts {
  inputCount: number;
  outputCount: number;
  inputAmount: bigint;
  outputAmount: bigint;
  fee: bigint;
}

export interface GetTransactionAmountsOptions extends FeeValidationOptions {
  /**
   * Skip fee validation checks
   * Default: false (validation enabled)
   * 
   * WARNING: Only disable validation if you have alternative fee checking.
   * Without validation, transactions with absurdly high fees could be created.
   */
  skipFeeValidation?: boolean;
}

/**
 * Get transaction amounts from PSBT
 * 
 * Calculates input amounts, output amounts, and fee from a PSBT.
 * By default, validates that the fee is reasonable to prevent accidental loss of funds.
 * 
 * @param psbt - PSBT to analyze
 * @param options - Validation options
 * @returns Transaction amounts (input count/amount, output count/amount, fee)
 * @throws Error if fee validation fails (unless skipFeeValidation is true)
 */
export function getTransactionAmountsFromPsbt(
  psbt: UtxoPsbt,
  options: GetTransactionAmountsOptions = {}
): TransactionAmounts {
  const inputCount = psbt.data.inputs.length;
  const outputCount = psbt.data.outputs.length;
  const txInputs = psbt.txInputs;
  const txOutputs = psbt.txOutputs;
  const inputAmount = psbt.data.inputs.reduce((acc, input, inputIndex) => {
    if (input.witnessUtxo) {
      return acc + BigInt(input.witnessUtxo.value);
    } else if (input.nonWitnessUtxo) {
      const tx = createTransactionFromBuffer(input.nonWitnessUtxo, psbt.network, { amountType: 'bigint' });
      return acc + tx.outs[txInputs[inputIndex].index].value;
    } else {
      throw new Error('missing witnessUtxo and nonWitnessUtxo');
    }
  }, BigInt(0));
  const outputAmount = psbt.data.outputs.reduce(
    (acc, output, outputIndex) => acc + txOutputs[outputIndex].value,
    BigInt(0)
  );
  const fee = inputAmount - outputAmount;

  // Validate fee unless explicitly skipped
  if (!options.skipFeeValidation) {
    validateFee(fee, inputAmount, options);
  }

  return {
    inputCount,
    outputCount,
    inputAmount,
    outputAmount,
    fee,
  };
}
