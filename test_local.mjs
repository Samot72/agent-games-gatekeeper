import { Prover } from './prover.mjs';
import { parseInput, decide, circuitInputs } from './gatekeeper.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const prover = new Prover(
  join(here, 'circuits', 'gatekeeper.wasm'),
  join(here, 'circuits', 'gatekeeper_final.zkey'),
  join(here, 'circuits', 'gatekeeper_vk.json'),
);

const VK = '0x7d3a11111111111111111111111111111111111111111111111111111111f291';
const VK2 = '0xa4c122222222222222222222222222222222222222222222222222222222b8ff';
const RCPT = '0xDe42000000000000000000000000000000009f01';
const RCPT2 = '0xDe42000000000000000000000000000000009f02';

const base = {
  registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
  expiry_block: 8430000, current_block: 8420000,
  recipient: RCPT, condition_recipient: RCPT,
  amount: '500', max_transfer: '1000', proof_tx: '0xa4c1aaaa8ff1',
};

const cases = [
  ['VALID', {}, 'APPROVE'],
  ['VK_SUBSTITUTION', { proof_vk: VK2 }, 'REJECT'],
  ['THRESHOLD_MISMATCH', { public_balance: '900' }, 'REJECT'],
  ['EXPIRED_CONDITION', { current_block: 8430000 }, 'REJECT'],
  ['RECIPIENT_MISMATCH', { recipient: RCPT2 }, 'REJECT'],
  ['AMOUNT_OVERFLOW', { amount: '1500' }, 'REJECT'],
];

let fail = 0;
for (const [name, patch, expectDecision] of cases) {
  const input = parseInput({ ...base, ...patch, proof_tx: '0xtx_' + name });
  const verdict = decide(input, false);
  const okDecision = verdict.decision === expectDecision;
  const salt = 12345n;
  const goodInputs = circuitInputs(input, 'gk_test_1', verdict.decision, salt, 'keccak');
  const good = await prover.prove(goodInputs, 60000);
  // The opposite decision must FAIL to prove (circuit is the referee).
  const wrongDecision = verdict.decision === 'APPROVE' ? 'REJECT' : 'APPROVE';
  const badInputs = circuitInputs(input, 'gk_test_1', wrongDecision, salt, 'keccak');
  const bad = await prover.prove(badInputs, 60000);
  const line = {
    name, decision: verdict.decision, reason: verdict.reason, okDecision,
    proveGood: good.ok && good.verified, proveGoodMs: good.ms,
    proveWrongFails: !bad.ok,
  };
  console.log(JSON.stringify(line));
  if (!okDecision || !line.proveGood || !line.proveWrongFails) fail++;
  if (name === 'VALID' && good.ok) {
    console.log('publicSignals order check:', JSON.stringify(good.publicSignals));
    const expect = [null, input.registeredVk, input.proofVk, input.minimum, input.publicBalance,
      input.expiryBlock, input.currentBlock, input.recipient, input.conditionRecipient,
      input.amount, input.maxTransfer, 1n, null];
    for (let i = 1; i <= 11; i++) {
      const got = BigInt(good.publicSignals[i]);
      if (got !== expect[i]) console.log(`  MISMATCH idx ${i}: got ${got} expect ${expect[i]}`);
    }
    console.log('  taskId signal:', good.publicSignals[12], 'out0:', good.publicSignals[0]);
  }
}
console.log(fail === 0 ? 'ALL CIRCUIT TESTS PASS' : `${fail} FAILURES`);
process.exit(fail === 0 ? 0 : 1);
