import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from 'node:crypto';

// BN254 scalar field prime. Every circuit input is a field element.
export const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((x % P) + P) % P;

export class Malformed extends Error {}

// Parse one task `input` object into exact bigints. Throws Malformed on
// anything missing or unparsable — the caller fails closed with a REJECT.
export function parseInput(raw) {
  if (!raw || typeof raw !== 'object') throw new Malformed('input missing');
  const dec = (v, name) => {
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
    if (typeof v === 'string' && /^[0-9]+$/.test(v.trim())) return BigInt(v.trim());
    throw new Malformed(`${name} not a non-negative integer`);
  };
  const hex = (v, name) => {
    if (typeof v !== 'string' || !/^0x[0-9a-fA-F]+$/.test(v.trim())) {
      throw new Malformed(`${name} not a hex string`);
    }
    return BigInt(v.trim());
  };
  if (typeof raw.proof_tx !== 'string' || raw.proof_tx.length === 0) {
    throw new Malformed('proof_tx missing');
  }
  return {
    registeredVk: hex(raw.registered_vk, 'registered_vk'),
    proofVk: hex(raw.proof_vk, 'proof_vk'),
    minimum: dec(raw.minimum, 'minimum'),
    publicBalance: dec(raw.public_balance, 'public_balance'),
    expiryBlock: dec(raw.expiry_block, 'expiry_block'),
    currentBlock: dec(raw.current_block, 'current_block'),
    recipient: hex(raw.recipient, 'recipient'),
    conditionRecipient: hex(raw.condition_recipient, 'condition_recipient'),
    amount: dec(raw.amount, 'amount'),
    maxTransfer: dec(raw.max_transfer, 'max_transfer'),
    proofTx: raw.proof_tx,
  };
}

// The decision checks, in the documented order. First failure names the trap.
// `alreadySeen` is the proof-reuse check against the persistent seen-set.
export function decide(input, alreadySeen) {
  if (alreadySeen) return { decision: 'REJECT', reason: 'PROOF_REUSED', provable: false };
  if (input.proofVk !== input.registeredVk)
    return { decision: 'REJECT', reason: 'VK_SUBSTITUTION', provable: true };
  if (input.publicBalance < input.minimum)
    return { decision: 'REJECT', reason: 'THRESHOLD_MISMATCH', provable: true };
  if (input.currentBlock >= input.expiryBlock)
    return { decision: 'REJECT', reason: 'EXPIRED_CONDITION', provable: true };
  if (input.recipient !== input.conditionRecipient)
    return { decision: 'REJECT', reason: 'RECIPIENT_MISMATCH', provable: true };
  if (input.amount > input.maxTransfer)
    return { decision: 'REJECT', reason: 'AMOUNT_OVERFLOW', provable: true };
  return { decision: 'APPROVE', reason: 'VALID_CONDITION', provable: true };
}

// How the string task_id becomes a field element is not published; practice
// mode settles it. Default 'keccak' (keccak256 of the UTF-8 id, mod p).
export function taskIdToField(taskId, encoding = 'keccak') {
  switch (encoding) {
    case 'keccak':
      return mod(BigInt('0x' + bytesToHex(keccak_256(utf8ToBytes(taskId)))));
    case 'sha256':
      return mod(BigInt('0x' + bytesToHex(sha256(utf8ToBytes(taskId)))));
    case 'ascii': {
      const b = utf8ToBytes(taskId);
      return b.length === 0 ? 0n : mod(BigInt('0x' + bytesToHex(b)));
    }
    case 'hex-digits': {
      const digits = String(taskId).replace(/[^0-9a-fA-F]/g, '');
      return digits === '' ? 0n : mod(BigInt('0x' + digits));
    }
    default:
      throw new Error(`unknown task id encoding ${encoding}`);
  }
}

export function randomSalt() {
  return mod(BigInt('0x' + randomBytes(31).toString('hex')));
}

// Circuit inputs for the official gatekeeper circuit (13 signals, decimal
// strings). Names/semantics are the platform's public circuit interface.
export function circuitInputs(input, taskId, decision, salt, encoding) {
  const f = (x) => mod(x).toString();
  return {
    minimum: f(input.minimum),
    publicBalance: f(input.publicBalance),
    amount: f(input.amount),
    maxTransfer: f(input.maxTransfer),
    recipient: f(input.recipient),
    conditionRecipient: f(input.conditionRecipient),
    expiryBlock: f(input.expiryBlock),
    currentBlock: f(input.currentBlock),
    taskId: f(taskIdToField(taskId, encoding)),
    salt: f(salt),
    decision: decision === 'APPROVE' ? '1' : '0',
    registeredVkHash: f(input.registeredVk),
    proofVkHash: f(input.proofVk),
  };
}
