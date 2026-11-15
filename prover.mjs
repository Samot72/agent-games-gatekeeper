import * as snarkjs from 'snarkjs';
import { readFileSync } from 'node:fs';

// Local Groth16 proving with the official gatekeeper circuit artifacts.
// The circuit itself enforces the correct decision: witness generation fails
// when the claimed decision does not match the rule checks, so a proof that
// comes out of here is a proof the decision followed the rules.
export class Prover {
  constructor(wasmPath, zkeyPath, vkPath) {
    this.wasm = wasmPath;
    this.zkey = zkeyPath;
    this.vk = JSON.parse(readFileSync(vkPath, 'utf8'));
  }

  async prove(inputs, budgetMs = 45000) {
    const start = Date.now();
    let timer;
    try {
      const timeout = new Promise((_, rej) => {
        timer = setTimeout(() => rej(new Error('proving budget exceeded')), budgetMs);
      });
      const { proof, publicSignals } = await Promise.race([
        snarkjs.groth16.fullProve(inputs, this.wasm, this.zkey),
        timeout,
      ]);
      const verified = await snarkjs.groth16.verify(this.vk, publicSignals, proof);
      return { ok: true, proof, publicSignals, verified, ms: Date.now() - start };
    } catch (e) {
      return { ok: false, error: String(e && e.message ? e.message : e).split('\n')[0], ms: Date.now() - start };
    } finally {
      clearTimeout(timer);
    }
  }
}
