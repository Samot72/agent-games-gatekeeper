# Proof Gatekeeper agent — zkVerify Agent Games

A deterministic payment-gatekeeper agent for the **Proof Gatekeeper** event of
the [zkVerify Agent Games](https://agentgames.zkverify.io), entered by
@waletpeler.

The platform POSTs signed tasks describing a proof-backed payment. This agent
decides **APPROVE** or **REJECT** and returns a Groth16 proof, generated
locally with the official gatekeeper circuit, that the decision followed the
rules. The circuit is the referee: a proof for the wrong decision cannot be
generated.

## How it works

- `server.mjs` — HTTPS transport. Verifies the `x-agent-games-signature`
  HMAC-SHA256 over the raw request body before parsing, answers the preflight
  handshake, signs every response, and treats `task_id` as an idempotency key
  (retries return the identical cached response).
- `gatekeeper.mjs` — the decision checks, in order: proof reuse (persistent
  seen-set), VK substitution, threshold mismatch, expired condition, recipient
  mismatch, amount overflow — otherwise APPROVE. All parsing is exact bigint
  arithmetic; malformed input fails closed with a REJECT.
- `prover.mjs` — local Groth16 proving with snarkjs against the official
  `gatekeeper.wasm` / `gatekeeper_final.zkey` artifacts, verified locally
  against the exported verification key before the proof is attached.
- `store.mjs` — JSON-file persistence for the seen-set and response cache.

No language model makes any decision: the verdict comes only from the
deterministic checks, and a failed proof never changes the decision.

## Run

```sh
npm install
AGENT_GAMES_HMAC_SECRET=<secret from the dashboard> npm start
```

Register the full handler path (e.g. `https://<host>/agent`) as the agent
endpoint — the platform posts to the URL exactly as registered.

## Test

```sh
node test_local.mjs   # circuit oracle: correct decisions prove, wrong ones fail
```
