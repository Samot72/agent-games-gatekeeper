import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { candidateKeys, verifyKey, signHex, SIGNATURE_HEADER } from './hmac.mjs';
import { Store } from './store.mjs';
import { Prover } from './prover.mjs';
import { parseInput, decide, circuitInputs, randomSalt, Malformed } from './gatekeeper.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const TASK_ID_ENCODING = process.env.TASK_ID_ENCODING || 'keccak';
const DATA_DIR = process.env.DATA_DIR || here;

const keys = candidateKeys(SECRET);
if (keys.length === 0) {
  console.error('AGENT_GAMES_HMAC_SECRET is not set — signed requests will be rejected');
}

const store = new Store(join(DATA_DIR, 'state.json'));
const prover = new Prover(
  join(here, 'circuits', 'gatekeeper.wasm'),
  join(here, 'circuits', 'gatekeeper_final.zkey'),
  join(here, 'circuits', 'gatekeeper_vk.json'),
);

const inFlight = new Map(); // task_id -> Promise<string> (idempotent retries)

function log(event, fields) {
  console.log(JSON.stringify({ t: new Date().toISOString(), event, ...fields }));
}

async function handleGatekeeper(envelope) {
  const taskId = envelope.task_id;
  const mode = envelope.mode === 'competition' ? 'competition' : 'practice';

  const cached = store.cachedResponse(taskId);
  if (cached) return cached;
  if (inFlight.has(taskId)) return inFlight.get(taskId);

  const run = (async () => {
    let input = null;
    let verdict;
    try {
      input = parseInput(envelope.input);
      verdict = decide(input, store.hasSeen(mode, input.proofTx));
    } catch (e) {
      if (!(e instanceof Malformed)) throw e;
      verdict = { decision: 'REJECT', reason: 'PUBLIC_INPUT_MISMATCH', provable: false };
      log('task.malformed', { taskId, error: e.message });
    }

    const body = { decision: verdict.decision, reason_code: verdict.reason };
    let proofAttached = false;
    let proofError = null;

    if (verdict.provable && input) {
      const inputs = circuitInputs(input, taskId, verdict.decision, randomSalt(), TASK_ID_ENCODING);
      const outcome = await prover.prove(inputs);
      if (outcome.ok && outcome.verified) {
        body.proof = outcome.proof;
        body.public_signals = outcome.publicSignals;
        proofAttached = true;
      } else {
        proofError = outcome.ok ? 'local verify failed' : outcome.error;
      }
    }
    if (input) body.proof_tx = input.proofTx;

    const bodyString = JSON.stringify(body);
    store.saveResponse(taskId, bodyString);
    // Only an approved proof reference enters the seen-set; a later task that
    // reuses it is then rejected as PROOF_REUSED.
    if (input && verdict.decision === 'APPROVE') store.markSeen(mode, input.proofTx);
    log('task.answered', {
      taskId, mode, decision: verdict.decision, reason: verdict.reason,
      proofAttached, proofError,
    });
    return bodyString;
  })();

  inFlight.set(taskId, run);
  try {
    return await run;
  } finally {
    inFlight.delete(taskId);
  }
}

const server = createServer((req, res) => {
  const send = (status, bodyString, key) => {
    const headers = { 'content-type': 'application/json' };
    if (key) headers[SIGNATURE_HEADER] = signHex(key, bodyString);
    res.writeHead(status, headers);
    res.end(bodyString);
  };

  if (req.method === 'GET') {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/siwe-form') {
      const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      const html = '<!doctype html><html><body>' +
        '<form method="POST" action="https://agentgames.zkverify.io/api/auth/callback/wallet">' +
        '<textarea name="message" rows="14" cols="80">' + esc(url.searchParams.get('message')) + '</textarea><br>' +
        '<input name="signature" size="100" value="' + esc(url.searchParams.get('signature')) + '"><br>' +
        '<input name="csrfToken" size="70" value="' + esc(url.searchParams.get('csrfToken')) + '"><br>' +
        '<input type="hidden" name="callbackUrl" value="https://agentgames.zkverify.io/dashboard">' +
        '<input type="hidden" name="json" value="true">' +
        '<button type="submit">Sign in to Agent Games</button>' +
        '</form></body></html>';
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(html);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'gatekeeper-agent', protocolVersion: 'v1' }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405); res.end(); return;
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    const key = verifyKey(keys, raw, req.headers[SIGNATURE_HEADER]);
    if (!key) {
      send(401, JSON.stringify({ error: 'invalid signature' }), null);
      return;
    }
    let envelope;
    try {
      envelope = JSON.parse(raw.toString('utf8'));
    } catch {
      send(400, JSON.stringify({ error: 'invalid json' }), key);
      return;
    }
    try {
      if (envelope.type === 'agent-games.preflight.v1') {
        send(200, JSON.stringify({ ok: true, protocolVersion: 'v1' }), key);
        return;
      }
      if (envelope.type === 'agent-games.proof-gatekeeper.v1' && envelope.task_id) {
        const bodyString = await handleGatekeeper(envelope);
        send(200, bodyString, key);
        return;
      }
      // Unknown signed payload: fail closed with a signed rejection.
      log('task.unknown_type', { type: envelope.type || envelope.eventId || null });
      send(200, JSON.stringify({ decision: 'REJECT', reason_code: 'PUBLIC_INPUT_MISMATCH' }), key);
    } catch (e) {
      log('task.error', { error: String(e && e.message ? e.message : e) });
      send(200, JSON.stringify({ decision: 'REJECT', reason_code: 'PUBLIC_INPUT_MISMATCH' }), key);
    }
  });
});

server.listen(PORT, () => log('agent.listening', { port: PORT, encoding: TASK_ID_ENCODING }));
