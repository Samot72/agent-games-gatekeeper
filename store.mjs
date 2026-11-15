import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// Persistent state: seen proof references (per mode) + idempotent responses.
// Plain JSON file; the agent is single-process so no locking is needed.
export class Store {
  constructor(path) {
    this.path = path;
    // Best-effort: the data dir may not exist (e.g. DATA_DIR=/data with no
    // volume attached). State persistence must never be able to kill a task
    // answer, so every filesystem touch here is failure-tolerant. The mkdir
    // is deliberately NON-recursive: a single syscall that fails fast on
    // exotic filesystems instead of walking ancestors.
    try { mkdirSync(dirname(path)); } catch { /* exists or in-memory only */ }
    this.data = { seen: { practice: [], competition: [] }, responses: {} };
    if (existsSync(path)) {
      try {
        const parsed = JSON.parse(readFileSync(path, 'utf8'));
        if (parsed && parsed.seen && parsed.responses) this.data = parsed;
      } catch { /* start fresh on a corrupt file */ }
    }
    this.seenSets = {
      practice: new Set(this.data.seen.practice || []),
      competition: new Set(this.data.seen.competition || []),
    };
  }

  flush() {
    this.data.seen = {
      practice: [...this.seenSets.practice],
      competition: [...this.seenSets.competition],
    };
    try {
      writeFileSync(this.path, JSON.stringify(this.data));
    } catch (e) {
      // Persistence is best-effort; the in-memory sets remain authoritative
      // for this process. Never let a failed write eat a task response.
      console.log(JSON.stringify({ t: new Date().toISOString(), event: 'store.flush_failed', error: String(e && e.message ? e.message : e) }));
    }
  }

  hasSeen(mode, proofTx) {
    return this.seenSets[mode]?.has(proofTx) ?? false;
  }

  markSeen(mode, proofTx) {
    if (this.seenSets[mode] && !this.seenSets[mode].has(proofTx)) {
      this.seenSets[mode].add(proofTx);
      this.flush();
    }
  }

  cachedResponse(taskId) {
    return this.data.responses[taskId] || null;
  }

  saveResponse(taskId, bodyString) {
    this.data.responses[taskId] = bodyString;
    this.flush();
  }
}
