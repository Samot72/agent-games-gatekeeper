import { readFileSync, writeFileSync, existsSync } from 'node:fs';

// Persistent state: seen proof references (per mode) + idempotent responses.
// Plain JSON file; the agent is single-process so no locking is needed.
export class Store {
  constructor(path) {
    this.path = path;
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
    writeFileSync(this.path, JSON.stringify(this.data));
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
