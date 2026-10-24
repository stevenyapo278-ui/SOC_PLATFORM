'use strict';

// Disjoncteur de circuit pour les appels IA — porté de Projet_IA_Hub.
// 3 échecs transitoires → circuit ouvert 30 s, puis un test half-open.

class CircuitBreaker {
  constructor(name, options = {}) {
    this.name = name;
    this.maxFailures = options.maxFailures || 3;
    this.resetTimeoutMs = options.resetTimeoutMs || 30000;
    this.halfOpenMaxRequests = options.halfOpenMaxRequests || 1;

    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureAt = null;
    this.nextAttemptAt = null;
    this.lastError = null;
  }

  get isOpen() {
    return this.state === 'OPEN';
  }

  allowRequest() {
    if (this.state === 'CLOSED') return true;

    if (this.state === 'OPEN') {
      if (this.nextAttemptAt && Date.now() >= this.nextAttemptAt) {
        this.state = 'HALF_OPEN';
        this.successCount = 0;
        return true;
      }
      return false;
    }

    if (this.state === 'HALF_OPEN') {
      return this.successCount < this.halfOpenMaxRequests;
    }

    return false;
  }

  onSuccess() {
    this.failureCount = 0;
    this.successCount += 1;
    this.lastError = null;

    if (this.state === 'HALF_OPEN' && this.successCount >= this.halfOpenMaxRequests) {
      this.state = 'CLOSED';
      this.nextAttemptAt = null;
    }
  }

  onFailure(error) {
    this.failureCount += 1;
    this.lastFailureAt = new Date();
    this.lastError = (error && error.message) || String(error);

    if (this.state === 'HALF_OPEN') {
      this.state = 'OPEN';
      this.nextAttemptAt = Date.now() + this.resetTimeoutMs;
      this.successCount = 0;
      return;
    }

    if (this.failureCount >= this.maxFailures) {
      this.state = 'OPEN';
      this.nextAttemptAt = Date.now() + this.resetTimeoutMs;
    }
  }

  async call(fn, fallback = null) {
    if (!this.allowRequest()) {
      const err = new Error(`Disjoncteur [${this.name}] ouvert — appel refusé`);
      err.code = 'CIRCUIT_OPEN';
      if (fallback) return fallback(err);
      throw err;
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      if (this.isTransient(err)) this.onFailure(err);
      if (fallback) return fallback(err);
      throw err;
    }
  }

  isTransient(err) {
    const msg = ((err && err.message) || '').toLowerCase();
    const status = (err && err.status) || (err && err.response && err.response.status);
    return (
      status === 429 ||
      status >= 500 ||
      msg.includes('timeout') ||
      msg.includes('econnrefused') ||
      msg.includes('econnreset') ||
      msg.includes('etimedout') ||
      msg.includes('socket') ||
      msg.includes('too many requests')
    );
  }

  status() {
    return {
      name: this.name,
      state: this.state,
      failureCount: this.failureCount,
      lastFailureAt: this.lastFailureAt,
      nextAttemptAt: this.nextAttemptAt ? new Date(this.nextAttemptAt) : null,
      lastError: this.lastError,
    };
  }

  reset() {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureAt = null;
    this.nextAttemptAt = null;
    this.lastError = null;
  }
}

const breakers = new Map();

function getBreaker(name, options) {
  if (!breakers.has(name)) breakers.set(name, new CircuitBreaker(name, options));
  return breakers.get(name);
}

function allBreakerStatuses() {
  return Array.from(breakers.values()).map((b) => b.status());
}

module.exports = { CircuitBreaker, getBreaker, allBreakerStatuses };
