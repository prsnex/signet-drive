// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The signed-in session, held in memory only. It carries the non-extractable KEM
// private key — the session's decryption capability that C2-C4 read for every DEK
// unwrap. That CryptoKey cannot be serialized and is never persisted, so a page
// refresh requires re-authentication; sign-out clears it. Reactive ($state) so the
// UI follows sign-in / sign-out.

import type { Session } from './auth';

class SessionStore {
  current = $state<Session | null>(null);

  get isAuthenticated(): boolean {
    return this.current !== null;
  }

  set(session: Session): void {
    this.current = session;
  }

  clear(): void {
    this.current = null;
  }
}

export const sessionStore = new SessionStore();
