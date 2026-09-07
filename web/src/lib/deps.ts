// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The auth flows (C1a) take an injected API client + WebAuthn gateway so they
// unit-test against fakes. In the browser they run against the real same-origin
// API (the session cookie travels via credentials: 'include') and the platform
// navigator.credentials.

import type { AuthDeps } from './auth';
import { createApiClient } from './api';
import { browserGateway } from './webauthn';

export function authDeps(): AuthDeps {
  return { api: createApiClient(), gateway: browserGateway };
}
