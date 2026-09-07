// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Map an auth-flow error to user-facing copy. The UX bar (Settled): no crypto or
// protocol detail surfaces — calm, plain language with a clear next step. The
// codes are the server's error-envelope codes (PRSN-UX Strawman v09 §7); non-API
// errors (a cancelled passkey prompt, a PRF-incapable authenticator) arrive as
// plain Errors from the injected gateway and carry a usable message.
//
// S169 (punch-list §1-22): every literal here moved into the Paraglide catalog
// (web/messages/en.json, the err_* keys) so a commissioned translation covers the
// error surface. These strings were previously invisible to the catalog — the one
// class of web copy a translator would silently never receive. The fall-through
// arms that surface `error.message` intentionally remain: those strings originate
// SERVER-side (already-specific validation text) and are not this catalog's to
// translate.

import { SignetApiError } from './api';
import { StallError, TransferExhaustedError } from './transfer';
// Relative on purpose: the unit-test runner resolves no $lib aliases (vite.config's
// stated design), and the compiled catalog is a sibling directory either way.
import { m } from './paraglide/messages.js';

export function friendlyAuthError(error: unknown): string {
  if (error instanceof SignetApiError) {
    switch (error.code) {
      case 'webauthn_authentication_failed':
        // Deliberately covers BOTH paths behind this one server code — an unknown
        // email (no ceremony ever ran) and a genuinely failed passkey assertion —
        // without confirming which (anti-enumeration: the message must not reveal
        // whether the account exists). "with that passkey" was wrong for the
        // unknown-email path (S121 UI/UX review, W3).
        return m.err_auth_signin_failed();
      case 'email_unavailable':
        return m.err_auth_email_unavailable();
      case 'handle_unavailable':
        return m.err_auth_username_taken();
      case 'email_verification_invalid':
        return m.err_auth_link_invalid();
      case 'prf_not_supported':
        return m.err_auth_prf_not_supported();
      case 'ceremony_not_found':
        return m.err_auth_took_too_long();
      case 'rate_limited':
        return m.err_common_rate_limited_attempts();
      case 'invalid_request':
        return m.err_common_check_details();
      case 'internal_error':
        return m.err_common_internal();
      default:
        return error.message || m.err_common_generic();
    }
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return m.err_common_generic();
}

// Account-management ceremony errors (C4: issue / revoke / change-capability /
// delete) → calm, plain copy. Same UX bar: no crypto or protocol detail. The
// `invalid_request` validations the server returns here are already user-shaped
// and specific (a handle mismatch, an already-revoked attestation, a bad PRSN
// handle, a fingerprint mismatch), so we surface the server's own message rather
// than flatten them to one generic line. Client-side P-011 verification failures
// arrive as plain Errors carrying their own message (the final fallback).
export function friendlyCeremonyError(error: unknown): string {
  if (error instanceof SignetApiError) {
    switch (error.code) {
      case 'webauthn_authentication_failed':
        return m.err_ceremony_passkey_failed();
      case 'ceremony_not_found':
        return m.err_ceremony_took_too_long();
      case 'handle_unavailable':
        return m.err_ceremony_handle_taken();
      case 'handle_in_flight':
        // Bug040: distinct from handle_unavailable — the name is held by the
        // guardian's OWN in-flight enrollment, so the action is finish/cancel that
        // one and reuse the name, NOT pick a different name.
        return m.err_ceremony_handle_in_flight();
      case 'not_found':
        return m.err_ceremony_not_under_guardianship();
      case 'permission_denied':
        return m.err_common_no_permission();
      case 'version_conflict':
        return m.err_ceremony_version_conflict();
      case 'rate_limited':
        return m.err_common_rate_limited_attempts();
      case 'invalid_request':
        return error.message || m.err_common_check_details();
      case 'internal_error':
        return m.err_common_internal();
      default:
        return error.message || m.err_common_generic();
    }
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return m.err_common_generic();
}

// Admin-dashboard errors (C5: system-config edits + comped-account grants) → calm
// copy. The route is admin-gated, so permission_denied is rare; `not_found` covers
// an unknown config key / account / grant, `version_conflict` an already-revoked
// grant, `invalid_request` a bad value or duration (the server's message is already
// specific there, so surface it). Codes are the server's error-envelope codes.
export function friendlyAdminError(error: unknown): string {
  if (error instanceof SignetApiError) {
    switch (error.code) {
      case 'not_found':
        return m.err_admin_item_gone();
      case 'version_conflict':
        return m.err_admin_grant_changed();
      case 'permission_denied':
        return m.err_common_no_permission();
      case 'rate_limited':
        return m.err_common_rate_limited_requests();
      case 'invalid_request':
        return error.message || m.err_admin_check_value();
      case 'authentication_required':
        return m.err_common_session_ended();
      case 'internal_error':
        return m.err_common_internal();
      default:
        return error.message || m.err_common_generic();
    }
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return m.err_common_generic();
}

// Billing errors (D2: checkout + portal redirects) → calm copy. `billing_not_configured`
// (no Stripe on this deployment) and `billing_unavailable` (a transient Stripe failure)
// are deployment/infra states, not user mistakes; `invalid_request` covers the
// portal's "no Stripe customer yet" case (a comped account that never subscribed),
// whose server message is already user-shaped, so we surface it. Codes are the
// server's error-envelope codes (error.rs / billing.rs).
export function friendlyBillingError(error: unknown): string {
  if (error instanceof SignetApiError) {
    switch (error.code) {
      case 'billing_not_configured':
        return m.err_billing_not_configured();
      case 'billing_unavailable':
        return m.err_billing_unavailable();
      case 'permission_denied':
        return m.err_billing_holder_only();
      case 'rate_limited':
        return m.err_common_rate_limited_requests();
      case 'invalid_request':
        return error.message || m.err_billing_try_again();
      case 'authentication_required':
        return m.err_common_session_ended();
      case 'internal_error':
        return m.err_common_internal();
      default:
        return error.message || m.err_common_generic();
    }
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return m.err_common_generic();
}

// Data-plane (file browser) errors → calm, plain copy. Same UX bar: no crypto or
// protocol detail. Codes are the server's error-envelope codes (error.rs).
export function friendlyDriveError(error: unknown): string {
  if (error instanceof SignetApiError) {
    switch (error.code) {
      case 'quota_exceeded':
        return m.err_drive_quota_exceeded();
      case 'cross_root_move_not_supported':
        return m.err_drive_cross_root_move();
      case 'version_conflict':
        return m.err_drive_name_in_use();
      case 'folder_write_locked_pending_invitations':
        // Honest about the real resolution paths — a pending invite can hold the
        // lock for its whole TTL, so "try again in a moment" was misleading
        // (S121 review, W6). The Share dialog lists + cancels pending invites.
        return m.err_drive_folder_locked_pending();
      case 'not_found':
        return m.err_drive_item_gone();
      case 'prsn_cannot_create_private_folder':
        return m.err_drive_prsn_private_folder();
      case 'rate_limited':
        return m.err_common_rate_limited_requests();
      case 'authentication_required':
        return m.err_common_session_ended();
      case 'invalid_request':
        return m.err_common_check_details();
      case 'internal_error':
        return m.err_common_internal();
      default:
        return error.message || m.err_common_generic();
    }
  }
  // bug060: a transfer that exhausted its attempt budget is a NETWORK-WINDOW
  // failure, not a server fault — "something went wrong on our end" would be both
  // untrue and unactionable. The product bar (bug060 §7.0, Chris S126) is that
  // every failure says what happened, that nothing was lost, and what to do next;
  // nothing here IS lost, because the parts already stored are kept and a re-run
  // resumes from them.
  // ⚠⚠ bug199: SPLIT BY DIRECTION. One string served both verbs, so a failed
  // DOWNLOAD read "the upload stopped early… start the same upload again" — an
  // instruction for an operation the user never began, pointing at a recovery
  // that does not exist for them. ⭐ And the cause claim went with it: "the
  // connection to storage kept dropping" was asserted whatever actually happened
  // (the measured truth in bug198 was four instant failures at the head, 7.0-7.7
  // ms, nothing sent). Ruled (Gus, S180): NO cause claims on either verb —
  // causes go to logs, never to users — and "refresh" is the escalation line,
  // not the first instruction.
  if (error instanceof TransferExhaustedError) {
    return error.direction === 'download'
      ? m.err_drive_transfer_exhausted_download()
      : m.err_drive_transfer_exhausted_upload();
  }
  if (error instanceof StallError) {
    return m.err_drive_stalled();
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return m.err_common_generic();
}
