// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Reactive state for the file browser (Platform Overview View 1 / 1b). Holds the
// session's Drive, the current navigation path, the decrypted folder + file
// listings, multi-select, quota, and the open dialog. Every name is decrypted
// client-side via Drive — the server only ever returned ciphertext. Mutations
// refresh by re-fetching (the SSE live-update stream is C2-3).

import {
  SignetApiError,
  createApiClient,
  type FileView,
  type FolderView,
  type GuardedPrsn,
  type MeResponse,
  type QuotaResponse,
  type PendingInvitationView,
  type RecipientView,
  type SharedFolderView,
} from './api';
import type { Session } from './auth';
import { Drive, capacityRefusal, type DownloadProgress, type DownloadSink } from './drive';
import { friendlyDriveError } from './errors';
import { UploadWakeLock, type WakeLockApiLike } from './wake-lock';
import { DownloadCancelledError, openSwStreamedSink } from './sw-download';
import { groupSharedByOwner, type GroupedShares } from './grouping';
import { dedupeName } from './names';
import { UploadBatch, type UploadBatchState } from './upload-batch';
import {
  DropReadError,
  FolderCreateError,
  createPlannedFolders,
  nameFolders,
  perFolderDedupe,
  planFromRelativePaths,
  resolveEntries,
  type DropCapture,
  type FolderTarget,
  type FolderUploadPlan,
} from './folder-drop';
import { loadNavState, saveNavState } from './nav-persist';
// Relative on purpose, matching errors.ts: the unit-test runner resolves no $lib aliases.
import { m } from './paraglide/messages.js';

/** bug193 (v03 §4): the fallback's pre-flight refusal — the file provably cannot
 *  buffer under the served cap, so nothing is transferred (bug070's principle on
 *  the download side). Typed so the catch can pick the honest copy. */
class FallbackTooLargeError extends Error {
  constructor() {
    super('file exceeds the buffering fallback cap');
  }
}

export interface NamedFolder {
  view: FolderView;
  name: string;
  /** For a shared-with-me folder, the owner's account id — groups the Guardian's
   *  per-PRSN nav (Bug009). Undefined for the account's own folders. */
  ownerAccountId?: string;
  /** bug223: for a shared-with-me folder, THIS account's permission on it
   *  (`read_only` | `read_write`). The server has always sent it
   *  (`list_shared_with_me` selects `sr.permission`); the client dropped it, which
   *  is why the UI could only ask "owner?" and not "may I write?". Undefined for
   *  the account's own folders, where ownership answers it. */
  permission?: string;
}

export interface NamedFile {
  view: FileView;
  name: string;
}

/** One step in the navigation path. `rootFolderId` is constant within a path
 *  (the top-level folder's id) — it binds the §7.2/§7.3 crypto for everything
 *  in this hierarchy. */
/** One file of an upload plan, as the batch sees it (`folder`: an index into the
 *  plan's folders, or null for the folder the upload was started in). */
interface PlanItem {
  name: string;
  size: number;
  file: File;
  folder: number | null;
}

/** A folder upload's preparation, shown before the batch exists. */
export type FolderPrep =
  | { kind: 'reading'; files: number }
  | { kind: 'creating'; done: number; total: number };

export interface Crumb {
  folderId: string;
  rootFolderId: string;
  name: string;
}

export type Dialog =
  | { kind: 'newFolder'; topLevel: boolean }
  | { kind: 'newShareFolder' }
  | { kind: 'rename'; file?: NamedFile; folder?: NamedFolder }
  | { kind: 'move' }
  | { kind: 'confirmDelete'; file?: NamedFile; folder?: NamedFolder }
  | { kind: 'sharePanel'; rootFolderId: string; role: 'owner' | 'recipient' }
  | null;

// The SSE event names the change stream emits (changes.rs `ChangeKind` + the
// lag `resync`); any one triggers a debounced refresh. ⚠ `connected` is NOT in
// this list — it is handled separately in `connect()` so the FIRST one can be
// skipped; see the bug190 block there.
const CHANGE_EVENTS = [
  'folder_created',
  'folder_updated',
  'folder_deleted',
  'file_uploaded',
  'file_updated',
  'file_deleted',
  'resync',
];

/** The minimal surface `attachChangeListeners` needs — so a test can supply a
 *  plain object instead of a real `EventSource` (which does not exist under
 *  vitest's `node` environment). */
export interface ChangeEventTarget {
  addEventListener(type: string, listener: () => void): void;
}

/** bug226 — which expanded tree nodes are VISIBLE and have never been fetched?
 *
 *  A node renders expanded only if every ancestor above it is also expanded, so the
 *  set that matters is not "everything the user ever expanded" — it is the reachable
 *  frontier. ⭐ Walking stops AT an unfetched node, because its children are exactly
 *  what we do not yet know. ⇒ **calling this repeatedly yields the tree one LEVEL at
 *  a time** — which is INHERENT, not an optimisation: level N+1's ids are only knowable
 *  once level N has landed.
 *
 *  ⚠⚠ **CORRECTION to my own first justification (Gus, F2-review).** I wrote that the
 *  per-level shape was load-bearing because of whole-site HTTP/1.1's ~6 connections per
 *  host. **That reasoning is wrong** and is recorded here because a false mechanism
 *  outlives a false conclusion: the browser queues a wide frontier at 6/host by itself
 *  and nothing breaks. What per-level actually buys is the *visibility filter* — a node
 *  under a collapsed parent never renders, so fetching it is pure waste. The real cost
 *  of getting this wrong was never connection count; it was serial latency in front of
 *  first paint, which is why hydration is no longer awaited.
 *
 *  ⚠ `seen` is a cycle guard. A folder tree should not contain one; a corrupted
 *  parent chain could, and an unbounded walk would hang the page load. */
export function visibleUnfetchedExpanded(
  rootIds: readonly string[],
  expanded: ReadonlySet<string>,
  children: ReadonlyMap<string, readonly { view: { folder_id: string } }[]>,
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const walk = (ids: readonly string[]): void => {
    for (const id of ids) {
      if (seen.has(id)) continue;
      seen.add(id);
      if (!expanded.has(id)) continue;
      const kids = children.get(id);
      // undefined ⇒ never fetched. NOT the same as `[]`, which means fetched and
      // genuinely empty — conflating those two IS bug226.
      if (kids === undefined) {
        out.push(id);
        continue;
      }
      walk(kids.map((k) => k.view.folder_id));
    }
  };
  walk(rootIds);
  return out;
}

/** bug190 §6-1 — wire every change event to a refresh.
 *
 *  Extracted from `connect()` for the same reason `makeConnectedHandler` was:
 *  `connect()` constructs a real `EventSource` and touches the whole store, so
 *  the wiring inside it is untestable. The loop is the only thing that makes
 *  membership of `CHANGE_EVENTS` mean anything, and it had NO test at all.
 *
 *  ⚠⚠ This and the parity test prove DIFFERENT halves, and neither implies the
 *  other:
 *    · `server/tests/sse_event_parity.rs` proves `CHANGE_EVENTS` matches the set
 *      the server can actually emit — the DENOMINATOR (bug190 §6-2).
 *    · this function's tests prove every member of that list is actually wired
 *      to a refresh — the BEHAVIOUR (bug190 §6-1).
 *  A correct list nobody iterates, and a correct loop over a short list, are
 *  both the original defect. */
/** bug223 §1 — may this account ADD content (upload, and by extension delete its
 *  own files) in a folder root it is viewing?
 *
 *  ⭐ Extracted as a pure function for the reason `attachChangeListeners` was
 *  (bug190 §6-1): the store's getters read `currentRootId`, `sharedWithMe` and a
 *  live EventSource, so a rule embedded in them has no test. The rule is the thing
 *  that has to be right; it should not require a browser to check.
 *
 *  ⚠ **Fails closed on the PERMISSION, and that is the whole of the claim** (Gus,
 *  bug223 F2). Anything not exactly `'read_write'` — `'read_only'`, a value this
 *  client does not know, or a permission it could not read — is not write authority.
 *
 *  ⚠⚠ **It does NOT fail closed on the ROLE, deliberately.** `currentShareRole`
 *  returns `null` for two different states: a private folder (owned ⇒ full
 *  authority) and *a root not yet resolved* — a deep link, or a bug184 nav restore,
 *  before `loadSharedWithMe` has landed. `null` therefore reads as OWNED, so in that
 *  window a recipient briefly sees write controls enabled. **Display-only: the
 *  server answers at use, and this predates the getter** (`ownsCurrentRoot` has
 *  always had it). Recorded as a decision, and pinned by a test, so a later reader
 *  changes it on purpose rather than by accident. */
export function mayAddContent(
  role: 'owner' | 'recipient' | null,
  permission: string | undefined,
): boolean {
  // Not a recipient ⇒ the account owns this root (an owned share folder, or a
  // private folder, which reports `null`). Ownership is full authority.
  if (role !== 'recipient') return true;
  return permission === 'read_write';
}

/** bug223 §2 — may this account DELETE, given what is selected?
 *
 *  ⚠⚠ **Delete is two rules wearing one label, and conflating them IS the bug223
 *  defect one layer down.** A FILE resolves `sharing::folder_authority`, which
 *  grants a `read_write` recipient `Write` (bug208 §3b, Chris's ruling: *write
 *  authority IS delete authority*). A FOLDER is owner-only — `folders.rs` deletes
 *  with `WHERE folder_id = $1 AND account_id = $2` and answers `not_found`
 *  otherwise. A mixed selection therefore takes the STRICTER bar, or the UI offers
 *  a button the server refuses for part of what is selected. */
export function mayDelete(
  ownsRoot: boolean,
  canAddContent: boolean,
  selectionIncludesAFolder: boolean,
): boolean {
  return selectionIncludesAFolder ? ownsRoot : canAddContent;
}

export function attachChangeListeners(target: ChangeEventTarget, onChange: () => void): void {
  for (const name of CHANGE_EVENTS) {
    target.addEventListener(name, () => onChange());
  }
}

// bug202 (S179): the explicit SSE reconnect ladder. EventSource retries a
// TRANSIENT drop itself (readyState CONNECTING), but a hard ABORT closes it for
// good (readyState CLOSED) and nothing restarts it — see `connect()`. Doubling
// from 1 s to a 30 s ceiling: fast enough that a download-induced abort is
// invisible to the user, slow enough that a server outage is not a retry storm
// from every open tab.
const SSE_RECONNECT_BASE_MS = 1_000;
const SSE_RECONNECT_MAX_MS = 30_000;

// bug202 §4a: how often we ASK the stream whether it is still alive, because on the
// download-abort path it is never told. ⚠⚠ The v0.5.43 fix hung entirely off
// `onerror` and was INERT: measured on Firefox with a bare instrumented EventSource
// polled at 1 Hz across a download, the stream goes `OPEN → CLOSED` with NO error
// event — `closes: []`, `creates: []`, and no second `stream` request on the wire
// (Firefox does not natively retry either). Nothing can hang off an event that does
// not fire, so liveness must be POLLED. 1 s satisfies the closing condition's
// "a new stream request within ~1–2 s"; the check itself is a property read, and
// the 1 s → 30 s ladder still governs the RECONNECT, so a genuinely dead server is
// not polled into a retry storm.
const SSE_LIVENESS_INTERVAL_MS = 1_000;

/** bug202: the liveness poll's whole decision, exported so it is pinned by a test.
 *
 *  Reconnect on **CLOSED only**. ⚠ CONNECTING means the browser's own retry is in
 *  flight; reconnecting there races it and leaves the page holding two streams —
 *  which is why this asks for CLOSED specifically and NOT `!== OPEN`. That one
 *  substitution is the plausible future edit, and it is what `sse-liveness.test.ts`
 *  exists to catch.
 *
 *  ⛔ What this predicate does NOT cover, stated so nobody reads its green as more
 *  than it is: it cannot catch the defect being fixed here. The v0.5.43 fix failed
 *  because a real Firefox never FIRES `onerror` on this path — a stub fires whatever
 *  it is told to, so a unit test would have passed over that defect happily. This
 *  guards the rule, never the wiring; the wiring closes on deployed staging
 *  (bug202 §5, Firefox). ROOTS §B-5.8. */
/** bug190: the `connected` decision, exported so the TEST PINS THE REAL FUNCTION
 *  rather than a copy of its shape — the same reason `shouldReconnectStream` is
 *  exported. A replica test passes happily while the shipped wiring drifts.
 *
 *  The server emits `connected` on EVERY connect. The liveness poll only acts on
 *  CLOSED, so a transient drop recovered by the browser's OWN retry is invisible
 *  to us except through this event — and before bug190 nothing refreshed on it.
 *
 *  ⚠ The FIRST `connected` is skipped: it is the initial connect and the page has
 *  just loaded its listing. The flag is per-EventSource ON PURPOSE — a native
 *  retry re-fires on the SAME instance (so it refreshes), while our own reconnect
 *  builds a NEW instance whose first `connected` is skipped because
 *  `scheduleReconnect` has already refreshed. That is what stops the two paths
 *  double-refreshing. */
export function makeConnectedHandler(onReconnected: () => void): () => void {
  let seenConnected = false;
  return () => {
    if (!seenConnected) {
      seenConnected = true;
      return;
    }
    onReconnected();
  };
}

export function shouldReconnectStream(readyState: number): boolean {
  return readyState === /* EventSource.CLOSED */ 2;
}

/** A shared-with-me folder, shaped like a FolderView so the sidebar + navigation
 *  treat it like any other top-level folder (timestamps are unused here). */
function sharedToFolderView(shared: SharedFolderView): FolderView {
  return {
    folder_id: shared.folder_id,
    parent_folder_id: null,
    root_folder_id: shared.root_folder_id,
    folder_type: shared.folder_type,
    encrypted_name: shared.encrypted_name,
    created_at: 0,
    modified_at: 0,
  };
}

export class Browser {
  private readonly drive: Drive;
  private eventSource: EventSource | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectDelayMs = SSE_RECONNECT_BASE_MS;
  private livenessTimer: ReturnType<typeof setInterval> | null = null;

  me = $state<MeResponse | null>(null);
  quota = $state<QuotaResponse | null>(null);
  /** Top-level folders the account owns (private + owned share) — the sidebar. */
  topLevel = $state<NamedFolder[]>([]);
  /** The open folder's path; the last entry is the current folder (empty = home). */
  path = $state<Crumb[]>([]);
  childFolders = $state<NamedFolder[]>([]);
  files = $state<NamedFile[]>([]);
  /** Share folders shared *with* the caller (recipient) — merged into the sidebar. */
  sharedWithMe = $state<NamedFolder[]>([]);
  /** The PRSNs under this account's guardianship (humans only) — drives the
   *  per-PRSN nav sections (Bug009). */
  prsns = $state<GuardedPrsn[]>([]);
  /** Recipients of the share folder the share panel is open for. */
  recipients = $state<RecipientView[]>([]);
  /** Pending (un-accepted, un-expired) invitations on that folder — the owner's
   *  view (S121, W6): the surface that explains the write-lock + carries cancel. */
  pendingInvitations = $state<PendingInvitationView[]>([]);
  selectedFiles = $state<Set<string>>(new Set());
  selectedFolders = $state<Set<string>>(new Set());

  // ── Left-nav folder tree (§1-35) ────────────────────────────────────────────
  // Per-folder expand state + lazily-fetched child folders for the sidebar tree,
  // keyed by folder id so the state survives the reactive re-derivation of the
  // sidebar lists on every refresh. The fetch + decrypt + path navigation live
  // here (not in the component) so a future main-pane tree-table reuses them
  // unchanged — the presentation differs per surface, the logic does not.
  /** Folder ids the user has expanded in the nav tree. */
  treeExpanded = $state<Set<string>>(new Set());
  /** bug184: PRSN groups expanded in the sidebar. Lifted from Sidebar-local state so
   *  it can be persisted with the rest of the navigation position. */
  expandedPrsns = $state<Set<string>>(new Set());
  /** Decrypted child folders by parent id, cached on first expand. */
  treeChildren = $state<Map<string, NamedFolder[]>>(new Map());
  /** Parent ids whose children are currently being fetched. */
  treeLoading = $state<Set<string>>(new Set());

  loading = $state(true);
  busy = $state(false);
  error = $state('');
  /** bug044: the transient post-download confirmation (null = none showing). */
  downloaded = $state<{ fileName: string; count: number; chose: boolean } | null>(null);
  private downloadedTimer: ReturnType<typeof setTimeout> | undefined;
  dialog = $state<Dialog>(null);

  /** bug101: the per-item ⋯ / right-click actions menu — a single menu at the top
   *  level, opened by both the file panel and the left-nav tree. Holds the target
   *  item, whether the caller OWNS it (rename is owner-only, server-enforced),
   *  whether this particular item is DELETABLE by them (bug223 — not the same
   *  question: a file yields to a `read_write` recipient, a folder does not), and
   *  the viewport coords to render at. */
  contextMenu = $state<{
    x: number;
    y: number;
    file?: NamedFile;
    folder?: NamedFolder;
    owned: boolean;
    deletable: boolean;
  } | null>(null);
  /** Active upload progress, or null when idle — the BATCH record (F2,
   *  2026-09-23; `upload-batch.ts` owns its shape and its sums). Live BYTES +
   *  resilience signals (bug046/bug047): the FileList renders a determinate
   *  bytes-based bar (a slow upload never reads as frozen), the in-flight and
   *  retry notes, and — when a bad network window pauses a file — that file's
   *  Resume/Cancel affordance while the rest of the batch keeps moving. */
  uploadProgress = $state<UploadBatchState | null>(null);
  /** Active download progress, or null when idle (bug061). The FileList renders
   *  a determinate per-chunk bar — the honest read-path analog of the upload
   *  bar, so a slow download no longer reads as a frozen screen. */
  downloadProgress = $state<({ fileName: string } & DownloadProgress) | null>(null);
  /** The in-flight batch's control surface (resume/cancel, whole or per file); null when idle. */
  private uploadBatch: UploadBatch<PlanItem> | null = null;
  /** A folder drop's preparation, before the batch exists (folder-upload design
   *  note §2.4): the tree walk (`reading`, files found so far) or the folder
   *  creation (`creating`, n of m). Null otherwise. */
  folderPrep = $state<FolderPrep | null>(null);
  /** The batch-end note for skipped OS clutter (Gus, v01 review answer 2); empty
   *  when there is nothing to say. Cleared when the next upload starts. */
  uploadNotice = $state('');

  constructor(session: Session) {
    this.drive = new Drive(createApiClient(), session);
  }

  get isPrsn(): boolean {
    return this.me?.account_type === 'prsn';
  }

  get current(): Crumb | null {
    return this.path.at(-1) ?? null;
  }

  get currentRootId(): string | null {
    return this.path[0]?.rootFolderId ?? null;
  }

  get selectionCount(): number {
    return this.selectedFiles.size + this.selectedFolders.size;
  }

  /** Humans see a private-folders section; both kinds see share folders. */
  get privateFolders(): NamedFolder[] {
    return this.topLevel.filter((f) => f.view.folder_type === 'private');
  }

  get shareFolders(): NamedFolder[] {
    return [...this.topLevel.filter((f) => f.view.folder_type !== 'private'), ...this.sharedWithMe];
  }

  /** Share folders the account *owns* (the "Your share folders" zone) — excludes
   *  folders shared *with* it. */
  get ownedShareFolders(): NamedFolder[] {
    return this.topLevel.filter((f) => f.view.folder_type !== 'private');
  }

  /** The "shared with me" folders grouped by owner: one section per dependent PRSN,
   *  plus the folders other humans shared in. The Guardian's per-PRSN nav (Bug009). */
  get groupedShares(): GroupedShares {
    return groupSharedByOwner(this.sharedWithMe, this.prsns);
  }

  /** When the open folder's hierarchy root is one of this Guardian's PRSNs' folders,
   *  the owning PRSN — so the UI can flag "you're in <prsn>'s folder" (read-write as
   *  Guardian). Null otherwise. */
  get currentPrsnOwner(): GuardedPrsn | null {
    const rootId = this.currentRootId;
    if (!rootId) return null;
    const shared = this.sharedWithMe.find((f) => f.view.folder_id === rootId);
    if (!shared?.ownerAccountId) return null;
    return this.prsns.find((p) => p.account_id === shared.ownerAccountId) ?? null;
  }

  /** The caller's relationship to the open folder's root, when it's a share
   *  folder: an owner can invite/remove, a recipient can leave. */
  get currentShareRole(): 'owner' | 'recipient' | null {
    const rootId = this.currentRootId;
    if (!rootId) return null;
    if (
      this.topLevel.some((f) => f.view.folder_id === rootId && f.view.folder_type !== 'private')
    ) {
      return 'owner';
    }
    if (this.sharedWithMe.some((f) => f.view.folder_id === rootId)) return 'recipient';
    return null;
  }

  /** bug101: does the signed-in account OWN the open folder's root? `currentShareRole`
   *  is 'owner' for an owned share root and null for a private folder (both owned) —
   *  only a 'recipient' root belongs to someone else (a folder shared *to* you, incl.
   *  a PRSN's folder you hold as Guardian).
   *
   *  ⚠⚠ **bug223 CORRECTION.** This comment used to read "rename / move / DELETE are
   *  owner-only server-side", and the delete third of that was FALSE — `delete_file`
   *  and `delete_files_batch` resolve `sharing::folder_authority`, which grants a
   *  `read_write` recipient `Write` (bug208 §3b, Chris's ruling: *write authority IS
   *  delete authority*). The belief written here is what produced the defect. **Rename
   *  and move ARE owner-only** (`files.rs::update_file`, owner-scoped on both the file
   *  and the destination), so those two still gate on this. **Delete gates on
   *  `canWriteCurrentRoot`.** */
  get ownsCurrentRoot(): boolean {
    return this.currentShareRole !== 'recipient';
  }

  /** bug223: may this account ADD AND REMOVE content in the open folder's root?
   *  True for an owner, and for a recipient holding `read_write` — which every
   *  Guardian holds on a PRSN's share folder **by construction**: `sharing.rs`
   *  inserts that row itself with `permission = 'read_write', is_mandatory_guardian
   *  = TRUE` when a PRSN creates a share folder (Chris, S191: *"Guardians are always
   *  read-write on all PRSN account folders — that is what we planned"*).
   *
   *  ⚠ The defect this exists to fix is a MODEL MISMATCH, not a missing check: the
   *  server's authority is ternary (`None | Read | Write`) and the client's was
   *  binary (owner | not), so a `read_write` recipient was rendered read-only for
   *  delete (server allows) and full-owner for new-folder (server refuses). Both
   *  cells were wrong, in opposite directions.
   *
   *  ⚠ Fails CLOSED: an unknown or absent permission is not `read_write`, so a
   *  recipient whose row the client could not read is treated as read-only. */
  get canWriteCurrentRoot(): boolean {
    const rootId = this.currentRootId;
    const permission = rootId
      ? this.sharedWithMe.find((f) => f.view.folder_id === rootId)?.permission
      : undefined;
    return mayAddContent(this.currentShareRole, permission);
  }

  /** bug223: may the current SELECTION be deleted? ⚠⚠ **Delete is not one rule.**
   *  A FILE resolves `sharing::folder_authority`, so a `read_write` recipient may
   *  delete it (bug208 §3b). A FOLDER is owner-only — `folders.rs` deletes with
   *  `WHERE folder_id = $1 AND account_id = $2` and answers `not_found` otherwise.
   *  The toolbar's Delete acts on a mixed selection, so gating it on write authority
   *  alone would offer a recipient a button the server refuses for any folder in the
   *  selection — the same shape as the bug223 defect, one layer down.
   *  ⇒ Any folder in the selection raises the bar to ownership. */
  get canDeleteSelection(): boolean {
    return mayDelete(this.ownsCurrentRoot, this.canWriteCurrentRoot, this.selectedFolders.size > 0);
  }

  /** bug223: may THIS item be deleted? The per-item form of `canDeleteSelection`,
   *  for the ⋯ menu, which always acts on exactly one file or one folder. */
  canDeleteItem(item: { file?: NamedFile; folder?: NamedFolder }): boolean {
    return mayDelete(this.ownsCurrentRoot, this.canWriteCurrentRoot, item.folder !== undefined);
  }

  /** The lone selected item, when exactly one is selected (rename targets it). */
  get singleSelection(): { file?: NamedFile; folder?: NamedFolder } | null {
    if (this.selectionCount !== 1) return null;
    if (this.selectedFiles.size === 1) {
      const id = [...this.selectedFiles][0];
      const file = this.files.find((f) => f.view.file_id === id);
      return file ? { file } : null;
    }
    const id = [...this.selectedFolders][0];
    const folder = this.childFolders.find((f) => f.view.folder_id === id);
    return folder ? { folder } : null;
  }

  /** Same-root move destinations: up to the parent, or into a subfolder (the
   *  folders being moved are excluded — you can't move one into itself). v1 keeps
   *  the picker to the visible hierarchy; arbitrary same-root move is a polish item. */
  get moveTargets(): { folderId: string; label: string }[] {
    const targets: { folderId: string; label: string }[] = [];
    // "Up" is the parent, when there is one; a top-level folder is its own root,
    // so moving it up would re-root (unsupported in v1).
    const parent = this.path.at(-2);
    if (parent) targets.push({ folderId: parent.folderId, label: `↑ ${parent.name}` });
    for (const folder of this.childFolders) {
      if (!this.selectedFolders.has(folder.view.folder_id)) {
        targets.push({ folderId: folder.view.folder_id, label: folder.name });
      }
    }
    return targets;
  }

  async init(): Promise<void> {
    this.loading = true;
    this.error = '';
    try {
      const [me, quota] = await Promise.all([this.drive.me(), this.drive.quota()]);
      this.me = me;
      this.quota = quota;
      // The guardianship roster (humans only; a PRSN has no dependents) drives the
      // per-PRSN nav. Loaded once — the roster is stable across folder changes.
      if (me.account_type !== 'prsn') await this.loadPrsns();
      await this.loadTopLevel();
      await this.loadSharedWithMe();
      // bug184: reopen where the user was. AFTER the folder lists load (the walk
      // resolves names from them) and BEFORE connect(), so a restore cannot race an
      // SSE-driven refresh. Fails soft to Home by contract.
      await this.restoreNav();
      this.connect();
      // bug226: restoreNav brings back WHICH nodes are expanded but not their
      // children, so without this the tree renders expanded-and-unknown — which the
      // template used to display as "No subfolders."
      //
      // ⚠⚠ DELIBERATELY NOT AWAITED (Gus, F2-review). Awaiting it put the whole page
      // behind one serial round-trip PER EXPANDED DEPTH before `loading` cleared: a
      // Guardian with four levels open on a high-RTT link waited four-plus RTTs to see
      // anything. ⭐ The three-state render is what makes firing-and-forgetting safe —
      // each node carries its own spinner until its level lands, instead of the page
      // holding still for all of them. Nothing here rejects: `loadTreeChildren`
      // catches internally.
      void this.hydrateVisibleTree();
    } catch (e) {
      this.error = friendlyDriveError(e);
    } finally {
      this.loading = false;
    }
  }

  /** Subscribe to the SSE change stream; any change event schedules a refresh,
   *  so a folder/file changed in another session (e.g. another device) shows up
   *  here without a manual reload. EventSource carries the session cookie
   *  same-origin.
   *
   *  ⚠⚠ bug202 (S179): this comment previously asserted EventSource "reconnects on
   *  drop on its own", and **that prose was a runtime claim falsified by
   *  observation** (ROOTS §B-2.6). Measured on Firefox, on two independent
   *  downloads: `GET /v1/changes/stream` ends `NS_BINDING_ABORTED` during a
   *  download and **no reconnect appears in a ~2.7 min window**.
   *
   *  The distinction the old comment missed: EventSource retries a **transient**
   *  failure itself (readyState CONNECTING), but a hard **abort** closes it
   *  permanently (readyState CLOSED) and nothing restarts it. `dispose()` — the
   *  only `close()` path — had not run.
   *
   *  Why a download aborts it: the trigger is a bare top-level navigation, and a
   *  navigation cancels in-flight requests. That is bug198's own mechanism; the
   *  fence fixed the **chunk loop** by starting it after `consumed`, but it cannot
   *  protect a connection already open when the trigger fires. ⭐ Gus's S179
   *  enumeration of the class — "the page's open request sources" — names two that
   *  matter: this stream, and concurrent uploads (still unmeasured).
   *
   *  Consequence when unfixed: after any web download the file list silently stops
   *  updating live for the page's lifetime — a file added by another device or a
   *  PRSN never appears until a manual reload. */
  private connect(): void {
    if (typeof EventSource === 'undefined' || this.eventSource) return;
    const source = new EventSource('/v1/changes/stream', { withCredentials: true });
    attachChangeListeners(source, () => this.scheduleRefresh());
    // ── bug190: close the gap on the path our liveness poll CANNOT see ────────
    //
    // The server emits `connected` on EVERY connect. Our poll only acts on
    // CLOSED, and `scheduleReconnect` refreshes on that path — but a TRANSIENT
    // drop recovered by the browser's OWN retry never reaches CLOSED, so nothing
    // refreshed and the view silently kept a gap. That recovery is invisible to
    // us except through this event.
    //
    // ⚠ The FIRST `connected` is skipped deliberately: it is the initial connect,
    // and the page has just loaded its listing, so refreshing there is a
    // redundant round trip. Only a RE-connect implies events were missed.
    // The flag is per-EventSource ON PURPOSE — a native retry re-fires
    // `connected` on the SAME instance (so it refreshes, which is the point),
    // while our own reconnect builds a NEW instance whose first `connected` is
    // correctly skipped because `scheduleReconnect` has already refreshed. That
    // is what keeps the two paths from double-refreshing.
    source.addEventListener(
      'connected',
      makeConnectedHandler(() => this.scheduleRefresh()),
    );
    // A stream that opened is a healthy one: reset the ladder so the next abort
    // retries promptly rather than inheriting an old backoff.
    source.onopen = () => {
      this.reconnectDelayMs = SSE_RECONNECT_BASE_MS;
    };
    this.eventSource = source;
    this.startLivenessCheck();
  }

  /** bug202: the liveness check — the only thing that notices a dead stream.
   *
   *  ⚠⚠ This REPLACES the `onerror` reconnect rather than adding to it. The S179
   *  fix reasoned about *which* `readyState` `onerror` would report and shipped in
   *  v0.5.43; the measurement says `onerror` does not fire at all on this path, so
   *  the fix was inert and the closing condition failed on deployed staging. A
   *  poll subsumes the with-error case anyway — that close also lands in CLOSED —
   *  so there is nothing left for an error handler to do.
   *
   *  ⚠ CONNECTING is deliberately left alone: the browser's own retry is in flight
   *  and a second attempt would race it and double the streams. That half of the
   *  original reasoning survives, and it is the reason this tests for CLOSED
   *  specifically rather than "not OPEN". */
  private startLivenessCheck(): void {
    if (this.livenessTimer !== null) return;
    this.livenessTimer = setInterval(() => {
      const source = this.eventSource;
      if (!source || !shouldReconnectStream(source.readyState)) return;
      source.close();
      this.eventSource = null;
      this.scheduleReconnect();
    }, SSE_LIVENESS_INTERVAL_MS);
  }

  /** Reconnect the change stream after a hard close, backing off 1s → 30s.
   *  ⚠ The reconnect ALSO refreshes: changes that happened while we were
   *  disconnected produced no event, so a silent reconnect would leave the list
   *  stale — which is the same user-visible symptom the reconnect exists to end. */
  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;
    const delay = this.reconnectDelayMs;
    this.reconnectDelayMs = Math.min(delay * 2, SSE_RECONNECT_MAX_MS);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
      this.scheduleRefresh();
    }, delay);
  }

  /** Coalesce a burst of change events into one refresh. */
  private scheduleRefresh(): void {
    if (this.refreshTimer !== null) clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = null;
      void this.refresh();
    }, 300);
  }

  /** Close the stream + cancel any pending refresh (call on sign-out / unmount). */
  dispose(): void {
    this.eventSource?.close();
    this.eventSource = null;
    if (this.refreshTimer !== null) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    // bug202: a pending reconnect must die with the browser, or a disposed
    // instance resurrects its own stream after sign-out.
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    // ⚠ And so must the liveness poll — it is an interval, so unlike the reconnect
    // timeout it never stops on its own. A surviving one would see `eventSource`
    // null, do nothing, and tick forever after sign-out.
    if (this.livenessTimer !== null) {
      clearInterval(this.livenessTimer);
      this.livenessTimer = null;
    }
    this.reconnectDelayMs = SSE_RECONNECT_BASE_MS;
  }

  async openTopLevel(folder: NamedFolder): Promise<void> {
    this.path = [
      { folderId: folder.view.folder_id, rootFolderId: folder.view.folder_id, name: folder.name },
    ];
    await this.loadContents();
    this.persistNav(); // bug184
  }

  async openChild(folder: NamedFolder): Promise<void> {
    const rootFolderId = this.currentRootId ?? folder.view.folder_id;
    this.path = [
      ...this.path,
      { folderId: folder.view.folder_id, rootFolderId, name: folder.name },
    ];
    await this.loadContents();
    this.persistNav(); // bug184
  }

  async navigateTo(index: number): Promise<void> {
    this.path = this.path.slice(0, index + 1);
    await this.loadContents();
    this.persistNav(); // bug184
  }

  async goHome(): Promise<void> {
    this.path = [];
    this.childFolders = [];
    this.files = [];
    this.clearSelection();
    this.persistNav(); // bug184: Home is a position too — persist it, or a reload
    // after going Home would reopen the folder you deliberately left.
    await this.refresh();
  }

  /** Open a folder addressed by its full path (a nav-tree name-click). Sets the
   *  whole breadcrumb at once — unlike openChild, which appends one level. */
  async openTreePath(path: Crumb[]): Promise<void> {
    if (path.length === 0) return;
    this.path = path;
    await this.loadContents();
    this.persistNav(); // bug184
  }

  /** bug184: snapshot where we are, so a reload does not drop the user at Home.
   *
   *  ⚠ IDS ONLY. A Crumb carries the DECRYPTED folder name and sessionStorage is readable
   *  by any script on this origin — `persist.ts` keeps the KEM key non-extractable for
   *  exactly that reason, so writing plaintext names beside it would expose more than the
   *  key store does. Names are re-derived at restore from data this session has already
   *  decrypted. `nav-persist` drops a name defensively too, in case this is ever changed. */
  private persistNav(): void {
    saveNavState({
      path: this.path.map((c) => ({ folderId: c.folderId, rootFolderId: c.rootFolderId })),
      treeExpanded: [...this.treeExpanded],
      expandedPrsns: [...this.expandedPrsns],
    });
  }

  /** bug184: walk the saved id-chain back into Crumbs, resolving each name from loaded
   *  data, and open as deep as we can get.
   *
   *  ⚠ FAILS SOFT AT EVERY STEP, by contract (bug184 §4/§5.2): a folder since deleted,
   *  unshared, or belonging to another account simply ends the walk, and we open however
   *  far we got — Home if that is nowhere. A restore is an optimisation and must never
   *  become a new failure mode. ⭐ The stale-pointer arm is the realistic input here, not
   *  the happy one: the record outlives the folders it names. */
  private async restoreNav(): Promise<void> {
    const saved = loadNavState();
    // Expansion state is pure ids — restore it directly, whatever happens to the path.
    if (saved.treeExpanded.length) this.treeExpanded = new Set(saved.treeExpanded);
    if (saved.expandedPrsns.length) this.expandedPrsns = new Set(saved.expandedPrsns);
    if (!saved.path.length) return;

    const crumbs: Crumb[] = [];
    let candidates: NamedFolder[] = [...this.topLevel, ...this.sharedWithMe];
    for (const step of saved.path) {
      const hit = candidates.find((f) => f.view.folder_id === step.folderId);
      if (!hit) break; // gone, unshared, or never ours — stop here and open what we have
      crumbs.push({
        folderId: hit.view.folder_id,
        rootFolderId: hit.view.root_folder_id ?? hit.view.folder_id,
        name: hit.name,
      });
      try {
        candidates = await this.loadChildFolders(hit.view.folder_id);
      } catch {
        break; // a failed child fetch ends the walk; it never fails the page
      }
    }
    if (crumbs.length) await this.openTreePath(crumbs);
  }

  /** bug184: toggle a PRSN group in the sidebar. Lives here rather than in the
   *  component so it persists with the rest of the navigation position. */
  togglePrsn(accountId: string): void {
    const next = new Set(this.expandedPrsns);
    if (next.has(accountId)) next.delete(accountId);
    else next.add(accountId);
    this.expandedPrsns = next;
    this.persistNav();
  }

  /** Toggle a folder's tree expansion; lazily fetch + decrypt its child folders
   *  the first time it opens (FolderView carries no child count, so every folder
   *  is expandable and the fetch is what reveals whether it has subfolders). */
  async toggleTree(folder: NamedFolder): Promise<void> {
    const id = folder.view.folder_id;
    const next = new Set(this.treeExpanded);
    if (next.has(id)) {
      next.delete(id);
      this.treeExpanded = next;
      this.persistNav(); // bug184: a COLLAPSE is state too — this arm returns early
      return;
    }
    next.add(id);
    this.treeExpanded = next;
    this.persistNav(); // bug184
    if (!this.treeChildren.has(id)) await this.loadTreeChildren(id);
  }

  private async loadTreeChildren(parentId: string): Promise<void> {
    this.treeLoading = new Set(this.treeLoading).add(parentId);
    try {
      const named = await this.loadChildFolders(parentId);
      this.treeChildren = new Map(this.treeChildren).set(parentId, named);
    } catch (e) {
      // ⭐ bug226 (Gus's ruling) — the honest state after a failed fetch is NOT
      // EXPANDED. An open chevron with nothing under it is this same bug rendered in
      // whitespace: the user reads it as empty. Collapsing keeps the tree to exactly
      // three states (`undefined | [] | non-empty`), each with a defined render, and
      // makes the chevron itself the retry affordance. The global error still carries
      // the failure. ⚠ Cost, accepted and visible: a transient failure on reload loses
      // that node's restored expansion.
      this.collapseTreeNode(parentId);
      this.error = friendlyDriveError(e);
    } finally {
      const done = new Set(this.treeLoading);
      done.delete(parentId);
      this.treeLoading = done;
    }
  }

  /** Fetch + decrypt the child folders of `parentId`. The reusable fetch seam for
   *  any tree surface (the left-nav now; a main-pane tree-table later). */
  async loadChildFolders(parentId: string): Promise<NamedFolder[]> {
    const { folders } = await this.drive.listFolders(parentId);
    return this.decryptFolders(folders);
  }

  /** Re-fetch children for every *cached* tree node (not just the currently-expanded
   *  ones) so the nav stays consistent with the main pane after a mutation / SSE
   *  change. Refreshing only expanded nodes left a collapsed-but-cached node stale:
   *  a subfolder created under such a node wasn't picked up, so re-expanding it
   *  showed a stale "No subfolders." until a reload cleared the cache (Bug012). A
   *  transient failure keeps the prior children rather than blanking the tree. */
  /** bug226 — fetch children for every expanded node the user can actually SEE.
   *
   *  ⚠ Deliberately NOT "every id in `treeExpanded`". A node under a collapsed parent
   *  never renders, so fetching it buys nothing and costs a connection —
   *  `visibleUnfetchedExpanded` returns only the reachable frontier, and because the
   *  walk stops at each unfetched node this loop advances **one level per round**.
   *
   *  ⚠ THREE independent terminators, and it is worth knowing which is doing the work.
   *  (1) A failed fetch now COLLAPSES its node, so it leaves the frontier by ceasing to
   *  be visible — this is the real mechanism. (2) `attempted` still bounds each node to
   *  one try per load, and keeps termination true if (1) is ever changed. (3) The depth
   *  counter is a backstop only (§B-4.7: bound every wait). ⭐ Recorded because a
   *  guard that has quietly stopped being load-bearing is one nobody re-checks.
   *
   *  ⚠ **A benign overlap, named so nobody "fixes" it** (Gus): this and a user's own
   *  `toggleTree` can fetch the same id at once — two requests, identical data, last
   *  write wins through the per-id merge. **Harmless.** A lock here would add a
   *  failure mode to prevent a duplicate GET. */
  /** bug226 — collapse one node and persist it, the single place that models
   *  "we could not show you what is in here." Mirrors `toggleTree`'s collapse arm,
   *  including its `persistNav()`, so a failure does not resurrect on the next load. */
  private collapseTreeNode(id: string): void {
    if (!this.treeExpanded.has(id)) return;
    const next = new Set(this.treeExpanded);
    next.delete(id);
    this.treeExpanded = next;
    this.persistNav();
  }

  private async hydrateVisibleTree(): Promise<void> {
    const rootIds = [...this.topLevel, ...this.sharedWithMe].map((f) => f.view.folder_id);
    const attempted = new Set<string>();
    for (let depth = 0; depth < 12; depth++) {
      const frontier = visibleUnfetchedExpanded(
        rootIds,
        this.treeExpanded,
        this.treeChildren,
      ).filter((id) => !attempted.has(id));
      if (frontier.length === 0) return;
      frontier.forEach((id) => attempted.add(id));
      await Promise.all(frontier.map((id) => this.loadTreeChildren(id)));
    }
    // ⭐ Past the backstop: collapse whatever is still unknown rather than leave it
    // spinning (Gus). "Beyond the depth bound" must not be a permanent spinner — that
    // is this bug in a different sentence, which is exactly what the failure path
    // above is collapsing for.
    visibleUnfetchedExpanded(rootIds, this.treeExpanded, this.treeChildren).forEach((id) =>
      this.collapseTreeNode(id),
    );
  }

  private async refreshTree(): Promise<void> {
    const cached = [...this.treeChildren.keys()];
    if (cached.length === 0) return;
    await Promise.all(
      cached.map(async (id) => {
        try {
          const named = await this.loadChildFolders(id);
          // ⚠⚠ bug226 F2 (Gus) — MERGE into the live map on each completion; do NOT
          // snapshot up front and assign the snapshot back at the end. That older
          // shape LOST any write that landed during the await: a `toggleTree` expand
          // finishing mid-refresh, or a hydration round, was reverted to `undefined`.
          // Under the pre-bug226 template that node then rendered "No subfolders." —
          // ⭐ a second, independent producer of this bug's symptom, and a likely
          // cause of the §6 sightings that followed "messy sequences" and were
          // dismissed as transient. Same per-id merge `loadTreeChildren` already uses.
          this.treeChildren = new Map(this.treeChildren).set(id, named);
        } catch {
          // keep the prior children on a transient failure
        }
      }),
    );
  }

  async createFolder(name: string): Promise<void> {
    const trimmed = name.trim();
    if (!trimmed) return;
    const dialog = this.dialog;
    const topLevel = dialog?.kind === 'newFolder' ? dialog.topLevel : false;
    await this.mutate(async () => {
      const parent = topLevel ? null : this.current;
      await this.drive.createFolder(
        trimmed,
        parent ? { folderId: parent.folderId, rootFolderId: parent.rootFolderId } : undefined,
      );
    });
  }

  /** Create a top-level share folder (owned) — it appears under the sidebar's
   *  share section after the refresh. */
  async createShareFolder(name: string): Promise<void> {
    const trimmed = name.trim();
    if (!trimmed) return;
    await this.mutate(async () => {
      await this.drive.createShareFolder(trimmed);
    });
  }

  /** Open the share panel for the current folder's root share folder. */
  async openSharePanel(): Promise<void> {
    const role = this.currentShareRole;
    const rootId = this.currentRootId;
    if (!role || !rootId) return;
    this.dialog = { kind: 'sharePanel', rootFolderId: rootId, role };
    this.error = '';
    this.recipients = [];
    this.pendingInvitations = [];
    await this.loadRecipients(rootId);
    // Pending invitations are an owner-only read (the endpoint 404s otherwise).
    if (role === 'owner') {
      await this.loadInvitations(rootId);
    }
  }

  /** Invite a recipient to a share folder; returns the invitation token (for the
   *  shareable link) or null on failure. Refreshes the recipient list. */
  async invite(rootFolderId: string, handle: string, permission: string): Promise<string | null> {
    const trimmed = handle.trim();
    if (!trimmed) return null;
    this.busy = true;
    this.error = '';
    try {
      const result = await this.drive.inviteToShareFolder(
        { folderId: rootFolderId, rootFolderId },
        trimmed,
        permission,
      );
      await this.loadRecipients(rootFolderId);
      await this.loadInvitations(rootFolderId);
      return result.token;
    } catch (e) {
      // Bug005(b): the server answers a DUPLICATE pending invitation with
      // version_conflict (sharing.rs), which the generic drive mapping words as a
      // NAME collision ("That name is already in use here") — misleading in this
      // dialog. The call site knows it was an invite, so it words the 409 honestly.
      if (e instanceof SignetApiError && e.code === 'version_conflict') {
        this.error =
          'That recipient already has a pending invitation for this folder — ' +
          'send them the link you generated, or try again after it expires.';
      } else {
        this.error = friendlyDriveError(e);
      }
      return null;
    } finally {
      this.busy = false;
    }
  }

  /** Cancel a pending invitation (owner action; S121, W6). Deleting it releases
   *  the folder's write-lock server-side; the token that was generated for it
   *  stops working. Refreshes the pending list. */
  async cancelInvitation(rootFolderId: string, invitationId: string): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await this.drive.cancelInvitation(rootFolderId, invitationId);
      await this.loadInvitations(rootFolderId);
    } catch (e) {
      this.error = friendlyDriveError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Remove a recipient (owner action); refreshes the recipient list. */
  async removeRecipient(rootFolderId: string, recipientId: string): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await this.drive.removeRecipient(rootFolderId, recipientId);
      await this.loadRecipients(rootFolderId);
    } catch (e) {
      this.error = friendlyDriveError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Leave a share folder (recipient action); returns home and refreshes. */
  async leave(rootFolderId: string): Promise<void> {
    await this.mutate(async () => {
      await this.drive.leaveShareFolder(rootFolderId);
      this.path = [];
      this.childFolders = [];
      this.files = [];
    });
  }

  /**
   * bug070: the pre-flight refusal for a batch, or `null` to proceed.
   *
   * The server already refuses both of these correctly and cheaply, at
   * `multipart::initiate` before a single byte reaches object storage. What was
   * missing was refusing *before starting*: a user with 500 MB free could kick off a
   * 50 GB upload and learn it failed from a round trip, and a batch that did not fit
   * uploaded files one by one until one failed — quota honoured, nothing corrupted,
   * but no warning that the batch could never complete.
   *
   * Both comparisons use **stored (ciphertext) sizes** from `Drive.uploadPlan`, the
   * same function the upload declares from. Comparing `File.size` against a ceiling
   * the server applies to ciphertext is what made the old guard wrong at the
   * boundary.
   */
  private async preflightCapacity(files: File[], cap: number | undefined): Promise<string | null> {
    // Stored (ciphertext) sizes from the same planner the upload declares from.
    const candidates = files.map((file) => ({
      name: file.name,
      storedSize: this.drive.uploadPlan(file.size).storedSize,
    }));

    // Read the quota FRESH rather than trusting `this.quota`: the cached figure can
    // be stale by a whole previous batch, or by a PRSN in the same Guardian pool
    // uploading concurrently, and this decides whether to start at all. A failed read
    // yields null, which `capacityRefusal` treats as fail-open by contract.
    let remaining: number | null = null;
    try {
      const fresh = await this.drive.quota();
      remaining = Math.max(0, fresh.bytes_quota - fresh.bytes_used);
    } catch {
      remaining = null;
    }

    return capacityRefusal(candidates, cap ?? null, remaining);
  }

  /** The Upload button: plain files into the current folder. */
  async uploadFiles(fileList: FileList | File[]): Promise<void> {
    const files = Array.from(fileList);
    if (files.length === 0) return;
    await this.uploadPlan({
      folders: [],
      files: files.map((file) => ({ file, folder: null })),
      skipped: 0,
    });
  }

  /** A DROP: files, folders, or both (folder-upload design note §2.2). The capture
   *  was taken synchronously inside the drop event; this resolves the whole tree
   *  BEFORE anything is created, so an unreadable entry refuses the drop with
   *  nothing done (refuse before acting, bug070). */
  async uploadDrop(capture: DropCapture): Promise<void> {
    if (!this.current || this.busy) return;
    this.error = '';
    this.uploadNotice = '';
    // ⛔ An item the browser gave no entry for is refused, never uploaded: it is
    // the class that produced the dead `RAW` file (Chris, 2026-09-25).
    if (capture.unreadable.length > 0) {
      this.error = m.err_drop_not_readable({ names: capture.unreadable.join(', ') });
      return;
    }
    if (capture.entries.length === 0) return;
    // ⛔ Folder creation is owner-only (see `uploadPlan`). The capture already
    // knows which entries are folders, so a non-owner's folder drop is refused
    // HERE, before the walk reads a single file (Gus, code review note a).
    if (capture.entries.some((e) => e.isDirectory) && !this.ownsCurrentRoot) {
      this.error = m.err_drop_folders_not_owner();
      return;
    }
    // Busy for the walk too, so a second drop cannot start alongside it.
    this.busy = true;
    this.folderPrep = { kind: 'reading', files: 0 };
    let plan: FolderUploadPlan;
    try {
      plan = await resolveEntries(capture.entries, (files) => {
        this.folderPrep = { kind: 'reading', files };
      });
    } catch (e) {
      this.error =
        e instanceof DropReadError
          ? m.err_drop_unreadable({ path: e.path })
          : friendlyDriveError(e);
      return;
    } finally {
      this.folderPrep = null;
      this.busy = false;
    }
    await this.uploadPlan(plan);
  }

  /** The Upload menu's "Folder…" (§2.6; Chris, 2026-09-25): a folder chosen with
   *  `<input webkitdirectory>`. */
  async uploadPickedFolder(fileList: FileList | File[]): Promise<void> {
    if (!this.current || fileList.length === 0) return;
    this.error = '';
    this.uploadNotice = '';
    await this.uploadPlan(planFromRelativePaths(fileList));
  }

  /** Upload a plan into the current folder: create its folders parent-first, then
   *  ONE batch over every file, each file carrying its own target (§2.4). A plain
   *  file upload is the plan with no folders, so it runs the identical path. */
  private async uploadPlan(plan: FolderUploadPlan): Promise<void> {
    const folder = this.current;
    if (!folder) return;
    this.uploadNotice = '';
    if (plan.files.length === 0 && plan.folders.length === 0) {
      this.showUploadSkipped(plan.skipped);
      return;
    }
    // ⛔ Creating a folder is OWNER-only on the server (folders.rs resolves the
    // parent with `account_id = you`; bug223), while uploading files is open to a
    // read_write recipient. So a folder upload into someone else's share folder
    // would fail at its first folder — refuse it here, before anything is created.
    if (plan.folders.length > 0 && !this.ownsCurrentRoot) {
      this.error = m.err_drop_folders_not_owner();
      return;
    }
    const cap = this.me?.max_upload_size_bytes;
    // bug070: refuse before a single byte moves — and, for a folder upload, before a
    // single folder is created — on the two grounds the server will refuse on. This
    // runs against STORED sizes from `Drive.uploadPlan` — the same function the
    // upload declares from — because the server's ceiling and its quota reservation
    // both apply to ciphertext, not to `File.size`.
    const preflight = await this.preflightCapacity(
      plan.files.map((f) => f.file),
      cap,
    );
    if (preflight) {
      this.error = preflight;
      return;
    }
    // A share-folder upload must wrap each file's DEK to the folder's recipients
    // (S049); a private folder (null role) stays self-only. Read ONCE: every target
    // of a folder upload sits under the drop target's root, so they all share it.
    const shareFolder = this.currentShareRole !== null;
    // §2.3: a dropped folder whose name is taken among the target's SUBFOLDERS is
    // created as "RAW (1)" by bug048's rule — never merged. Folder names dedupe
    // against folders only, file names against files only (today's client
    // namespace; the server stores names opaquely), so a folder may share a
    // file's name (Gus, v01 review). Nested folders are new, so they keep theirs.
    const folderNames = nameFolders(
      plan.folders,
      this.childFolders.map((f) => f.name),
      dedupeName,
    );
    // Filled once the folders are created; index = the plan's folder index.
    let targets: FolderTarget[] = [];
    // F4 (2026-09-21): the transfer layer has no `document`. Forward page
    // visibility so a retry after a suspension refreshes from the server
    // (drive.ts), and hold the screen awake for a long upload (the lock is
    // gated on the transfer layer's own forecast, in wake-lock.ts).
    const wakeLock = new UploadWakeLock(
      typeof navigator !== 'undefined'
        ? (navigator as Navigator & { wakeLock?: WakeLockApiLike }).wakeLock
        : undefined,
    );
    // bug048: the target may already hold these names (names are ciphertext to
    // the server — zero-access — so uniqueness is a CLIENT decision; the CLI
    // applies the identical rule, names.ts ↔ names.rs). Each target folder keeps
    // its own taken-set, which also accumulates the batch's own choices, so
    // dropping "a.txt" twice yields "a.txt" + "a (1).txt". The batch chooses names
    // in file order, before any await (upload-batch.ts). A new folder starts empty.
    const items: PlanItem[] = plan.files.map((p) => ({
      name: p.file.name,
      size: p.file.size,
      file: p.file,
      folder: p.folder,
    }));
    // F2 (2026-09-23): the batch keeps up to N files open on ONE slot pool —
    // the scheduling and the record's sums live in upload-batch.ts, tested
    // there; this store wires `document` in and the record out.
    const batch = new UploadBatch<PlanItem>({
      files: items,
      dedupe: perFolderDedupe(
        this.files.map((f) => f.name),
        dedupeName,
      ),
      // bug070: the SAME planner the pre-flight compared against.
      planParts: (size) => this.drive.uploadPlan(size),
      upload: (item, uploadName, onProgress, controller, slots) => {
        const target =
          item.folder === null
            ? { folderId: folder.folderId, rootFolderId: folder.rootFolderId }
            : targets[item.folder];
        // The File streams chunk-by-chunk inside Drive.uploadFile (peak memory is
        // N chunks across the batch); progress reports live bytes + retries + the
        // paused state per file, summed by the batch.
        return this.drive.uploadFile(
          { folderId: target.folderId, rootFolderId: target.rootFolderId, shareFolder },
          uploadName,
          item.file,
          onProgress,
          controller,
          slots,
        );
      },
      onState: (state) => {
        this.uploadProgress = state;
        wakeLock.consider(state.etaSeconds);
      },
      // The document's CURRENT state first: a batch begun while hidden has no
      // hide transition to learn from (Gus, fold 2).
      initiallyVisible: document.visibilityState === 'visible',
    });
    this.uploadBatch = batch;
    const onVisibilityChange = () => {
      const visible = document.visibilityState === 'visible';
      batch.setVisibility(visible);
      if (visible) wakeLock.onVisible();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    // Abandoning the page mid-upload is a ROLLBACK by design (the File handle
    // cannot survive a reload, so cross-reload resume is structurally out):
    // fire a best-effort keepalive abort for every open file so the
    // reservations free promptly — the server's expiry sweep is the backstop. A
    // bfcache restore (`persisted`) keeps the page alive, so the uploads are
    // left alone.
    const onPageHide = (event: PageTransitionEvent) => {
      if (event.persisted) return;
      for (const active of batch.activeUploads()) {
        void fetch(
          `/v1/files/${encodeURIComponent(active.fileId)}/multipart/${encodeURIComponent(active.uploadId)}`,
          { method: 'DELETE', credentials: 'include', keepalive: true },
        ).catch(() => undefined);
      }
    };
    window.addEventListener('pagehide', onPageHide);
    await this.mutate(async () => {
      try {
        // §2.4 step 3: every folder exists before the first file opens; a creation
        // failure stops here, so no file is sent into a half-built tree.
        if (plan.folders.length > 0) {
          targets = await this.createFolders(plan, folderNames, folder);
        }
        if (items.length === 0) return;
        const outcome = await batch.run();
        // §2.7: a file that failed on a definitive verdict was rolled back and
        // is reported HERE, at batch end, beside the ones that landed — never
        // silently. One failure reads as it always has; several name the count
        // and the first reason. The user's own cancel is not an error.
        if (outcome.failures.length === 1) throw outcome.failures[0].error;
        if (outcome.failures.length > 1) {
          throw new Error(
            m.filelist_upload_some_failed({
              failed: outcome.failures.length,
              count: items.length,
              reason: friendlyDriveError(outcome.failures[0].error),
            }),
          );
        }
      } finally {
        this.folderPrep = null;
        this.uploadProgress = null;
        this.uploadBatch = null;
        document.removeEventListener('visibilitychange', onVisibilityChange);
        void wakeLock.release();
        window.removeEventListener('pagehide', onPageHide);
      }
    });
    // Gus (v01 review, answer 2): skipped OS clutter is silent while running and
    // counted HERE, in one place, whatever the batch's outcome.
    this.showUploadSkipped(plan.skipped);
  }

  /** §2.4 step 3, wired: `createPlannedFolders` over `Drive.createFolder` (nested
   *  folders reuse the root's metadata key there, exactly as "New folder" does),
   *  with the panel's `Creating folders n of m`. A failure becomes the message that
   *  names the folder that failed and the top-level folders it left (Gus, note b). */
  private async createFolders(
    plan: FolderUploadPlan,
    names: string[],
    dropTarget: FolderTarget,
  ): Promise<FolderTarget[]> {
    try {
      return await createPlannedFolders(
        plan.folders,
        names,
        dropTarget,
        (name, parent) => this.drive.createFolder(name, parent),
        (done, total) => {
          this.folderPrep = { kind: 'creating', done, total };
        },
      );
    } catch (e) {
      if (!(e instanceof FolderCreateError)) throw e;
      const reason = friendlyDriveError(e.reason);
      throw new Error(
        e.createdRoots.length > 0
          ? m.err_folder_create_failed_partial({
              name: e.folderPath,
              reason,
              created: e.createdRoots.join(', '),
            })
          : m.err_folder_create_failed({ name: e.folderPath, reason }),
      );
    }
  }

  /** The batch-end count of skipped OS clutter; nothing when there was none. */
  private showUploadSkipped(skipped: number): void {
    if (skipped <= 0) return;
    this.uploadNotice =
      skipped === 1
        ? m.filelist_upload_skipped_one()
        : m.filelist_upload_skipped_many({ count: skipped });
  }

  /** Resume a paused upload (the bug047 bad-window pause): one file by index,
   *  or every paused file of the batch when none is named. */
  resumeUpload(fileIndex?: number): void {
    if (fileIndex === undefined) this.uploadBatch?.resumeAll();
    else this.uploadBatch?.resumeFile(fileIndex);
  }

  /** Cancel the whole in-flight/paused batch — aborts every open file
   *  server-side, frees their reservations, keeps the files already landed
   *  (a user action, never surfaced as an error). */
  cancelUpload(): void {
    this.uploadBatch?.cancel();
  }

  /** F2 §2.7: cancel ONE file of the batch (a paused one, typically); the
   *  others keep going. */
  cancelUploadFile(fileIndex: number): void {
    this.uploadBatch?.cancelFile(fileIndex);
  }

  async download(file: NamedFile): Promise<boolean> {
    this.busy = true;
    this.error = '';
    // bug193 / v03 §3c: collision avoidance is OURS, per session — measured at
    // S176 that Safari's download manager silently REPLACES an existing
    // same-named file where Chrome/Firefox suffix. Self-suffixing before the
    // handoff gives one rule on every browser. ⚠ Residual, stated: a collision
    // with a file that predates this session is unknowable from a page and stays
    // platform behaviour.
    const downloadName = this.uniqueDownloadName(file.name);
    // The zeroed banner seed is the transfer's real starting state (bug187):
    // there is no save dialog on this path — the SW sink or the refusal both
    // settle within the same click's turn.
    this.downloadProgress = {
      fileName: file.name,
      completedChunks: 0,
      totalChunks: 0,
      receivedBytes: 0,
      totalBytes: 0,
    };
    // bug195 (k): held so the success claim can await the BROWSER'S handoff, not
    // merely our own readiness. Null on the fallback path, whose anchor click
    // hands over a complete Blob synchronously.
    let handoff: Promise<void> | null = null;
    try {
      await this.drive.downloadFileVia(
        file.view.file_id,
        async (meta) => {
          // ⭐ THE PATH (v03): the SW-streamed download — the browser's own
          // download manager writes the disk; peak page memory is the window.
          // No picker, no grant; partials and progress are the browser's own.
          if (meta.swDownloadEnabled) {
            const sink = await openSwStreamedSink(downloadName, meta.plaintextBytes);
            if (sink) {
              handoff = sink.consumed ?? null;
              return sink;
            }
          }
          // ⚠ FALLBACK — CAPPED AND REFUSING, the only other path (v03 §6-6:
          // the old uncapped buffer is DELETED, not parked; the kill-switch
          // retracts to THIS). Pre-flight refusal: we hold the plaintext length
          // and the served cap, so a file that provably cannot buffer refuses
          // BEFORE any byte moves (bug070's principle). Per-file, never
          // per-batch (Gus amendment 2).
          if (meta.plaintextBytes > meta.bufferCapBytes) {
            throw new FallbackTooLargeError();
          }
          return this.bufferingAnchorSink(downloadName);
        },
        (p) => {
          this.downloadProgress = { fileName: file.name, ...p };
        },
      );
      // ⚠⚠ bug195 (k): THE CLAIM IS EARNED, NOT ASSUMED. v0.5.39 announced a save
      // the moment the worker said it was ready to serve — so a download the
      // browser never took was reported as saved, with no file on disk. The notice
      // now waits for the browser to have actually claimed the response.
      //
      // This is deliberately AFTER the transfer completes, so awaiting it costs
      // nothing in the normal case: handoff happens within milliseconds of the
      // trigger, long before the last chunk.
      if (handoff) await handoff;
      // bug044/bug187: both remaining paths land in the browser's own downloads
      // (the SW response and the anchor alike), so the location claim is TRUE —
      // the picker path that made it sometimes-false is gone. ⚠ What we can now
      // honestly claim is HANDOFF plus a finished write, NOT a landed file: a
      // cancel or a full disk after handoff still ends with nothing on disk. The
      // copy says only that much.
      this.showDownloaded({ fileName: file.name, count: 1, chose: false });
      return true;
    } catch (e) {
      // F-B (Gus): the user cancelling from the BROWSER's own download UI is a
      // decision, not an error — quiet stop, no toast (the download-side
      // sibling of UploadCancelledError's handling).
      if (e instanceof DownloadCancelledError) return false;
      // FallbackTooLargeError is our own pre-flight refusal; RangeError is the
      // same fact discovered late (V8's single-allocation limit at the concat —
      // kept as a second net for a mis-served cap; measured S173: 2 GiB refused
      // instantly, tab alive, nothing on disk). One copy serves both: honest,
      // names no other browser and no CLI (product principle, S176).
      this.error =
        e instanceof FallbackTooLargeError || e instanceof RangeError
          ? m.err_drive_download_too_large()
          : friendlyDriveError(e);
      return false;
    } finally {
      this.busy = false;
      this.downloadProgress = null;
    }
  }

  /** The capped fallback's sink: buffer verified chunks, and on commit hand ONE
   *  Blob to an anchor — the browser files it under `downloadName`. Reached only
   *  under the served cap (the factory refused anything larger pre-flight). */
  private bufferingAnchorSink(downloadName: string): DownloadSink {
    const parts: BlobPart[] = [];
    return {
      write: async (chunk) => {
        parts.push(chunk);
      },
      close: async () => {
        const blob = new Blob(parts, { type: 'application/octet-stream' });
        parts.length = 0;
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = downloadName;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      },
      abort: async () => {
        parts.length = 0;
      },
    };
  }

  /** bug193 / v03 §3c: session-scoped self-suffixing — `name (n).ext` for a
   *  repeat of a name this session already sent to the download manager. */
  private usedDownloadNames = new Map<string, number>();
  private uniqueDownloadName(name: string): string {
    const seen = this.usedDownloadNames.get(name) ?? 0;
    this.usedDownloadNames.set(name, seen + 1);
    if (seen === 0) return name;
    const dot = name.lastIndexOf('.');
    const stem = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';
    return `${stem} (${seen})${ext}`;
  }

  async downloadSelected(): Promise<void> {
    let saved = 0;
    let lastName = '';
    // bug186 DISSOLVED (v03 §3d): every file in the batch rides the same path —
    // the SW stream (or the capped fallback), sequentially, so memory is bounded
    // by the largest member, never the batch. A too-large member on the fallback
    // refuses PER-FILE (Gus amendment 2) — download() returns false for it, sets
    // the honest copy, and the rest of the batch proceeds. Chrome's native
    // multiple-downloads prompt (one Allow, browser-owned) is the accepted UX;
    // Proton's archive-into-one-stream alternative is named-and-deferred in v03.
    for (const file of this.files) {
      if (this.selectedFiles.has(file.view.file_id) && (await this.download(file))) {
        saved += 1;
        lastName = file.name;
      }
    }
    // One honest summary for a multi-select (each download() above set a
    // single-file notice; the batch replaces it with the count). Location claim
    // is uniformly true now — both paths land in the browser's downloads.
    if (saved > 1) this.showDownloaded({ fileName: lastName, count: saved, chose: false });
  }

  /** bug044: the transient post-download confirmation, auto-clearing so it never
   *  lingers as stale UI.
   *
   *  bug187 §2: `chose` records whether the user picked the destination. It selects
   *  between naming the location (true only on the fallback path, which really does
   *  file into the browser's download directory) and naming only the file. */
  private showDownloaded(notice: { fileName: string; count: number; chose: boolean }): void {
    this.downloaded = notice;
    clearTimeout(this.downloadedTimer);
    this.downloadedTimer = setTimeout(() => {
      // Clear only if this notice is still the visible one (a later download
      // restarts the clock with its own timer).
      if (this.downloaded === notice) this.downloaded = null;
    }, 6000);
  }

  async rename(newName: string): Promise<void> {
    const dialog = this.dialog;
    if (!dialog || dialog.kind !== 'rename') return;
    const trimmed = newName.trim();
    if (!trimmed) return;
    await this.mutate(async () => {
      if (dialog.file) {
        await this.drive.renameFile(dialog.file.view, this.currentRootId ?? '', trimmed);
      } else if (dialog.folder) {
        await this.drive.renameFolder(dialog.folder.view, trimmed);
      }
    });
  }

  async moveTo(targetFolderId: string): Promise<void> {
    await this.mutate(async () => {
      for (const id of this.selectedFiles) await this.drive.moveFile(id, targetFolderId);
      for (const id of this.selectedFolders) await this.drive.moveFolder(id, targetFolderId);
    });
  }

  async deleteSelected(): Promise<void> {
    await this.mutate(async () => {
      const fileIds = [...this.selectedFiles];
      const folderIds = [...this.selectedFolders];
      if (fileIds.length) await this.drive.deleteFiles(fileIds);
      if (folderIds.length) await this.drive.deleteFolders(folderIds);
    });
  }

  /** bug055 — select every row in the current listing. The header tri-state
   *  checkbox and ⌘A/Ctrl+A both land here; deselect-all is clearSelection(). */
  selectAll(): void {
    this.selectedFiles = new Set(this.files.map((f) => f.view.file_id));
    this.selectedFolders = new Set(this.childFolders.map((f) => f.view.folder_id));
  }

  /** True when the current listing is non-empty and every row is selected.
   *  (Selections only ever hold current-listing ids — toggles add from the
   *  listing and reloads prune stale ids — so a count comparison suffices.) */
  get allSelected(): boolean {
    const total = this.files.length + this.childFolders.length;
    return total > 0 && this.selectionCount === total;
  }

  toggleFile(id: string): void {
    const next = new Set(this.selectedFiles);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    this.selectedFiles = next;
  }

  toggleFolder(id: string): void {
    const next = new Set(this.selectedFolders);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    this.selectedFolders = next;
  }

  clearSelection(): void {
    this.selectedFiles = new Set();
    this.selectedFolders = new Set();
  }

  openNewFolder(topLevel: boolean): void {
    this.dialog = { kind: 'newFolder', topLevel };
    this.error = '';
  }

  openNewShareFolder(): void {
    this.dialog = { kind: 'newShareFolder' };
    this.error = '';
  }

  openRename(): void {
    const single = this.singleSelection;
    if (!single) return;
    this.dialog = { kind: 'rename', file: single.file, folder: single.folder };
    this.error = '';
  }

  /** bug101: open Rename for a SPECIFIC item (the ⋯ / right-click menu) — which may
   *  be a left-nav tree folder that isn't in the current panel selection, so it
   *  can't route through `singleSelection`. */
  openRenameItem(item: { file?: NamedFile; folder?: NamedFolder }): void {
    this.dialog = { kind: 'rename', file: item.file, folder: item.folder };
    this.error = '';
  }

  /** bug101: open/close the single top-level ⋯ actions menu (see `contextMenu`). */
  openContextMenu(
    x: number,
    y: number,
    item: { file?: NamedFile; folder?: NamedFolder },
    owned: boolean,
  ): void {
    this.contextMenu = {
      x,
      y,
      file: item.file,
      folder: item.folder,
      owned,
      // bug223: rename stays owner-gated; delete asks the per-item question.
      deletable: this.canDeleteItem(item),
    };
  }
  closeContextMenu(): void {
    this.contextMenu = null;
  }

  openMove(): void {
    if (this.selectionCount === 0) return;
    this.dialog = { kind: 'move' };
    this.error = '';
  }

  openConfirmDelete(): void {
    if (this.selectionCount === 0) return;
    this.dialog = { kind: 'confirmDelete' };
    this.error = '';
  }

  /** bug101: open the delete confirmation for a SPECIFIC item (⋯ / right-click). */
  openConfirmDeleteItem(item: { file?: NamedFile; folder?: NamedFolder }): void {
    this.dialog = { kind: 'confirmDelete', file: item.file, folder: item.folder };
    this.error = '';
  }

  /** bug101: execute the confirm-delete dialog. A targeted delete (the dialog carries
   *  a file/folder, from the ⋯ menu) removes just that item; otherwise the toolbar
   *  multi-select path removes the current selection. */
  async confirmDelete(): Promise<void> {
    const dialog = this.dialog;
    if (dialog?.kind === 'confirmDelete' && (dialog.file || dialog.folder)) {
      const file = dialog.file;
      const folder = dialog.folder;
      await this.mutate(async () => {
        if (file) await this.drive.deleteFiles([file.view.file_id]);
        if (folder) await this.drive.deleteFolders([folder.view.folder_id]);
      });
    } else {
      await this.deleteSelected();
    }
  }

  closeDialog(): void {
    this.dialog = null;
    this.error = '';
  }

  private async loadTopLevel(): Promise<void> {
    const { folders } = await this.drive.listFolders();
    this.topLevel = await this.decryptFolders(folders);
  }

  private async loadSharedWithMe(): Promise<void> {
    try {
      const { folders } = await this.drive.sharedFolders();
      this.sharedWithMe = await Promise.all(
        folders.map(async (shared) => {
          const view = sharedToFolderView(shared);
          return {
            view,
            name: await this.safeFolderName(view),
            ownerAccountId: shared.owner_account_id,
            permission: shared.permission,
          };
        }),
      );
    } catch (e) {
      this.error = friendlyDriveError(e);
    }
  }

  private async loadPrsns(): Promise<void> {
    try {
      const { prsns } = await this.drive.listPrsns();
      this.prsns = prsns;
    } catch (e) {
      this.error = friendlyDriveError(e);
    }
  }

  private async loadRecipients(rootFolderId: string): Promise<void> {
    try {
      const { recipients } = await this.drive.listRecipients(rootFolderId);
      this.recipients = recipients;
    } catch (e) {
      this.error = friendlyDriveError(e);
    }
  }

  private async loadInvitations(rootFolderId: string): Promise<void> {
    try {
      const { invitations } = await this.drive.listInvitations(rootFolderId);
      this.pendingInvitations = invitations;
    } catch (e) {
      this.error = friendlyDriveError(e);
    }
  }

  private async loadContents(): Promise<void> {
    const folder = this.current;
    if (!folder) return;
    this.busy = true;
    this.error = '';
    try {
      const [foldersRes, filesRes] = await Promise.all([
        this.drive.listFolders(folder.folderId),
        this.drive.listFiles(folder.folderId),
      ]);
      this.childFolders = await this.decryptFolders(foldersRes.folders);
      this.files = await Promise.all(
        filesRes.files.map(async (view) => ({
          view,
          name: await this.safeFileName(view, folder.rootFolderId),
        })),
      );
      this.pruneSelection();
    } catch (e) {
      this.error = friendlyDriveError(e);
    } finally {
      this.busy = false;
    }
  }

  /** Drop selected ids that no longer exist after a (re)load — so a background
   *  change-stream refresh keeps a still-valid selection rather than clobbering
   *  it, and navigation (different ids) naturally clears it. */
  private pruneSelection(): void {
    const fileIds = new Set(this.files.map((f) => f.view.file_id));
    const folderIds = new Set(this.childFolders.map((f) => f.view.folder_id));
    this.selectedFiles = new Set([...this.selectedFiles].filter((id) => fileIds.has(id)));
    this.selectedFolders = new Set([...this.selectedFolders].filter((id) => folderIds.has(id)));
  }

  private async refresh(): Promise<void> {
    try {
      this.quota = await this.drive.quota();
      await this.loadTopLevel();
      await this.loadSharedWithMe();
      await this.refreshTree();
      if (this.current) await this.loadContents();
    } catch (e) {
      this.error = friendlyDriveError(e);
    }
  }

  private async mutate(op: () => Promise<void>): Promise<void> {
    this.busy = true;
    this.error = '';
    try {
      await op();
      this.dialog = null;
      await this.refresh();
    } catch (e) {
      this.error = friendlyDriveError(e);
    } finally {
      this.busy = false;
    }
  }

  private async decryptFolders(folders: FolderView[]): Promise<NamedFolder[]> {
    return Promise.all(
      folders.map(async (view) => ({ view, name: await this.safeFolderName(view) })),
    );
  }

  private async safeFolderName(view: FolderView): Promise<string> {
    try {
      return await this.drive.folderName(view);
    } catch {
      return '(unreadable)';
    }
  }

  private async safeFileName(view: FileView, rootFolderId: string): Promise<string> {
    try {
      return await this.drive.fileName(view, rootFolderId);
    } catch {
      return '(unreadable)';
    }
  }
}
