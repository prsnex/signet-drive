// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

// Folder upload — reading a drop, and planning the tree it describes.
// Design: `docs/design/Signet-Drive-Folder-Upload-Design-Note` (v02, Gus AGREE).
//
// ⛔ WHY THE DROP IS READ THROUGH ENTRIES, NEVER `dataTransfer.files`
// (Chris, production, 2026-09-25): a browser presents a dropped DIRECTORY in
// `dataTransfer.files` as a `File` carrying the directory's name and no readable
// content, and the drop handler uploaded it like any file — a folder `RAW` became
// a 0-byte FILE `RAW` with none of its photos. The guard is structural: nothing
// from a drop reaches `uploadFile` except a `File` obtained from a FILE entry.
// ⚠ It is not a size test and must never become one: a genuine 0-byte file is a
// legitimate thing to store (bug189 §3-3), and a size test would refuse it.
//
// Everything here is pure or takes minimal entry interfaces, so the walk is
// driven by unit tests with fake entries (`folder-drop.test.ts`).

/** The subset of `FileSystemEntry` the walk uses. */
export interface EntryLike {
  readonly isFile: boolean;
  readonly isDirectory: boolean;
  readonly name: string;
}

export interface FileEntryLike extends EntryLike {
  file(success: (file: File) => void, error?: (err: unknown) => void): void;
}

export interface DirectoryEntryLike extends EntryLike {
  createReader(): {
    readEntries(success: (entries: EntryLike[]) => void, error?: (err: unknown) => void): void;
  };
}

/** What a drop carried, captured SYNCHRONOUSLY inside the drop event (the item
 *  list is emptied once the handler returns). `unreadable` names every item the
 *  browser gave no entry for: refused, never uploaded (§2.2). */
export interface DropCapture {
  entries: EntryLike[];
  unreadable: string[];
}

/** A folder to create. `parent` indexes an EARLIER folder in the plan (parents
 *  always precede their children), or is `null` for the drop target itself. */
export interface PlannedFolder {
  name: string;
  parent: number | null;
  /** Slash-joined source path, for messages only. */
  path: string;
}

/** A file to upload into `folder` (an index into the plan's folders), or into the
 *  drop target itself when `null`. */
export interface PlannedFile {
  file: File;
  folder: number | null;
}

export interface FolderUploadPlan {
  folders: PlannedFolder[];
  files: PlannedFile[];
  /** OS clutter left out of the plan — never uploaded, counted for the batch-end
   *  report (Gus, v01 review answer 2). */
  skipped: number;
}

/** An entry the browser listed but would not let us read. The whole drop is
 *  refused before anything is created (§2.2: refuse before acting, bug070). */
export class DropReadError extends Error {
  constructor(readonly path: string) {
    super(`could not read ${path}`);
    this.name = 'DropReadError';
  }
}

/** OS clutter skipped on upload — Dropbox's ignore list, NOT "every dotfile":
 *  a user's own dotfile is their data (§2.2). */
export function isSystemClutter(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    name === '.DS_Store' ||
    name.startsWith('._') ||
    lower === 'thumbs.db' ||
    lower === 'desktop.ini'
  );
}

/** Minimal shape of a `DataTransferItem` for capture (tests pass fakes). */
export interface DropItemLike {
  readonly kind: string;
  webkitGetAsEntry?: () => EntryLike | null;
  getAsFile(): File | null;
}

/** Capture a drop's entries. Must run synchronously inside the `drop` handler.
 *  Returns `null` when the browser has no entries API at all — the caller refuses
 *  the drop rather than fall back to `dataTransfer.files`, because that fallback
 *  is exactly the path that turned a folder into a dead file. */
export function captureDrop(items: ArrayLike<DropItemLike>): DropCapture | null {
  const entries: EntryLike[] = [];
  const unreadable: string[] = [];
  for (const item of Array.from(items)) {
    if (item.kind !== 'file') continue;
    if (typeof item.webkitGetAsEntry !== 'function') return null;
    const entry = item.webkitGetAsEntry();
    if (entry && (entry.isFile || entry.isDirectory)) entries.push(entry);
    else unreadable.push(item.getAsFile()?.name || '(unnamed item)');
  }
  return { entries, unreadable };
}

function readFile(entry: FileEntryLike, path: string): Promise<File> {
  return new Promise((resolve, reject) => {
    entry.file(resolve, () => reject(new DropReadError(path)));
  });
}

/** Every child of a directory. `readEntries` returns BATCHES (Chrome: at most 100
 *  per call) and signals the end with an empty one, so it loops until then. */
async function readAll(dir: DirectoryEntryLike, path: string): Promise<EntryLike[]> {
  const reader = dir.createReader();
  const all: EntryLike[] = [];
  for (;;) {
    const batch = await new Promise<EntryLike[]>((resolve, reject) => {
      reader.readEntries(resolve, () => reject(new DropReadError(path)));
    });
    if (batch.length === 0) return all;
    all.push(...batch);
  }
}

/** Walk the captured entries into a plan. Every file entry is resolved to a
 *  `File` BEFORE the caller creates anything, so an unreadable entry refuses the
 *  whole drop with nothing created (throws `DropReadError`). `onCount` reports
 *  the files found so far — the panel's `Reading folder… N files` (Gus, answer 3).
 *  Folders come out parent-first (pre-order), so creating them in array order is
 *  always safe. */
export async function resolveEntries(
  entries: EntryLike[],
  onCount?: (files: number) => void,
): Promise<FolderUploadPlan> {
  const plan: FolderUploadPlan = { folders: [], files: [], skipped: 0 };

  const visit = async (entry: EntryLike, parent: number | null, parentPath: string) => {
    const path = parentPath ? `${parentPath}/${entry.name}` : entry.name;
    if (entry.isDirectory) {
      const index = plan.folders.length;
      plan.folders.push({ name: entry.name, parent, path });
      for (const child of await readAll(entry as DirectoryEntryLike, path)) {
        await visit(child, index, path);
      }
      return;
    }
    // Neither a file nor a directory: refused, never silently dropped (Gus, code
    // review note b) — whatever it is, the user did not get it.
    if (!entry.isFile) throw new DropReadError(path);
    if (isSystemClutter(entry.name)) {
      plan.skipped += 1;
      return;
    }
    const file = await readFile(entry as FileEntryLike, path);
    plan.files.push({ file, folder: parent });
    onCount?.(plan.files.length);
  };

  for (const entry of entries) await visit(entry, null, '');
  return plan;
}

/** The plan for a folder PICKED with `<input webkitdirectory>` (§2.6): each file
 *  carries `webkitRelativePath` ("RAW/sub/a.jpg"). Empty folders are invisible to
 *  that input — a browser limit; only a drop creates them. */
export function planFromRelativePaths(files: ArrayLike<File>): FolderUploadPlan {
  const plan: FolderUploadPlan = { folders: [], files: [], skipped: 0 };
  const byPath = new Map<string, number>();
  const folderFor = (segments: string[]): number | null => {
    let parent: number | null = null;
    let path = '';
    for (const name of segments) {
      path = path ? `${path}/${name}` : name;
      let index = byPath.get(path);
      if (index === undefined) {
        index = plan.folders.length;
        plan.folders.push({ name, parent, path });
        byPath.set(path, index);
      }
      parent = index;
    }
    return parent;
  };
  for (const file of Array.from(files)) {
    const rel = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
    const segments = rel.split('/').filter((s) => s.length > 0);
    const name = segments.pop() ?? file.name;
    const folder = folderFor(segments);
    if (isSystemClutter(name)) {
      plan.skipped += 1;
      continue;
    }
    plan.files.push({ file, folder });
  }
  return plan;
}

// ── Naming and creating the plan's folders (§2.3, §2.4) ──────────────────────
// Pure over callbacks, so the order, the naming and the failure report are unit
// tested; the store supplies `Drive.createFolder` and the listing's names.

/** Where a file lands: a folder and the root it sits under. */
export interface FolderTarget {
  folderId: string;
  rootFolderId: string;
}

/** §2.3: the names the plan's folders are CREATED under. A top-level folder
 *  whose name is taken among the target's SUBFOLDERS becomes "RAW (1)" by
 *  bug048's rule — never merged; the set accumulates, so two dropped `RAW`s
 *  become `RAW` and `RAW (1)`. Folder names dedupe against folders only (a folder
 *  may share a file's name — today's client namespace, Gus). Nested folders are
 *  new, so they keep their names. */
export function nameFolders(
  folders: readonly PlannedFolder[],
  takenFolderNames: Iterable<string>,
  dedupe: (desired: string, taken: ReadonlySet<string>) => string,
): string[] {
  const taken = new Set(takenFolderNames);
  return folders.map((f) => {
    if (f.parent !== null) return f.name;
    const chosen = dedupe(f.name, taken);
    taken.add(chosen);
    return chosen;
  });
}

/** bug048 per TARGET folder: the drop target starts from its listing's file names;
 *  each new folder starts empty. Each set accumulates the batch's own choices. */
export function perFolderDedupe(
  targetFileNames: Iterable<string>,
  dedupe: (desired: string, taken: ReadonlySet<string>) => string,
): (desired: string, item: { folder: number | null }) => string {
  const sets = new Map<number | null, Set<string>>([[null, new Set(targetFileNames)]]);
  return (desired, item) => {
    let taken = sets.get(item.folder);
    if (!taken) {
      taken = new Set();
      sets.set(item.folder, taken);
    }
    const chosen = dedupe(desired, taken);
    taken.add(chosen);
    return chosen;
  };
}

/** A folder of the plan could not be created. `createdRoots` names the top-level
 *  folders already made — what the user must delete (Gus, v01 note b); deleting a
 *  folder removes everything under it. */
export class FolderCreateError extends Error {
  constructor(
    readonly folderPath: string,
    readonly reason: unknown,
    readonly createdRoots: string[],
  ) {
    super(`could not create ${folderPath}`);
    this.name = 'FolderCreateError';
  }
}

/** Create the plan's folders in ORDER — parents always precede children — one
 *  round trip each, not parallelised until a tree is measured slow (Gus). Returns
 *  each folder's target, by plan index. Throws `FolderCreateError` at the first
 *  failure, having created nothing after it. */
export async function createPlannedFolders(
  folders: readonly PlannedFolder[],
  names: readonly string[],
  dropTarget: FolderTarget,
  create: (name: string, parent: FolderTarget) => Promise<{ folder_id: string }>,
  onProgress?: (done: number, total: number) => void,
): Promise<FolderTarget[]> {
  const targets: FolderTarget[] = [];
  const shown: string[] = [];
  const createdRoots: string[] = [];
  for (let i = 0; i < folders.length; i++) {
    onProgress?.(i, folders.length);
    const planned = folders[i];
    const parent = planned.parent === null ? dropTarget : targets[planned.parent];
    shown[i] = planned.parent === null ? names[i] : `${shown[planned.parent]}/${names[i]}`;
    let view: { folder_id: string };
    try {
      view = await create(names[i], parent);
    } catch (e) {
      throw new FolderCreateError(shown[i], e, [...createdRoots]);
    }
    targets[i] = { folderId: view.folder_id, rootFolderId: parent.rootFolderId };
    if (planned.parent === null) createdRoots.push(names[i]);
  }
  onProgress?.(folders.length, folders.length);
  return targets;
}
