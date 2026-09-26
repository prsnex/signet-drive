// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Folder upload — the pre-registered tests of the design note v02 §2.8, driven
// with fake entries (the shape the browser's File and Directory Entries API
// hands a drop handler).

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  captureDrop,
  createPlannedFolders,
  DropReadError,
  FolderCreateError,
  isSystemClutter,
  nameFolders,
  perFolderDedupe,
  planFromRelativePaths,
  resolveEntries,
  type DirectoryEntryLike,
  type DropItemLike,
  type EntryLike,
  type FileEntryLike,
} from './folder-drop';
import { dedupeName } from './names';

/** Every File the fakes hand out, so a test can prove a planned file came from a
 *  FILE entry and nowhere else. */
const handedOut = new Set<File>();

function file(name: string, opts: { fail?: boolean; content?: string } = {}): FileEntryLike {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file(success, error) {
      if (opts.fail) {
        error?.(new DOMException('NotReadableError'));
        return;
      }
      const f = new File([opts.content ?? 'x'], name);
      handedOut.add(f);
      success(f);
    },
  };
}

/** A directory whose reader returns `batch` entries per call, then an empty batch
 *  (Chrome returns at most 100 per `readEntries`). `calls` counts the reads. */
function dir(
  name: string,
  children: EntryLike[],
  opts: { batch?: number; fail?: boolean } = {},
): DirectoryEntryLike & { calls: number } {
  const d = {
    isFile: false,
    isDirectory: true,
    name,
    calls: 0,
    createReader() {
      let i = 0;
      return {
        readEntries(success: (e: EntryLike[]) => void, error?: (err: unknown) => void) {
          d.calls += 1;
          if (opts.fail) {
            error?.(new DOMException('NotReadableError'));
            return;
          }
          const size = opts.batch ?? 100;
          const out = children.slice(i, i + size);
          i += out.length;
          success(out);
        },
      };
    },
  };
  return d;
}

describe('resolveEntries — the tree walk', () => {
  it('plans a tree three deep, parents before children, each file in its own folder', async () => {
    const plan = await resolveEntries([
      dir('RAW', [file('a.jpg'), dir('sub', [file('b.jpg'), dir('deeper', [file('c.jpg')])])]),
    ]);
    expect(plan.folders.map((f) => [f.name, f.parent, f.path])).toEqual([
      ['RAW', null, 'RAW'],
      ['sub', 0, 'RAW/sub'],
      ['deeper', 1, 'RAW/sub/deeper'],
    ]);
    expect(plan.files.map((f) => [f.file.name, f.folder])).toEqual([
      ['a.jpg', 0],
      ['b.jpg', 1],
      ['c.jpg', 2],
    ]);
    // Parents always precede children, so creating in array order is safe.
    plan.folders.forEach((f, i) => {
      if (f.parent !== null) expect(f.parent).toBeLessThan(i);
    });
  });

  it('keeps an empty folder, and puts loose dropped files in the drop target', async () => {
    const plan = await resolveEntries([file('loose.jpg'), dir('RAW', [dir('empty', [])])]);
    expect(plan.folders.map((f) => f.name)).toEqual(['RAW', 'empty']);
    expect(plan.files.map((f) => [f.file.name, f.folder])).toEqual([['loose.jpg', null]]);
  });

  it('reads a directory of 250 entries across every readEntries batch', async () => {
    const children = Array.from({ length: 250 }, (_, i) => file(`p${i}.jpg`));
    const big = dir('RAW', children, { batch: 100 });
    const plan = await resolveEntries([big]);
    expect(plan.files).toHaveLength(250);
    // 100 + 100 + 50, then the empty batch that ends the listing.
    expect(big.calls).toBe(4);
  });

  it('refuses the whole drop on an unreadable file, naming its path', async () => {
    const walk = resolveEntries([dir('RAW', [file('ok.jpg'), file('bad.jpg', { fail: true })])]);
    await expect(walk).rejects.toBeInstanceOf(DropReadError);
    await expect(walk).rejects.toMatchObject({ path: 'RAW/bad.jpg' });
  });

  it('refuses the whole drop on an unreadable directory listing', async () => {
    await expect(
      resolveEntries([dir('RAW', [dir('locked', [], { fail: true })])]),
    ).rejects.toMatchObject({ path: 'RAW/locked' });
  });

  it('skips OS clutter and counts it, but keeps a user dotfile', async () => {
    const plan = await resolveEntries([
      dir('RAW', [
        file('.DS_Store'),
        file('._a.jpg'),
        file('Thumbs.db'),
        file('DESKTOP.INI'),
        file('.notes'),
        file('a.jpg'),
      ]),
    ]);
    expect(plan.skipped).toBe(4);
    expect(plan.files.map((f) => f.file.name)).toEqual(['.notes', 'a.jpg']);
  });

  it('reports the running count of files found', async () => {
    const seen: number[] = [];
    await resolveEntries([dir('RAW', [file('a'), file('b'), file('.DS_Store'), file('c')])], (n) =>
      seen.push(n),
    );
    expect(seen).toEqual([1, 2, 3]);
  });

  it('keeps a genuine 0-byte file — the guard is structural, never a size test', async () => {
    const plan = await resolveEntries([file('empty.txt', { content: '' })]);
    expect(plan.files).toHaveLength(1);
    expect(plan.files[0].file.size).toBe(0);
  });
});

describe('⛔ the dead-file guard (Chris, production, 2026-09-25)', () => {
  it('a dropped directory yields a FOLDER, and every planned file came from a file entry', async () => {
    // The shape Safari handed the old handler: an item whose `getAsFile()` is a
    // 0-byte File named after the folder, and whose ENTRY is the directory.
    const deadFile = new File([], 'RAW');
    const item: DropItemLike = {
      kind: 'file',
      webkitGetAsEntry: () => dir('RAW', [file('_DSF3902.JPG')]),
      getAsFile: () => deadFile,
    };
    const capture = captureDrop([item]);
    expect(capture).not.toBeNull();
    const plan = await resolveEntries(capture!.entries);
    expect(plan.folders.map((f) => f.name)).toEqual(['RAW']);
    expect(plan.files.map((f) => f.file.name)).toEqual(['_DSF3902.JPG']);
    for (const f of plan.files) {
      expect(f.file).not.toBe(deadFile);
      expect(handedOut.has(f.file)).toBe(true);
    }
  });

  it('the drop handler reads entries, never dataTransfer.files (the mutant this arm kills)', () => {
    const source = readFileSync(
      fileURLToPath(new URL('./components/FileList.svelte', import.meta.url)),
      'utf8',
    );
    const handler = source.slice(
      source.indexOf('function onDrop('),
      source.indexOf('// ── bug196 item 1'),
    );
    expect(handler.length).toBeGreaterThan(0); // the slice found the handler
    expect(handler).toContain('captureDrop(items)');
    // Strip comments: the handler's own comment names the forbidden read.
    const code = handler
      .split('\n')
      .filter((line) => !line.trim().startsWith('//'))
      .join('\n');
    expect(code).not.toMatch(/dataTransfer\??\.files/);
    expect(code).not.toMatch(/uploadFiles\(/);
  });
});

describe('captureDrop', () => {
  it('captures file and folder entries, ignores non-file items, names entry-less ones', () => {
    const items: DropItemLike[] = [
      { kind: 'file', webkitGetAsEntry: () => file('a.jpg'), getAsFile: () => null },
      { kind: 'string', webkitGetAsEntry: () => null, getAsFile: () => null },
      { kind: 'file', webkitGetAsEntry: () => null, getAsFile: () => new File(['x'], 'odd') },
    ];
    const capture = captureDrop(items)!;
    expect(capture.entries.map((e) => e.name)).toEqual(['a.jpg']);
    expect(capture.unreadable).toEqual(['odd']);
  });

  it('returns null when the browser has no entries API (the caller refuses; no fallback)', () => {
    expect(captureDrop([{ kind: 'file', getAsFile: () => new File(['x'], 'a') }])).toBeNull();
  });
});

describe("isSystemClutter — Dropbox's list, not every dotfile", () => {
  it.each([
    ['.DS_Store', true],
    ['._IMG_1.JPG', true],
    ['Thumbs.db', true],
    ['thumbs.DB', true],
    ['desktop.ini', true],
    ['.env', false],
    ['.DS_Store.txt', false],
    ['photo.jpg', false],
  ])('%s → %s', (name, expected) => {
    expect(isSystemClutter(name)).toBe(expected);
  });
});

describe('planFromRelativePaths — the Upload folder input', () => {
  const picked = (path: string) => {
    const f = new File(['x'], path.split('/').pop()!);
    Object.defineProperty(f, 'webkitRelativePath', { value: path });
    return f;
  };

  it('rebuilds the tree from webkitRelativePath, skipping clutter', () => {
    const plan = planFromRelativePaths([
      picked('RAW/a.jpg'),
      picked('RAW/sub/b.jpg'),
      picked('RAW/.DS_Store'),
      picked('RAW/sub/c.jpg'),
    ]);
    expect(plan.folders.map((f) => [f.name, f.parent])).toEqual([
      ['RAW', null],
      ['sub', 0],
    ]);
    expect(plan.files.map((f) => [f.file.name, f.folder])).toEqual([
      ['a.jpg', 0],
      ['b.jpg', 1],
      ['c.jpg', 1],
    ]);
    expect(plan.skipped).toBe(1);
  });
});

describe('nameFolders — suffix, never merge (§2.3)', () => {
  const folders = [
    { name: 'RAW', parent: null, path: 'RAW' },
    { name: 'sub', parent: 0, path: 'RAW/sub' },
    { name: 'RAW', parent: null, path: 'RAW' },
  ];

  it('a taken top-level name becomes "RAW (1)"; two dropped RAWs accumulate; nested names stay', () => {
    expect(nameFolders(folders, ['RAW'], dedupeName)).toEqual(['RAW (1)', 'sub', 'RAW (2)']);
    expect(nameFolders(folders, [], dedupeName)).toEqual(['RAW', 'sub', 'RAW (1)']);
  });

  it('dedupes against FOLDER names only: a file named RAW does not rename the folder', () => {
    // The live case (Gus): Chris's folder holds the dead 0-byte FILE `RAW`. The
    // store passes childFolders' names here, never the files'.
    expect(nameFolders(folders.slice(0, 1), ['Other'], dedupeName)).toEqual(['RAW']);
  });
});

describe('perFolderDedupe — bug048 per target folder', () => {
  it('dedupes each file within its own folder only', () => {
    const dedupe = perFolderDedupe(['a.jpg'], dedupeName);
    expect(dedupe('a.jpg', { folder: null })).toBe('a (1).jpg'); // taken in the target
    expect(dedupe('a.jpg', { folder: 0 })).toBe('a.jpg'); // a new folder starts empty
    expect(dedupe('a.jpg', { folder: 0 })).toBe('a (1).jpg'); // the batch's own choice
    expect(dedupe('a.jpg', { folder: 1 })).toBe('a.jpg');
  });
});

describe('createPlannedFolders — order and failure (§2.4, §2.5)', () => {
  const drop = { folderId: 'target', rootFolderId: 'root' };
  const folders = [
    { name: 'RAW', parent: null, path: 'RAW' },
    { name: 'sub', parent: 0, path: 'RAW/sub' },
    { name: 'deeper', parent: 1, path: 'RAW/sub/deeper' },
  ];

  it('creates each folder under its parent, parent first, all under the drop root', async () => {
    const calls: Array<[string, string, string]> = [];
    let n = 0;
    const progress: Array<[number, number]> = [];
    const targets = await createPlannedFolders(
      folders,
      ['RAW (1)', 'sub', 'deeper'],
      drop,
      async (name, parent) => {
        calls.push([name, parent.folderId, parent.rootFolderId]);
        return { folder_id: `f${n++}` };
      },
      (done, total) => progress.push([done, total]),
    );
    expect(calls).toEqual([
      ['RAW (1)', 'target', 'root'],
      ['sub', 'f0', 'root'],
      ['deeper', 'f1', 'root'],
    ]);
    expect(targets).toEqual([
      { folderId: 'f0', rootFolderId: 'root' },
      { folderId: 'f1', rootFolderId: 'root' },
      { folderId: 'f2', rootFolderId: 'root' },
    ]);
    expect(progress).toEqual([
      [0, 3],
      [1, 3],
      [2, 3],
      [3, 3],
    ]);
  });

  it('stops at the first failure, names it and the top-level folders it left', async () => {
    let created = 0;
    const attempt = createPlannedFolders(
      [...folders, { name: 'Other', parent: null, path: 'Other' }],
      ['RAW', 'sub', 'deeper', 'Other'],
      drop,
      async (name) => {
        if (name === 'deeper') throw new Error('refused');
        return { folder_id: `f${created++}` };
      },
    );
    await expect(attempt).rejects.toBeInstanceOf(FolderCreateError);
    await expect(attempt).rejects.toMatchObject({
      folderPath: 'RAW/sub/deeper',
      createdRoots: ['RAW'],
    });
    expect(created).toBe(2); // nothing after the failure — and `Other` never made
  });

  it('a failure at the first folder leaves nothing behind to name', async () => {
    await expect(
      createPlannedFolders(folders, ['RAW', 'sub', 'deeper'], drop, async () => {
        throw new Error('refused');
      }),
    ).rejects.toMatchObject({ folderPath: 'RAW', createdRoots: [] });
  });
});

describe('refuse before acting — the order the store keeps (Gus, code review notes b, c)', () => {
  it('an entry that is neither a file nor a folder refuses the drop, naming it', async () => {
    const odd: EntryLike = { isFile: false, isDirectory: false, name: 'socket' };
    await expect(resolveEntries([dir('RAW', [file('a.jpg'), odd])])).rejects.toMatchObject({
      path: 'RAW/socket',
    });
  });

  it('ownership is checked before the walk (drop) and before the pre-flight (every plan)', () => {
    const store = readFileSync(
      fileURLToPath(new URL('./browser.svelte.ts', import.meta.url)),
      'utf8',
    );
    const drop = store.slice(
      store.indexOf('async uploadDrop('),
      store.indexOf('async uploadPickedFolder('),
    );
    expect(drop.length).toBeGreaterThan(0);
    const ownsInDrop = drop.indexOf('!this.ownsCurrentRoot');
    expect(ownsInDrop).toBeGreaterThan(-1);
    expect(ownsInDrop).toBeLessThan(drop.indexOf('resolveEntries('));

    const plan = store.slice(
      store.indexOf('private async uploadPlan('),
      store.indexOf('private async createFolders('),
    );
    expect(plan.length).toBeGreaterThan(0);
    const ownsInPlan = plan.indexOf('!this.ownsCurrentRoot');
    expect(ownsInPlan).toBeGreaterThan(-1);
    expect(ownsInPlan).toBeLessThan(plan.indexOf('this.preflightCapacity('));
    // And every folder is created before the batch runs.
    expect(plan.indexOf('this.createFolders(')).toBeLessThan(plan.indexOf('batch.run()'));
  });
});

describe('the Upload menu (Chris, 2026-09-25: one button, "Files…" / "Folder…")', () => {
  const component = readFileSync(
    fileURLToPath(new URL('./components/FileList.svelte', import.meta.url)),
    'utf8',
  );

  it('there is one upload control in the toolbar, and it opens the menu', () => {
    expect(component).toContain('onclick={openUploadMenu}');
    expect(component).not.toContain('filelist_upload_folder');
    expect(component).toContain('m.filelist_upload_menu_files()');
    expect(component).toContain('m.filelist_upload_menu_folder()');
  });

  it('"Folder…" gates on ownership, as New folder does (creating folders is owner-only)', () => {
    const menu = component.slice(
      component.indexOf('<ActionMenu'),
      component.indexOf('/>', component.indexOf('<ActionMenu')),
    );
    const folderItem = menu.slice(menu.indexOf('m.filelist_upload_menu_folder()'));
    expect(folderItem).toContain('disabled: !browser.ownsCurrentRoot');
    expect(folderItem).toContain('folderInput?.click()');
  });
});

describe('the menu opens with focus on its first item (Gus, review of d8e29bd1)', () => {
  it('ActionMenu focuses the first ENABLED item once visible, once per opening', () => {
    const menu = readFileSync(
      fileURLToPath(new URL('./components/ActionMenu.svelte', import.meta.url)),
      'utf8',
    );
    expect(menu).toContain("querySelector<HTMLButtonElement>('button.item:not(:disabled)')");
    // Gated on the measured position: a hidden element cannot take focus.
    expect(menu).toMatch(/if \(!pos \|\| !menuEl \|\| focused\) return;/);
  });
});
