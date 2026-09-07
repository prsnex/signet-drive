// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Extension → file-type icon (S003 UI carve; authored by Gus, integrated by Hlin).
// The mapping is a plain exported const so the owner can extend it without
// touching the icon components. Unknown or absent extensions fall back to
// IconFileGeneric — every file always has a face.
import type { Component } from 'svelte';

import IconFileArchive from './IconFileArchive.svelte';
import IconFileCode from './IconFileCode.svelte';
import IconFileDoc from './IconFileDoc.svelte';
import IconFileGeneric from './IconFileGeneric.svelte';
import IconFileImage from './IconFileImage.svelte';
import IconFileMedia from './IconFileMedia.svelte';
import IconFilePdf from './IconFilePdf.svelte';
import IconFileSheet from './IconFileSheet.svelte';

export type FileIcon = Component<{ size?: number }>;

export const ICON_BY_EXTENSION: Record<string, FileIcon> = {
  // documents
  doc: IconFileDoc,
  docx: IconFileDoc,
  md: IconFileDoc,
  odt: IconFileDoc,
  pages: IconFileDoc,
  rtf: IconFileDoc,
  txt: IconFileDoc,
  // images
  bmp: IconFileImage,
  gif: IconFileImage,
  heic: IconFileImage,
  jpeg: IconFileImage,
  jpg: IconFileImage,
  png: IconFileImage,
  svg: IconFileImage,
  tiff: IconFileImage,
  webp: IconFileImage,
  // sheets
  csv: IconFileSheet,
  numbers: IconFileSheet,
  ods: IconFileSheet,
  tsv: IconFileSheet,
  xls: IconFileSheet,
  xlsx: IconFileSheet,
  // code & config
  c: IconFileCode,
  cpp: IconFileCode,
  css: IconFileCode,
  go: IconFileCode,
  h: IconFileCode,
  html: IconFileCode,
  js: IconFileCode,
  json: IconFileCode,
  py: IconFileCode,
  rs: IconFileCode,
  sh: IconFileCode,
  swift: IconFileCode,
  toml: IconFileCode,
  ts: IconFileCode,
  yaml: IconFileCode,
  yml: IconFileCode,
  // archives
  '7z': IconFileArchive,
  bz2: IconFileArchive,
  dmg: IconFileArchive,
  gz: IconFileArchive,
  rar: IconFileArchive,
  tar: IconFileArchive,
  zip: IconFileArchive,
  // audio & video
  aac: IconFileMedia,
  flac: IconFileMedia,
  m4a: IconFileMedia,
  mkv: IconFileMedia,
  mov: IconFileMedia,
  mp3: IconFileMedia,
  mp4: IconFileMedia,
  wav: IconFileMedia,
  webm: IconFileMedia,
  // pdf
  pdf: IconFilePdf,
};

/** File-type icon for a file name; IconFileGeneric when the extension is
 *  unknown, absent, or the name is dot-leading with no real extension. */
export function iconForFile(name: string): FileIcon {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return IconFileGeneric;
  return ICON_BY_EXTENSION[name.slice(dot + 1).toLowerCase()] ?? IconFileGeneric;
}
