// Removes the Authenticode signature of each PE file in place, as the LTK Patcher License
// requires of a redistributed patcher binary. A file without a signature is unchanged.
//
// Usage: node scripts/strip-signature.mjs <file>...

import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// Index of the certificate table in the optional header's data directories.
const SECURITY_DIRECTORY = 4;

/** Returns the offset of the optional header's `CheckSum` and certificate table entry. */
function headerOffsets(pe) {
  if (pe.readUInt16LE(0) !== 0x5a4d) {
    throw new Error("Not a PE file: no MZ header");
  }
  const ntHeaders = pe.readUInt32LE(0x3c);
  if (pe.readUInt32LE(ntHeaders) !== 0x00004550) {
    throw new Error("Not a PE file: no PE signature");
  }

  const optionalHeader = ntHeaders + 24;
  const magic = pe.readUInt16LE(optionalHeader);
  const directories =
    magic === 0x20b ? optionalHeader + 112 : magic === 0x10b ? optionalHeader + 96 : null;
  if (directories === null) {
    throw new Error(`Unknown optional header magic: 0x${magic.toString(16)}`);
  }

  return {
    checksum: optionalHeader + 64,
    security: directories + SECURITY_DIRECTORY * 8,
  };
}

/** Returns the PE checksum of `pe`, whose `CheckSum` field is at `checksumOffset`. */
export function peChecksum(pe, checksumOffset) {
  let sum = 0;
  for (let i = 0; i < pe.length; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) {
      continue;
    }
    const word = i + 1 < pe.length ? pe.readUInt16LE(i) : pe[i];
    sum += word;
    sum = (sum & 0xffff) + (sum >>> 16);
  }

  return ((sum & 0xffff) + (sum >>> 16) + pe.length) >>> 0;
}

/**
 * Returns `pe` without its certificate table, or `null` if it has none.
 *
 * Fails if the table is not at the end of the file, where a signing tool appends it.
 */
export function stripSignature(pe) {
  const offsets = headerOffsets(pe);
  const tableOffset = pe.readUInt32LE(offsets.security);
  const tableSize = pe.readUInt32LE(offsets.security + 4);
  if (tableOffset === 0 || tableSize === 0) {
    return null;
  }
  if (tableOffset + tableSize !== pe.length) {
    throw new Error("The certificate table is not at the end of the file");
  }

  const stripped = Buffer.from(pe.subarray(0, tableOffset));
  stripped.writeUInt32LE(0, offsets.security);
  stripped.writeUInt32LE(0, offsets.security + 4);
  stripped.writeUInt32LE(peChecksum(stripped, offsets.checksum), offsets.checksum);

  return stripped;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    console.error("Usage: node scripts/strip-signature.mjs <file>...");
    process.exit(1);
  }

  for (const file of files) {
    const stripped = stripSignature(readFileSync(file));
    if (stripped === null) {
      console.log(`${file}: not signed`);
      continue;
    }
    writeFileSync(file, stripped);
    console.log(`${file}: signature removed`);
  }
}
