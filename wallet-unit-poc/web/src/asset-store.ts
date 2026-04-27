// Asset storage: OPFS primary, IndexedDB fallback. Cache keys embed the
// upstream SHA-256 (a key-hit implies prior verification). Writes stage at
// `<key>.partial` and rename atomically on commit — a crash mid-stream
// cannot leave a poisoned committed key.

export interface AssetWriter {
  stream: WritableStream<Uint8Array>;
  commit(): Promise<void>;
  abort(): Promise<void>;
}

export interface AssetStore {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
  writer(key: string): Promise<AssetWriter>;
  delete(key: string): Promise<void>;
  listKeys(prefix: string): Promise<string[]>;
  purgePartials(): Promise<void>;
  clearAll(): Promise<void>;
}

export const PARTIAL_SUFFIX = ".partial";

function hasOPFS(): boolean {
  // Atomic commit needs `FileSystemFileHandle.move()` — Chrome 110, Firefox 111,
  // Safari 17.4. Older browsers fall back to IDB.
  return (
    typeof navigator !== "undefined" &&
    "storage" in navigator &&
    navigator.storage != null &&
    typeof (navigator.storage as { getDirectory?: unknown }).getDirectory ===
      "function" &&
    typeof FileSystemFileHandle !== "undefined" &&
    typeof (FileSystemFileHandle.prototype as unknown as Moveable).move ===
      "function"
  );
}

type Moveable = { move(name: string): Promise<void> };
type AsyncIterableDir = {
  [Symbol.asyncIterator](): AsyncIterableIterator<[string, FileSystemHandle]>;
};

// ---------------------------------------------------------------------------
// OPFS backend
// ---------------------------------------------------------------------------

async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  return navigator.storage.getDirectory();
}

const opfsStore: AssetStore = {
  async get(key) {
    try {
      const root = await opfsRoot();
      const handle = await root.getFileHandle(key, { create: false });
      const file = await handle.getFile();
      const buf = await file.arrayBuffer();
      return new Uint8Array(buf);
    } catch (err) {
      if ((err as DOMException).name === "NotFoundError") return null;
      throw err;
    }
  },
  async put(key, bytes) {
    await opfsStore.delete(key);
    const root = await opfsRoot();
    const handle = await root.getFileHandle(key, { create: true });
    const writable = await handle.createWritable();
    // .slice().buffer gives createWritable() a plain ArrayBuffer — required
    // because SharedArrayBuffer-backed views are rejected.
    await writable.write(bytes.slice().buffer);
    await writable.close();
  },
  async writer(key) {
    const partialKey = `${key}${PARTIAL_SUFFIX}`;
    const root = await opfsRoot();
    await opfsRemove(root, partialKey);
    const handle = await root.getFileHandle(partialKey, { create: true });
    const writable = (await handle.createWritable()) as unknown as WritableStream<Uint8Array>;
    return {
      stream: writable,
      async commit() {
        // Overwrite-on-rename is browser-specific in OPFS; delete-then-move
        // keeps behavior portable.
        await opfsRemove(root, key);
        await (handle as unknown as Moveable).move(key);
      },
      async abort() {
        await opfsRemove(root, partialKey).catch(() => {});
      },
    };
  },
  async delete(key) {
    await opfsRemove(await opfsRoot(), key);
  },
  async listKeys(prefix) {
    const all = await opfsListAll(await opfsRoot());
    return all.filter((name) => name.startsWith(prefix));
  },
  async purgePartials() {
    const root = await opfsRoot();
    for (const name of await opfsListAll(root)) {
      if (name.endsWith(PARTIAL_SUFFIX)) await opfsRemove(root, name);
    }
  },
  async clearAll() {
    const root = await opfsRoot();
    for (const name of await opfsListAll(root)) {
      await opfsRemove(root, name, { recursive: true });
    }
  },
};

async function opfsRemove(
  root: FileSystemDirectoryHandle,
  name: string,
  opts?: { recursive?: boolean },
): Promise<void> {
  try {
    await root.removeEntry(name, opts);
  } catch (err) {
    if ((err as DOMException).name !== "NotFoundError") throw err;
  }
}

async function opfsListAll(root: FileSystemDirectoryHandle): Promise<string[]> {
  const iter = (root as unknown as AsyncIterableDir)[Symbol.asyncIterator]();
  const names: string[] = [];
  for (;;) {
    const next = await iter.next();
    if (next.done) break;
    names.push(next.value[0]);
  }
  return names;
}

// ---------------------------------------------------------------------------
// IndexedDB backend
// ---------------------------------------------------------------------------

const DB_NAME = "zkid-assets";
const DB_VERSION = 1;
const BYTES_STORE = "assets";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(BYTES_STORE))
        db.createObjectStore(BYTES_STORE, { keyPath: "key" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbRun<T>(
  stores: string | string[],
  mode: IDBTransactionMode,
  fn: (tx: IDBTransaction) => T | Promise<T>,
): Promise<T> {
  const db = await openDb();
  try {
    const tx = db.transaction(stores, mode);
    const result = await Promise.resolve(fn(tx));
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    return result;
  } finally {
    db.close();
  }
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

const idbStore: AssetStore = {
  get: (key) =>
    idbRun(BYTES_STORE, "readonly", async (tx) => {
      const row = await req<{ key: string; bytes: Uint8Array } | undefined>(
        tx.objectStore(BYTES_STORE).get(key),
      );
      return row ? row.bytes : null;
    }),
  async put(key, bytes) {
    await idbStore.delete(key);
    await idbRun(BYTES_STORE, "readwrite", (tx) =>
      req(tx.objectStore(BYTES_STORE).put({ key, bytes })),
    );
  },
  async writer(key) {
    let chunks: Uint8Array[] | null = [];
    const stream = new WritableStream<Uint8Array>({
      write(chunk) { chunks?.push(chunk.slice()); },
      abort() { chunks = null; },
    });
    return {
      stream,
      async commit() {
        if (chunks === null) throw new Error(`commit after abort for ${key}`);
        let total = 0;
        for (const c of chunks) total += c.byteLength;
        const merged = new Uint8Array(total);
        let off = 0;
        // Drop each chunk as we copy so peak heap stays ~1× the asset size.
        for (let i = 0; i < chunks.length; i++) {
          const c = chunks[i];
          merged.set(c, off);
          off += c.byteLength;
          chunks[i] = new Uint8Array(0);
        }
        chunks = null;
        await idbStore.put(key, merged);
      },
      async abort() {
        chunks = null;
      },
    };
  },
  delete: (key) =>
    idbRun(BYTES_STORE, "readwrite", (tx) => {
      tx.objectStore(BYTES_STORE).delete(key);
    }),
  listKeys: (prefix) =>
    idbRun(BYTES_STORE, "readonly", async (tx) => {
      // U+FFFF is the highest BMP code point — bounds every prefix-extending key.
      const range = IDBKeyRange.bound(prefix, prefix + "￿", false, false);
      const keys = await req<IDBValidKey[]>(
        tx.objectStore(BYTES_STORE).getAllKeys(range),
      );
      return keys.map(String);
    }),
  async purgePartials() {
    // IDB writers buffer in JS heap; no .partial state to purge.
  },
  async clearAll() {
    await new Promise<void>((resolve, reject) => {
      const r = indexedDB.deleteDatabase(DB_NAME);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
      r.onblocked = () =>
        reject(new Error(`deleteDatabase blocked for ${DB_NAME}`));
    });
  },
};

export const assetStore: AssetStore = hasOPFS() ? opfsStore : idbStore;

export async function clearAllAssets(): Promise<void> {
  await assetStore.clearAll();
}
