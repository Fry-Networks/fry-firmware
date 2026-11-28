#pragma once
// KV backend of the BK7231N: FlashDB (library-flashdb, the key-value database LibreTiny already carries) on the "kvs" flash
// partition (0x1D3000+0x8000 on the Tuya QFN32 layout). FlashDB's own sector log gives the atomic-update guarantee: a set is a
// new record and the old one is only marked deleted afterwards, so a reset leaves one complete value.
#include <flashdb.h>

#include <string.h>

namespace fry_boards {

struct FlashDbBackend {
  static fdb_kvdb& db() {
    static fdb_kvdb d;
    return d;
  }

  static bool mount() {
    static int state = 0;
    if (state == 0) {
      memset(&db(), 0, sizeof(fdb_kvdb));
      state = (fdb_kvdb_init(&db(), "fry", "kvs", nullptr, nullptr) == FDB_NO_ERR) ? 1 : 2;
    }
    return state == 1;
  }

  static int size(const char* flat) {
    struct fdb_kv kv;
    if (!fdb_kv_get_obj(&db(), flat, &kv)) return -1;
    return static_cast<int>(kv.value_len);
  }

  static int read(const char* flat, uint8_t* buf, size_t cap) {
    const int n = size(flat);
    if (n < 0) return -1;
    struct fdb_blob blob;
    // A blob read is bounded by the buffer given: a longer stored value is truncated, never overrun.
    const size_t got = fdb_kv_get_blob(&db(), flat, fdb_blob_make(&blob, buf, cap));
    return static_cast<int>(got);
  }

  static bool write(const char* flat, const uint8_t* buf, size_t len) {
    struct fdb_blob blob;
    static const uint8_t kEmpty = 0;
    return fdb_kv_set_blob(&db(), flat, fdb_blob_make(&blob, len ? buf : &kEmpty, len)) == FDB_NO_ERR;
  }

  static bool erase(const char* flat) {
    if (size(flat) < 0) return true;
    return fdb_kv_del(&db(), flat) == FDB_NO_ERR;
  }

  static void each(void (*cb)(const char*, void*), void* ctx) {
    struct fdb_kv_iterator itr;
    fdb_kv_iterator_init(&itr);
    while (fdb_kv_iterate(&db(), &itr)) {
      if (itr.curr_kv.status == FDB_KV_WRITE) cb(itr.curr_kv.name, ctx);
    }
  }
};

}  // namespace fry_boards
