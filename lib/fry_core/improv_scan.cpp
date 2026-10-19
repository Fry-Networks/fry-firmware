#include "improv_scan.h"

#include <cstdio>
#include <cstring>

namespace fry {
namespace improv {

bool ScanList::add(const char* ssid, int rssi, bool secure) {
  if (!ssid || !ssid[0]) return false;
  ScanRow row;
  memset(&row, 0, sizeof(row));
  strncpy(row.ssid, ssid, sizeof(row.ssid) - 1);
  row.rssi = rssi;
  row.secure = secure;

  for (size_t i = 0; i < n_; i++) {
    if (strcmp(rows_[i].ssid, row.ssid) != 0) continue;
    if (rssi <= rows_[i].rssi) return false;
    n_--;  // drop the weaker sighting, re-insert below in order
    for (size_t j = i; j < n_; j++) rows_[j] = rows_[j + 1];
    break;
  }

  size_t pos = 0;
  while (pos < n_ && rows_[pos].rssi >= rssi) pos++;
  if (pos >= kMax) return false;  // full, and weaker than every kept row
  size_t last = n_ < kMax ? n_ : kMax - 1;  // a full list loses its weakest row
  for (size_t j = last; j > pos; j--) rows_[j] = rows_[j - 1];
  rows_[pos] = row;
  if (n_ < kMax) n_++;
  return true;
}

void formatRssi(int rssi, char* out, size_t outLen) { snprintf(out, outLen, "%d", rssi); }

const char* authCell(bool secure) { return secure ? "YES" : "NO"; }

}  // namespace improv
}  // namespace fry
