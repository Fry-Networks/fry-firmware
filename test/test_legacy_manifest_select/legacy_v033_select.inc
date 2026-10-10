  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    Serial.println("ota: manifest parse failed");
    return false;
  }

  const char* latest = doc["firmware_version"] | "";
  JsonObject build = doc["builds"][FRY_BUILD_ENV];
  const char* url = build["url"] | "";
  const char* sha = build["sha256"] | "";
  // Only ever move FORWARD. This was strcmp(...) != 0, which updated in either
  // direction, so a device running a newer build than the published manifest
  // downgraded itself (observed on the bench: cur=0.1.1 latest=0.1.0 action=update).
  // Deliberate rollback is slot-based, not manifest-driven. A text compare would also
  // mis-order 0.9.0 against 0.10.0, so components are compared numerically.
  bool willUpdate = (strlen(latest) > 0) && fry::isNewerVersion(latest, FRY_FIRMWARE_VERSION) &&
                    strlen(url) > 0 && strlen(sha) > 0;
