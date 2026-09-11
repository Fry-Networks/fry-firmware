// Maps the chip description esptool-js reports to the board key used by the Board menu and
// the firmware manifest. esptool-js `ESPLoader.main()` returns `getChipDescription()`, which is
// a marketing/package string such as "ESP32-S3 (QFN56) (revision v0.2)", "ESP32-D0WDQ6 (revision
// v1.0)", "ESP32-C3 AZ (QFN32) (revision v0.4)", "ESP8685 (QFN28) ..." or "ESP8266EX" — never the
// bare board key. Comparing a stripped version of that string against the menu value made every
// board look mismatched and told users to re-select a label that does not exist in the menu.

export const BOARD_LABELS = {
  esp8266: "ESP8266",
  esp32: "ESP32",
  esp32s3: "ESP32-S3",
  esp32c3: "ESP32-C3",
};

// Package suffixes of the classic ESP32 (Xtensa dual-core) family, per the esptool chip tables:
// D0WD, D0WDQ6, D0WD-V3, D0WDQ6-V3, D0WDR2-V3, D2WD, U4WDH, PICO-D4, PICO-V3, PICO-V3-02,
// S0WD, S0WDQ6. Note that "S0WD" is an ESP32 package, not the S-series.
const ESP32_CLASSIC_VARIANT = /^(D0WD|D2WD|U4WDH|PICO|S0WD)/;

/**
 * @param {string|undefined|null} description  esptool-js chip description
 * @returns {"esp8266"|"esp32"|"esp32s3"|"esp32c3"|null}  board key, or null when the chip is
 *          not one this flasher ships firmware for (ESP32-S2/C2/C5/C6/C61/H2/P4, unknown text)
 */
export function boardForChipDescription(description) {
  const raw = String(description ?? "").trim().toUpperCase();
  if (!raw) return null;
  const token = raw.replace(/^UNKNOWN\s+/, "").split(/[\s(]/)[0];
  if (token.startsWith("ESP8266") || token.startsWith("ESP8285")) return "esp8266";
  if (token === "ESP8685" || token === "ESP8686") return "esp32c3";
  if (!token.startsWith("ESP32")) return null;
  if (token === "ESP32") return "esp32";
  const variant = token.split("-")[1] || "";
  if (variant === "S3") return "esp32s3";
  if (variant === "C3") return "esp32c3";
  if (ESP32_CLASSIC_VARIANT.test(variant)) return "esp32";
  return null;
}

export function unsupportedMessage(detectedRaw) {
  const supported = Object.values(BOARD_LABELS).join(", ");
  return (
    `Detected chip "${detectedRaw}" is not one of the boards this flasher supports ` +
    `(${supported}). Flash cancelled — nothing was written.`
  );
}

export function mismatchMessage(detectedRaw, detectedBoard, selectedBoard) {
  const detectedLabel = BOARD_LABELS[detectedBoard];
  const selectedLabel = BOARD_LABELS[selectedBoard] || selectedBoard;
  return (
    `Detected chip is ${detectedRaw}, which uses the "${detectedLabel}" image, but the Board ` +
    `menu is set to "${selectedLabel}". Flashing the wrong image can brick the board. ` +
    `Switch the Board menu to "${detectedLabel}" and flash the matching image?`
  );
}
