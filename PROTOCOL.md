# Fry Device Provisioning Protocol v1

Shared contract between `Fry-Networks/fry-firmware` and `Fry-Networks/fry-app-android`.
This file is byte-identical in both repositories. Neither side may change it unilaterally.

## 1. BLE GATT (ESP32 / ESP32-S3 / ESP32-C3)

Service `46525900-0001-4000-8000-4652594e4554` (0x465259 = "FRY", 0x4652594e4554 = "FRYNET")

| Characteristic | UUID | Props | Payload |
|---|---|---|---|
| WiFi SSID     | `46525901-0001-4000-8000-4652594e4554` | write | UTF-8, 1..32 bytes |
| WiFi password | `46525902-0001-4000-8000-4652594e4554` | write | UTF-8, 0..64 bytes |
| Wallet        | `46525903-0001-4000-8000-4652594e4554` | write | UTF-8, exactly 58 bytes (Algorand) |
| Device name   | `46525904-0001-4000-8000-4652594e4554` | read | UTF-8, see grammar below |
| Miner key     | `46525905-0001-4000-8000-4652594e4554` | read | `IOT-<32 uppercase hex>` |
| Status        | `46525906-0001-4000-8000-4652594e4554` | read + notify | 1 byte state, plus a 2nd byte error code when state==4 |
| Firmware ver  | `46525907-0001-4000-8000-4652594e4554` | read | UTF-8 semver |
| Chip type     | `46525908-0001-4000-8000-4652594e4554` | read | `ESP32` or `ESP32-S3` or `ESP32-C3` |

**Advertising.** The 128-bit service UUID goes in the ADVERTISEMENT; the device name goes in the
SCAN RESPONSE. Name plus 128-bit UUID plus flags exceeds the 31-byte advertisement budget, so
advertising both truncates or refuses to start. Android performs an active scan, so a `ScanFilter`
by service UUID still matches and `scanRecord.deviceName` still resolves.

**Commit semantics.** Writing the WALLET characteristic commits provisioning. The firmware requires
SSID and WALLET to be present; the password may be empty (open network). The state machine leaves
`Provisioning` only on a wallet write.

**MTU.** The central requests MTU 185. Writes are write-with-response. If the MTU request fails the
peripheral must still accept the 58-byte wallet via a long/prepared write.

## 2. Status and error codes (shared by BLE characteristic 06 and ESP8266 `GET /status`)

| State | Meaning |
|---|---|
| 0 | Idle, no credentials stored |
| 1 | Provisioning, receiving credentials |
| 2 | Connecting, joining WiFi |
| 3 | Connected, WiFi up AND registered with hardwareapi |
| 4 | Error, see error code |

| Error | Meaning |
|---|---|
| 0 | none |
| 1 | bad SSID (empty or over 32 bytes) |
| 2 | WiFi authentication failed |
| 3 | associated but no IP (DHCP timeout) |
| 4 | hardwareapi registration failed |
| 5 | bad wallet (not a valid 58-char Algorand address) |

## 3. SoftAP and HTTP (ESP8266)

AP SSID `FRY-SETUP-<MAC6>`, open, IP `192.168.4.1`, DNS catch-all on port 53, HTTP on port 80.

- `GET /` returns the HTML provisioning form (PROGMEM, under 4 KB)
- `GET /info` returns `{"deviceName":"FRY-ESP8266-XXXXXX","minerKey":"IOT-...","fw":"0.1.0","chip":"ESP8266"}`
- `GET /api/scan` returns `{"nets":[{"ssid":"...","rssi":-50,"enc":true}]}` from a cached STA pre-scan
- `POST /provision` takes form-encoded `ssid`, `pass`, `wallet` and returns `200 {"ok":true}` or `400 {"ok":false,"err":"<reason>"}`
- `GET /status` returns `{"status":0..4,"err":0..5,"minerKey":"IOT-...","ip":"..."}`

The AP is torn down 10 seconds after status reaches 3.

## 4. Identity

- **Device name grammar:** `^FRY-(ESP8266|ESP32|ESP32-S3|ESP32-C3)-[0-9A-F]{6}$`
  where MAC6 is the last 3 bytes of the station MAC in uppercase hex.
- **Miner key:** `IOT-` followed by 32 uppercase hex characters, computed as
  `SHA256(mac6 || salt)` truncated to 16 bytes, where `salt` is 16 random bytes generated once on
  first boot and persisted. The key is generated once and never regenerated. It is case-sensitive
  and must be transmitted byte-exact.
- **Miner code** (hardwareapi `minerCode`, PoC `miner_type`): `IOTVPN`. Hyphen-free, because both
  the miner-key parser and the rewards classifier split on the first hyphen.

## 5. hardwareapi contract used by the firmware

Base `https://hardwareapi.frynetworks.com`, header `Authorization: Bearer <token>` using the
per-device token if one has been issued, otherwise the build-time bootstrap token. The header is
omitted entirely when both are empty.

- `POST /installations/{miner_key}/installations/{install_id}` with body
  `{"miner_key","install_id","minerCode":"IOTVPN","software_version_installed","poc_version_installed":"1.0.0","hostname","os","is_installed":true,"device_name"}`.
  Note that `minerCode` is camelCase while every sibling field is snake_case. Send no extra keys.
  The response is `{"status","device_token"}`. Repeat hourly and once after every OTA.
- `POST` or `PATCH /installations/{miner_key}/leases/{install_id}` with body `{"lease_seconds":900}`.
- `PUT /PoC/{miner_key}/hardware` with body `{"document":{...}}`, one slot per call, where
  `slot_number = (UTC minutes since midnight / 10) % 144`. Success is any 2xx; there is no response body.
- `GET /versions/IOTVPN?platform=<os>` for reward and version configuration.
- **Never** call `GET /credentials/{key}/verified` with the bootstrap token. It is rejected by
  design and naive clients loop forever on 401 recovery.

`os` is the build environment name: `esp8266`, `esp32`, `esp32s3` or `esp32c3`.

## 6. OTA manifest

```json
{"firmware_version":"0.1.1","builds":{"esp8266":{"url":"...","sha256":"..."},"esp32":{"url":"...","sha256":"..."},"esp32s3":{"url":"...","sha256":"..."},"esp32c3":{"url":"...","sha256":"..."}}}
```

The firmware looks up `builds[FRY_BUILD_ENV]`, where `FRY_BUILD_ENV` is the compile-time base
environment name, so a `*_lab` build still resolves its base environment. Downloads follow
redirects with a limit of 5, because a GitHub release asset is two hops and changes host. An image
is committed only after the streamed SHA-256 matches the manifest.

## 7. Lab-only serial commands (compiled only with `-DFRY_SERIAL_PROVISION=1`)

One JSON object per line on the serial port. Replies are one line prefixed with `[serial] `, and
passwords and keys are redacted to a length.

- `{"cmd":"set_wifi","ssid":"...","password":"..."}`
- `{"cmd":"set_wallet","addr":"..."}`
- `{"cmd":"set_wg","endpoint":"host:port","peer_pub":"...","priv":"...","psk":"...","addr":"10.13.13.2/24"}`
  where `psk` is REQUIRED because linuxserver/wireguard writes a PresharedKey into every peer
  config, and `addr` uses a /24 prefix and never /32, because with /32 the NAT return path never
  re-enters the tunnel.
- `{"cmd":"set_ota_url","url":"..."}` where an empty string restores the compiled default
- `{"cmd":"ota_now"}`, `{"cmd":"poc_now"}`, `{"cmd":"get_info"}`
- `{"cmd":"factory_reset"}` wipes `fry_wifi`, `fry/wallet`, `fry/installId`, `fry/deviceToken`,
  `fry_vpn` and `fry_ota`. It **preserves `fry/salt` and `fry/minerKey`** so that a re-provisioned
  board keeps one server identity.

## 8. Host tool CLI (fry-firmware `tools/`)

- `py -3 tools/provision.py --port COMx set-wifi [--no-reset] [--wait 75]` reads `FRY_SSID`,
  `FRY_PSK` and `FRY_WALLET` from the environment and sends `set_wifi` **and then** `set_wallet`.
  It never echoes a secret; it prints a character count instead.
- `py -3 tools/provision.py --port COMx cmd --json "{...}"`
- `py -3 tools/cap.py --port COMx --seconds N --out FILE [--reset]`
- `bash tools/flash.sh <env> <port>` retries up to 15 times, 4 seconds apart.

Serial ports are opened with `dtr=False` and `rts=False` set on the UNOPENED handle. Otherwise the
board resets on every connect.

## 9. Serial log lines that the QA gates grep for

```
FRY boot v<ver> chip=<CHIP> mac=<MAC> minerkey=IOT-<32HEX>
[boot] ready
BLE advertising name=<devname> svc=46525900
AP started FRY-SETUP-<MAC6> ip=192.168.4.1
wifi connected ip=<ip> rssi=<dbm>
api: registered install=<id> token=<present|none>
poc: slot=<n> put=<http> lease=<bool>
wg: handshake ok peer=<pub8> endpoint=<host:port>
socks5: listening :1080
ota: manifest check cur=<v> latest=<v> action=<none|update>
ota: applied <v> sha=ok
[health] up=<s> heap=<free> blk=<maxblock> rssi=<dbm> vpn=<up|down> relayed=<bytes> temp=<c|na>
```

Only ONE log family may use the literal `heap <N>k` shape, because the heap gate scrapes it.

## 10. Android test tags

Every interactive element carries a Compose `testTag` AND a `contentDescription`. The Compose root
sets `Modifier.semantics { testTagsAsResourceId = true }`, which surfaces the tag as a **bare**
resource id such as `resource-id="prov_ssid"`, with no package prefix.

`home_add_device_fab`, `scan_start`, `scan_result_<n>`, `scan_result_name_<n>`, `prov_ssid`,
`prov_pass`, `prov_wallet`, `prov_submit`, `prov_status`, `prov_minerkey`, `device_minerkey`,
`device_claim_link`, `settings_wallet`
