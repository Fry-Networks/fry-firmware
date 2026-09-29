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
| Miner key     | `46525905-0001-4000-8000-4652594e4554` | read | `FEM-<32 uppercase hex>` |
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
- `GET /info` returns `{"deviceName":"FRY-ESP8266-XXXXXX","minerKey":"FEM-...","fw":"0.1.0","chip":"ESP8266"}`
- `GET /api/scan` returns `{"nets":[{"ssid":"...","rssi":-50,"enc":true}]}` from a cached STA pre-scan
- `POST /provision` takes form-encoded `ssid`, `pass`, `wallet` and returns `200 {"ok":true}` or `400 {"ok":false,"err":"<reason>"}`
- `GET /status` returns `{"status":0..4,"err":0..5,"minerKey":"FEM-...","ip":"..."}`

The AP is torn down 10 seconds after status reaches 3.

## 4. Identity

- **Device name grammar:** `^FRY-(ESP8266|ESP32|ESP32-S3|ESP32-C3)-[0-9A-F]{6}$`
  where MAC6 is the last 3 bytes of the station MAC in uppercase hex.
- **Miner key:** `FEM-` followed by 32 uppercase hex characters, computed as
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
- `POST /measurements/{miner_key}` with the device telemetry body below, every
  `TELEMETRY_INTERVAL_MS` (600000, matching the PoC cadence). Success is `202 {"ok":true}`.
  **Auth is the SHARED bearer token, not the per-device token.** This endpoint is the one gated by
  `verify_bearer_token_general`, which compares the presented token against the server's
  `API_BEARER_TOKEN` and answers `401` on any mismatch — so a per-device token can never satisfy
  it (env unset is `500`, missing is `401`, wrong is `401`). The firmware still waits for a
  device token before its first post, but only as a readiness signal: that token appearing is what
  proves registration completed and the server has a row to attribute the sample to. The path
  parameter is the miner KEY, not the install id — the server resolves it against
  `minerKey`/`canonicalId`, which keeps a sample attributable when the install id is unknown.
- **Never** call `GET /credentials/{key}/verified` with the bootstrap token. It is rejected by
  design and naive clients loop forever on 401 recovery.

`os` is the build environment name: `esp8266`, `esp32`, `esp32s3` or `esp32c3`.

### 5.1 Telemetry body (`POST /measurements/{miner_key}`)

```json
{"miner_code":"IOTVPN","install_id":"<32 hex>","measurement_type":"telemetry",
 "timestamp":"2026-09-18T06:00:00Z","value":{
   "uptime_s":1234,"heap_free":157000,"heap_max_block":110580,
   "stack_high_water":4096,"rssi":-37,"chip":"ESP32","firmware":"0.3.1"}}
```

Twelve fields, five at the top level and seven under `value`. `uptime_s`, `heap_free`,
`heap_max_block` and `stack_high_water` are unsigned integers; `rssi` is signed; the rest are
strings. `timestamp` is RFC3339 UTC and is **never** sent before NTP has synced — an epoch-1970
value would silently mis-date the sample, so the firmware skips the cycle instead.

`stack_high_water` is reported in bytes on the ESP32 family (`uxTaskGetStackHighWaterMark`) and is
`0` on ESP8266, which has no per-task stack accounting — `0` means "not measurable here", not
"exhausted". `heap_max_block` is the largest contiguous block and is the value the OTA gate
actually decides on, which is why it is carried separately from `heap_free`.

The builder refuses rather than escapes: if `miner_code`, `install_id`, `timestamp`, `chip` or
`firmware` contains `"`, `\` or any byte below `0x20`, no body is produced and the cycle is
skipped. It also refuses to truncate — a partial JSON object is worse than no sample.

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
FRY boot v<ver> chip=<CHIP> mac=<MAC> minerkey=FEM-<32HEX>
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

## 11. Protocol v1.1 (firmware 0.4.0 and later; append-only)

Everything in sections 1 to 10 still holds; v1.1 only adds. A v1 client keeps working against a
v1.1 device, with one deliberate exception: a USER_SUPPLIED device that holds no miner key refuses
to commit provisioning until it is given one (11.3, 11.6). Capability detection: BLE characteristic
`0A` present, or `"proto":2` in ESP8266 `GET /info`, or an answer to Improv `0xF1`. None of those
means protocol 1.

### 11.1 Miner key ownership

- **Key model** (compile flag `FRY_KEY_MODEL`): `1` USER_SUPPLIED (default from 0.4.0) - the owner
  writes the FEM- key they already hold (dashboard or FEM PC); a board without one never mints its
  own and waits. `0` DEVICE_KEEPS - the v1 behaviour of section 4: minted once on first boot, every
  write refused.
- **Owner key format:** `^FEM-[A-Za-z0-9]{32}$`, exactly 36 ASCII bytes, byte-exact and
  case-sensitive. The dashboard mints `FEM-<32 uppercase base36>`, FEM PC `FEM-<32 uppercase hex>`,
  migrated legacy boards may hold `FEM-<32 lowercase hex>`; all three are valid. Clients trim
  whitespace and zero-width characters before sending and never change case; the firmware never
  trims or case-folds. An `IOT-` key is never accepted as input (legacy guidance: "IOT- keys are
  now FEM- keys: use FEM- with the same 32 characters").
- **Fielded boards keep their key.** An update never re-keys a board; a stored `IOT-<hex>` key is
  still rewritten to `FEM-<same hex>` on boot.
- **Who may write a key:**

| Stored key | USB (Improv `0xF0`) | BLE `09` | ESP8266 WPA2 setup AP | ESP8266 open AP |
|---|---|---|---|---|
| none | accept | accept | accept | `key_needs_secure_ap` |
| present, not yet confirmed | accept | accept | accept | `key_needs_secure_ap` |
| confirmed by a 2xx registration | accept (replace) | `key_locked` (8) | `key_locked` (8) | `key_needs_secure_ap` |
| any, DEVICE_KEEPS build | `key_locked` (8) | `key_locked` (8) | `key_locked` (8) | `key_needs_secure_ap` |

  Re-writing exactly the stored key is a no-op that always succeeds (except over the open AP). A
  malformed key is `bad_key` (7) everywhere.
- **A new key is a new installation:** `fry/installId`, `fry/deviceToken` and all of `fry_vpn` are
  cleared, `fry/keySrc` becomes `user` and `fry/keyOk` false. `fry/keyOk` turns true on the first 2xx
  registration and is what "confirmed" means above. `factory_reset` keeps the key, `keyOk`,
  `keySrc` and `fry/apCode`.
- **Masking:** wherever a key is shown without authentication it is its first 6 characters followed
  by U+2026 (UTF-8 `E2 80 A6`), e.g. `FEM-AB…`.
- **A USER_SUPPLIED board without a key** logs `minerkey=NONE` in its boot banner, stays
  provisionable even with Wi-Fi credentials stored, and skips registration, lease, PoC and
  WireGuard provisioning (nothing is sent to an empty key path).

### 11.2 Status and error codes v1.1

| Error | Meaning |
|---|---|
| 6 | KeyRequired - commit attempted without a miner key (USER_SUPPLIED) |
| 7 | BadKey - a key write that is not `^FEM-[A-Za-z0-9]{32}$` |
| 8 | KeyLocked - key write refused by policy (11.1) |
| 9 | registration answered 401 (key unknown to the server, or a legacy key) |
| 10 | registration answered 403 |
| 11 | registration answered 409 (key active on another install) |
| 12 | registration answered another 4xx |
| 13 | hardwareapi unreachable (transport error, 5xx or 429); the device keeps retrying |

- **Legacy byte.** v1 clients read one error byte and know 0-5; every code from 6 up is reported
  to them as 4 ("hardwareapi registration failed"), with the v1.1 code alongside as the detail.
- **BLE characteristic 06** carries `[state]`, or in Error `[4][legacy][detail]` (3 bytes; a v1
  client reads byte 1 as before). **ESP8266 `GET /status`** keeps `"err"` as the legacy byte and adds
  `"detail"`.
- **error_reset.** An SSID write while in Error (BLE `01`, `/provision`, Improv `0x01`) starts a
  new attempt exactly as from Idle; before v1.1 Error lasted until a reboot.
- **Late registration success.** When Wi-Fi joined and only the API side failed (4, 6, 9-13), a
  later successful registration moves the state to 3 Connected, and a later failure replaces the
  detail. Wi-Fi errors (1-3) and 5 are not changed by registration outcomes.
- **Registration schedule.** A 2xx repeats hourly. A 4xx waits 3600 s. An outage gets one quick
  retry (2 s), then 60 s, doubling per consecutive failure, capped at 3600 s. The serial line names
  the HTTP status, the detail code and the server's own `detail`/`error` string (at most 120
  characters, every key-shaped token masked).

### 11.3 BLE additions (ESP32 / ESP32-S3 / ESP32-C3)

| Characteristic | UUID | Props | Payload |
|---|---|---|---|
| Miner key        | `46525905-0001-4000-8000-4652594e4554` | read, **encrypted read** | the stored key; `""` when none |
| Status           | `46525906-0001-4000-8000-4652594e4554` | read + notify | `[state]` or `[4][legacy][detail]` (11.2) |
| Miner key write  | `46525909-0001-4000-8000-4652594e4554` | write, **encrypted write** | exactly 36 ASCII bytes (11.1) |
| Device status    | `4652590a-0001-4000-8000-4652594e4554` | read + notify | JSON, at most 160 bytes, below |

- **Security.** `05` and `09` require an encrypted link: LE Secure Connections, Just Works, no
  bonding (`setSecurityAuth(bond=false, mitm=false, sc=true)`, IO capability NoInputNoOutput). No
  other characteristic needs it, so a client that never touches those two is never asked to pair.
- **Client order:** `09` key -> `01` SSID -> `02` password -> `03` wallet (commit).
- **`09` write.** Validated at once and, if accepted, held in RAM only. It is persisted at the `03`
  commit, before Wi-Fi and wallet, and only if the commit goes ahead. A refused write sets Error 7
  or 8. Accepted in Idle, Provisioning and Error (in Error it is staged and the state is left alone
  until the next `01`); ignored while Connecting or Connected.
- **Commit without a key.** A USER_SUPPLIED board with no stored key and no staged `09` refuses the
  `03` commit: nothing is persisted, status becomes `[4][4][6]`, and the serial log says
  `[prov] refused: no miner key - set it with the web setup page (USB) or app>=0.4`. A v1 app hits
  exactly this on a new board.
- **`0A` device status.** Refreshed on every read and notified on every status change:
  `{"v":1,"proto":2,"caps":["key_write","error_reset","errs_v2"],"s":<state>,"e":<legacy>,"d":<detail>,"k":<0|1 key present>,"kc":<0|1 key confirmed>,"reg":<last registration HTTP status this boot, 0 if none, negative for a transport error>,"hb":<seconds since the last 2xx heartbeat, -1 if none>,"fw":"x.y.z","ota":"valid|pending|rolled_back"}`.
  `e` and `d` are 0 outside Error. It never carries the key, masked or not.
- **Link lifetime.** The device never drops the link. The client keeps it until 5 s after it saw
  state 3 Connected, then disconnects. One exception: a commit that arrives while the board is
  already running (joined earlier this boot, e.g. Wi-Fi-only over Improv) is persisted and the
  board restarts to join with it, so the link drops after state 2; clients treat that as the
  hand-off and follow the device through the dashboard.

### 11.4 Improv Serial vendor commands (USB, all chips)

- **Phases.** Current state (`0x02`), device info (`0x03`) and `0xF1` are answered in EVERY phase, so
  a web flasher connecting to a working board recognises it (and offers Update, not erase). `0x01`
  Wi-Fi settings and `0x04` scan are still answered only while the provisioning transport is up;
  otherwise the reply is Improv error `0x04`. `0xF0` is accepted in any phase. `0x42` and every
  other unassigned command, the rest of `0xF0`-`0xFF` included, stay "unknown command".
- **`0xF0` FrySetMinerKey.** RPC data `[36][key]`. A length byte that disagrees with the data, or a
  value that cannot be buffered, is Improv error `0x01`; a well-framed key of the wrong length or
  shape is `bad_key`. Result strings: `["ok","FEM-AB…"]` | `["err","7","bad_key"]` |
  `["err","8","key_locked"]` | `["err","8","store_failed"]`. It runs the same handler as BLE `09` and
  the `/provision` key field. When it stores a DIFFERENT key on a board that is already Ready, the
  board restarts about 0.3 s after the result so it registers under the new key; a client reopens
  the port (native-USB boards re-enumerate) and asks `0xF1` again.
- **`0xF1` FryGetStatus.** RPC data empty. Result strings, all decimal or plain text:
  `["1", state, legacy, detail, keySet 0|1, keyMasked or "", fw, lastRegHttp, hbAgeS, ota, apCode or ""]`,
  `"1"` being this layout's version. `apCode` is the ESP8266 setup-AP code while the board has no key,
  `""` otherwise. `state` is the provisioning session state: 0 on a board that booted straight into
  its network.
- **Wi-Fi settings result.** The `0x01` success URL carries `#key=<key>` only when a key is stored,
  and no fragment otherwise. A USER_SUPPLIED board without a key still joins over `0x01` (so a
  flasher's Wi-Fi step succeeds), then reports Error 4/6 and registers nothing until `0xF0` gives
  it a key. Recommended order for a new board: `0xF0`, then `0x01`, then `0xF1`.
- **Golden vectors** (synthetic key `FEM-TESTKEY0000000000000000000000001`; shared with
  `test/test_improv_vendor` and `test/flash/improv_fry.test.mjs`):

```
kFryReqSetKey            494d50524f56010327f0252446454d2d544553544b45593030303030303030303030303030303030303030303030303120
kFryReqGetStatus         494d50524f56010302f100d4
kFrySetKeyOk             494d50524f5601040ff00d026f6b0946454d2d5445e280a679
kFrySetKeyBadKey         494d50524f56010410f00e036572720137076261645f6b65794a
kFrySetKeyLocked         494d50524f56010413f0110365727201380a6b65795f6c6f636b65649f
kFryStatusConnected      494d50524f5601042af128013101330130013001310946454d2d5445e280a605302e342e30033230320231320576616c696400d4
kFryStatusKeyRequired    494d50524f56010429f127013101340134013601300005302e342e300130022d310770656e64696e6708414243443233343579
```

  `kFryStatusConnected` is state 3, key set and confirmed, reg 202, hb 12 s, fw 0.4.0, valid;
  `kFryStatusKeyRequired` is Error 4/6, no key, reg 0, hb -1, pending, setup code `ABCD2345`.

### 11.5 OTA v1.1

- **Manifest additions** (section 6 shape unchanged): optional `"channel":"prod"|"test"`; a missing
  channel reads as `prod`. Firmware 0.4+ ignores a manifest whose channel is not its own.
- **Left-out chips.** `builds` may omit an environment on purpose. The prod manifest omits the envs
  listed in `tools/ota_channels.json` (from 0.4.0: `esp32s3`, `esp8266`). A board whose
  `FRY_BUILD_ENV` has no entry does not update, and never takes another chip's image; v0.3.1 and
  0.3.3 behave the same (`test/test_legacy_manifest_select`). Their images are still published for
  manual flashing.
- **Version order** is SemVer 2.0 precedence: `0.4.1-rc.1` < `0.4.1`, and never downward.
- **Test channel.** Prerelease tag `ota-test`,
  `https://github.com/Fry-Networks/fry-firmware/releases/download/ota-test/manifest.json`, read only
  by the `*_test` builds (`-DFRY_OTA_TEST_CHANNEL=1`), which also expect `"channel":"test"`.
- **Image verification (ESP32 family).** A freshly installed image stays PENDING_VERIFY until the
  first hardwareapi response of ANY HTTP status (registration, PoC or lease) - a 401 still proves
  the network path, so it is never grounds for rollback. A crash or reboot before that makes the
  bootloader boot the previous image; no response 20 minutes after boot (2 minutes on the test
  channel) rolls back too. The previous image records the version as bad and never installs it
  again; a later version is taken normally. No manifest check runs while the image is pending.
  ESP8266 has one slot: nothing can be rolled back there.
- **`ota` status value:** `pending` (unverified image running), `rolled_back` (the other slot holds
  an image the bootloader rolled back from), else `valid`.

### 11.6 ESP8266 SoftAP v1.1

- **AP security follows the key.** Board WITHOUT a key (USER_SUPPLIED): WPA2 AP `FRY-SETUP-<MAC6>`
  whose passphrase is an 8-character setup code from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, generated
  once and kept in `fry/apCode`. It is shown ONLY over USB: the serial line
  `AP started FRY-SETUP-<MAC6> ip=192.168.4.1 wpa2 setup-code=<code> (no miner key yet)` and Improv
  `0xF1`. Board WITH a key: the open AP of section 3.
- `GET /info` adds `"proto":2,"caps":["key_write","error_reset","errs_v2"],"keySet":<bool>`, and
  `"minerKey"` is masked (11.1).
- `GET /status` is `{"status","err"(legacy),"detail","minerKey"(masked),"keySet","reg","hb","fw","ota","ip"}`.
- `POST /provision` takes `ssid`, `pass`, `wallet` and an optional `key`:

| Response | When |
|---|---|
| `200 {"ok":true,"status":2}` | committed; the join starts |
| `400 {"ok":false,"err":"bad_ssid"\|"bad_wallet"\|"bad_key","status":n}` | invalid field |
| `403 {"ok":false,"err":"key_needs_secure_ap"\|"key_locked","status":n}` | key refused by policy (11.1) |
| `409 {"ok":false,"err":"busy","status":n}` | a join is already running or done |
| `422 {"ok":false,"err":"key_required","status":n}` | USER_SUPPLIED board without a key and no `key` field |

  Nothing is persisted on any non-200 answer. A request in Error starts a new attempt (11.2).
- **After a failed join** the AP comes back and a new `/provision` is accepted.

### 11.7 Serial log lines added in v1.1

```
FRY boot v<ver> chip=<CHIP> mac=<MAC> minerkey=NONE
[identity] no miner key - waiting for the owner's FEM- key (web setup page over USB, app >= 0.4, or the setup AP)
[identity] owner key stored via <usb|ble|softap> (FEM-AB…)
[boot] wifi credentials stored but no miner key - staying provisionable
[prov] refused: no miner key - set it with the web setup page (USB) or app>=0.4
[prov] miner key changed - restarting to register with the new key
api: register rejected http=<code> detail=<9-12> (<text>) server="<detail>" next=<s>s
api: registration failed install=<id> http=<code> detail=13 (<text>) next=<s>s
ota: image <v> is pending verification - valid on the first hardwareapi answer, rolled back after <s>s without one
ota: image <v> marked valid (first hardwareapi answer: <register|poc|lease> http=<code>)
ota: no hardwareapi answer <s>s after booting pending image <v> - rolling back
ota: <v> was rolled back - running <v>, <v> will not be installed again
ota: not updating - <wrong_channel|bad_version|no_build> (manifest channel=<c>, ours=<c>)
AP started FRY-SETUP-<MAC6> ip=192.168.4.1 wpa2 setup-code=<code> (no miner key yet)
AP restarted FRY-SETUP-<MAC6> after the failed join - /provision accepts a new attempt
```

### 11.8 Round-2 amendments (supersede the parts of 11.1-11.7 named here; nothing above is removed)

- **Characteristic 05 is plain READ again** and returns the full stored key (`""` without one), as in
  v1, so app 0.3.x - which reads 05 before writing, with a 5 s timeout - never meets a pairing
  prompt. This replaces "read, encrypted read" in the 11.3 table and in its Security bullet. `09`
  stays WRITE_ENC. Residual, as in 0.3.x: while a board is provisionable, anyone in BLE range can
  read its key.
- **Secure Connections only.** Legacy pairing (TK = 0, passively decryptable) is refused
  (`ble_hs_cfg.sm_sc_only = 1`); a central must pair with LE Secure Connections to write `09`.
- **A staged key never outlives its link.** The key held in RAM after a `09` write is dropped on
  every BLE connect and disconnect, so only the central that staged it can commit it at `03`.
- **A running board keeps the 0.3.x rule.** While the board is in Error with Wi-Fi joined this boot
  and only the API side failed (4, 6, 9-13, or 7/8 raised after the join), SSID/password/wallet
  writes (`01`/`02`/`03`) over an UNENCRYPTED BLE link are ignored, and ESP8266 `POST /provision`
  over the OPEN AP answers `409 {"err":"busy"}`. An encrypted link (a client that wrote `09` is
  paired), USB and the WPA2 setup AP still start a new attempt. Wi-Fi errors (1-3) and errors raised
  before any join still reset on any SSID write, as in 11.2.
- **Late registration success, continued.** A key refusal (7/8) raised while running does not stop a
  later successful registration from moving the state to 3 Connected.
- **Improv `0x01` in every phase.** Wi-Fi settings over USB are accepted on a running board too (USB
  is physical access, the same trust as `0xF0`): they are persisted and the board restarts into
  them; no Provisioned state or URL is reported for the connection it is leaving. A board that
  was provisioned earlier this boot (state 2 Connecting or 3 Connected) starts over the same way;
  a board in Error starts over too, whatever the error. `0x04` scan is
  still answered only while the provisioning transport is up. The restart after an `0xF0` key change
  waits for 3 s without another Improv command; a `0x01` sent within that window restarts the board
  anyway. This replaces the 11.4 rule that `0x01` is gated on the provisioning transport.
- **Golden vectors** now live in `test/fixtures/improv_fry_vectors.json` (ASCII-only JSON with each
  vector's inputs); the hex lines in 11.4 are the same bytes.
- **Image verification (replaces the 11.5 bullet).** A pending image is marked valid only once
  hardwareapi has answered (any HTTP status) AND the image has run for `POC_INTERVAL_MS` + 60 s
  (11 minutes), so a crash in the VPN start, telemetry or the first PoC/lease cycle still rolls it
  back. A failed mark is retried on every later answer; a rollback that is impossible (no other
  valid image) leaves the image running and reported as `pending`. The no-answer deadline (20 min;
  2 min on the test channel) counts only time with the station associated and holding an IP. The
  manifest check a pending image skipped runs right after it is marked valid.
- **Strikes (replaces "never installs it again").** The previous image counts one strike per rollback
  from a version (`fry_ota/badver` + `fry_ota/badn`, written together by that image's boot check
  only). With fewer than 3 strikes the version is skipped on the first check after the rollback and
  retried at the next 6-hour check; at 3 it is skipped for good. A manifest naming a different
  version clears the strikes. A restart that is not a failure while the image is pending
  (restartToApply, a USB re-key) sets `fry_ota/planrst`, and the rollback it causes is not counted.
- **Keyless boards do not update.** A USER_SUPPLIED board without a key skips the manifest check: it
  makes no hardwareapi call at all, so a new image could never verify.
- **Kill switch.** A normal (non-prerelease) release whose manifest is exactly
  `{"firmware_version":"0.0.0","channel":"prod","builds":{}}` (`tools/fw-hold/manifest.json`) stops
  every client: v0.3.1/0.3.3 get no URL on any chip, 0.4.x see nothing newer (`test/test_fw_hold`).
- **Key recovery.** A board that lost `fry/minerKey` but kept `fry/salt`, and whose key was never
  written by its owner (`keySrc` is not `user`), re-derives the same `SHA256(mac6 || salt)` key at
  boot. It never mints a new key and never re-derives an owner's key.
- **Held chips.** 0.4.0 is not released for ESP32-S3 and ESP8266: not in any manifest and not
  attached to any release; the web flasher keeps their 0.3.3 parts in `docs/flash/fw/hold/`
  (`manifest-hold.json`).
- **Serial lines added or changed:**

```
ota: image <v> is pending verification - valid once hardwareapi answered and it ran <s>s, rolled back after <s>s of Wi-Fi without an answer
ota: image <v> marked valid after <s>s (hardwareapi answered, last http=<code>; <register|poc|lease|settle window>)
ota: marking <v> valid FAILED (err=<n>) - retried on the next hardwareapi answer
ota: no hardwareapi answer after <s>s of Wi-Fi on pending image <v> - rolling back
ota: rollback impossible (no other valid image) - staying on pending <v>
ota: <v> was rolled back - running <v>, strike <n>/3 for <v> - retried after the next 6 h check
ota: <v> was rolled back - running <v>, strike 3/3 for <v> - it will not be installed again
ota: <v> was rolled back by a planned restart - not counted
ota: manifest names <v> - strikes for <v> cleared
ota: manifest check skipped - no miner key yet
ota: not updating - <wrong_channel|bad_version|no_build> (manifest channel=<c>, ours=<c>, strikes=<n>)
[identity] miner key missing - re-deriving it from the stored salt (recovery, not a new key)
[prov] ignored: unencrypted write while running - pair (write the key) first
```
