# Setting up a Fry IoT VPN node

From a blank board to a device earning on the dashboard. Takes about ten minutes.

**No licence, subscription or activation key is required.** Flash the firmware, provision it with
your Wi-Fi and your Algorand wallet, then claim the miner key on the dashboard. That is the whole
process.

---

## 1. What you need

| | |
|---|---|
| A supported board | ESP32, ESP32-S3, ESP32-C3, or ESP8266 |
| A USB data cable | Charge-only cables will not work — the board must enumerate as a serial device |
| A 2.4 GHz Wi-Fi network | The radio on these chips **cannot see 5 GHz networks at all** |
| An Algorand wallet address | 58 characters. Rewards are paid here |
| An Android phone or tablet | For provisioning over Bluetooth or Wi-Fi |

A desktop computer running Chrome or Edge is needed for flashing only.

---

## 2. Flash the firmware

Open **<https://fry-networks.github.io/fry-firmware/flash/>** in Chrome or Edge on a desktop.
Firefox and Safari do not implement Web Serial and will not work.

1. Plug the board in.
2. Pick your board from the dropdown.
3. Click **Connect & Flash** and choose the serial port in the browser prompt.
4. Wait for `Done — Fry firmware vX.Y.Z flashed and verified`.

If no port appears, the board's USB-serial driver is probably missing. Most boards use CP210x,
CH340/CH9102, or the ESP32-S3/C3 built-in USB — install the matching driver and replug.

Prefer the command line? `pio run -e <env> -t upload` from a checkout of this repo, or flash the
release `.bin` files with `esptool`. See [README.md](../README.md).

---

## 3. Install the Android app

Download the latest APK from
**<https://github.com/Fry-Networks/fry-app-android/releases/latest>** and install it. Android will
warn about installing outside the Play Store; allow it for your browser or file manager.

Grant **Bluetooth** and **Location** when asked. Location feels unrelated, but Android 12 and later
require it for any Bluetooth scan — the app never reads your position.

---

## 4. Provision the board

Power the board and open the app's **Scan** tab.

- **ESP32 / ESP32-S3 / ESP32-C3** advertise over Bluetooth as `FRY-<CHIP>-<MAC6>`, for example
  `FRY-ESP32-C77AB8`.
- **ESP8266** has no Bluetooth. It raises a Wi-Fi setup network named `FRY-SETUP-<MAC6>` instead.
  The app finds it in the same scan.

Tap your device, then enter:

- your 2.4 GHz Wi-Fi name and password
- your 58-character Algorand wallet address

The board saves the credentials, joins your network, and registers itself. The app shows its
**miner key** — `IOT-` followed by 32 hex characters. **Write this down.** You need it in step 5,
and it is derived from the board's MAC, so it stays the same across factory resets.

### A board does not appear in the scan

The most common cause is that the board is **already provisioned**. A board that is on a Wi-Fi
network does not advertise, because it has nothing to be provisioned for. Factory reset it
(section 6) and scan again.

Otherwise, in order: check the board has power, keep it within a few metres of the phone, confirm
Bluetooth is on, and confirm Location permission was granted. The app now tells you which of these
is wrong instead of just showing an empty list.

---

## 5. Claim it on the dashboard

**This step is what makes the device show up, and it is easy to miss.** A provisioned device that
is online and earning will still be invisible on the dashboard until you claim its miner key,
because the dashboard lists devices belonging to your account, not every device on the network.

1. Sign in at **<https://dashboard.frynetworks.com>** and connect your wallet (Pera, Defly, Lute
   and Kibisis are supported).
2. Register the `IOT-...` miner key from step 4 to your account.
3. The device appears under **Devices**.

If the app says the device is online but the dashboard shows nothing, you are almost certainly at
this step. Note the app's "online" indicator only means the app finished provisioning recently —
it is not a live link to the board.

---

## 6. Monitor it

**Dashboard** — <https://dashboard.frynetworks.com> is the source of truth for status and rewards.
A device's standing comes from its Proof of Connectivity record: 144 ten-minute slots per day.
Rewards are always claimed manually; nothing is auto-sent.

**Serial** — connect over USB at **115200 baud** and watch the log directly:

```
pio device monitor --port COM5 --baud 115200
```

The lines worth knowing:

| Line | Meaning |
|---|---|
| `FRY boot v0.3.0 chip=ESP32 mac=... minerkey=IOT-...` | Boot banner with the board's identity |
| `BLE advertising name=FRY-ESP32-XXXXXX svc=465259` | Waiting to be provisioned |
| `wifi connected ip=...` | Joined your network |
| `wifi connect failed reason=201` | Wi-Fi not found — wrong name, out of range, or 5 GHz only |
| `wifi connect failed reason=202` | Wrong Wi-Fi password |
| `api: registered install=... token=none` | Registered with the network |
| `socks5: listening :1080` / `wg: handshake ok` | Relay is up and carrying traffic |
| `[health] up=... heap=... rssi=... vpn=up relayed=...` | Periodic health line |
| `ota: ... action=none` | Firmware is current |

---

## 7. Factory reset

Hold the **BOOT** button for **10 seconds** while the board is running. The serial log counts up
(`[reset] hold 3s/10s`) and then confirms:

```
[reset] factory reset - clearing wifi + wallet, identity preserved
```

The board clears its Wi-Fi credentials and wallet, reboots, and starts advertising again. **It
keeps its miner key**, so it stays the same device on the dashboard and you do not have to claim it
again.

On most boards BOOT is GPIO0 and is labelled `BOOT` or `FLASH`. On the ESP32-C3 DevKitM-1 it is
GPIO9.

Reset it when you change your Wi-Fi password or router, move the board to another network, want to
point it at a different wallet, or are handing it on to someone else.

---

## 8. Troubleshooting

**`wifi connect failed reason=201`** — the board cannot see the network. Almost always a 5 GHz-only
network, or a typo in the name. These chips are 2.4 GHz only. Factory reset and re-provision with
the right network.

**`wifi connect failed reason=202`** — wrong password. Factory reset and re-provision.

**`api: register rejected http=401`** — the board keeps running: Wi-Fi, the relay and health
reporting are unaffected, and it retries hourly. Nothing to do.

**Provisioning fails partway** — move the phone closer and retry; Bluetooth setup is sensitive to
range. If it keeps failing at the same step, factory reset first so the board starts clean.

**Nothing on serial** — wrong baud rate (it is 115200), a charge-only USB cable, or a board that is
not powered.

Still stuck? Ask in **<https://discord.gg/frynetworks>** with your board type, the `IOT-` miner key,
and the serial log around the failure.
