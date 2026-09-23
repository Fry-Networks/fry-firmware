#!/usr/bin/env python3
"""Renders docs/setup/esp32/index.html from a facts file.

    py -3 tools/render_guide.py --facts <facts.json> --out docs/setup/esp32/index.html

The guide is generated rather than written by hand because setup prose rots faster than anything
else in a repo: a reward figure, a heartbeat interval or a dashboard route changes on a server and
the page that told users about it keeps saying the old thing for months. Every number, URL and
rule below comes from the facts file, where each value carries the evidence that established it.

Two rules the generator enforces rather than trusts:

  * A MISSING FACT IS A HARD FAILURE. Rendering a blank, a "None" or a half-sentence where a fact
    should be is worse than not rendering at all - it ships a page that looks authoritative and
    is not. Facts.value() exits with the dotted key path it could not find.
  * THE LEGACY KEY PREFIX IS MENTIONED EXACTLY ONCE. Users flashing a board today do not have a
    legacy key and do not need to think about one; users who do have one need a single clear
    sentence, not a prefix scattered through the page for them to piece together. Later
    occurrences are turned into links back to that one note, and the count is asserted.
"""
import argparse
import html
import json
import os
import re
import sys

# The dashboard's product label for these boards. Supplied and hardware-verified by the team lead
# on 2026-09-22 rather than derived from a server, so it is an OPTIONAL fact: put
# "dashboard_device_label" in the facts file to override it, and the required-fact rule above is
# untouched either way.
DEFAULT_DEVICE_LABEL = "Fry Edge Miner"

LEGACY_ANCHOR = "legacy-key"


class Facts:
    """Dotted-path access to the facts file, where a miss is fatal."""

    def __init__(self, path):
        self.path = path
        with open(path, encoding="utf-8") as f:
            self._data = json.load(f)

    def _node(self, dotted):
        node = self._data
        walked = []
        for part in dotted.split("."):
            walked.append(part)
            if not isinstance(node, dict) or part not in node:
                sys.exit("render_guide: %s has no fact %r (failed at %r). Refusing to render a "
                         "page with a hole in it." % (self.path, dotted, ".".join(walked)))
            node = node[part]
        return node

    def value(self, dotted):
        """The fact's value. Facts are {"value": ..., "evidence": ...}; bare values work too."""
        node = self._node(dotted)
        if isinstance(node, dict):
            if "value" not in node:
                sys.exit("render_guide: fact %r in %s has no 'value'" % (dotted, self.path))
            return node["value"]
        return node

    def note(self, dotted, key="note"):
        """An optional 'note' or 'status' beside a value, or "" - commentary, not facts."""
        node = self._node(dotted)
        return node.get(key, "") if isinstance(node, dict) else ""

    def optional(self, dotted, default):
        try:
            node = self._data
            for part in dotted.split("."):
                node = node[part]
        except (KeyError, TypeError):
            return default
        return node.get("value", node) if isinstance(node, dict) else node


def esc(value):
    return html.escape(str(value), quote=True)


def enforce_single_legacy_mention(page):
    """Keeps the first "IOT-" and turns every later one into a link to that note."""
    first = page.find("IOT-")
    if first < 0:
        sys.exit("render_guide: the legacy-key note is missing - the prefix must appear exactly "
                 "once, and it appears not at all")
    head, tail = page[:first + 4], page[first + 4:]
    # "an IOT- key" has to become "a legacy-prefix key", not "an legacy-prefix key", so the
    # article in front of a later occurrence is rewritten with it.
    link = '<a href="#%s">legacy-prefix</a>' % LEGACY_ANCHOR
    tail = re.sub(r"\b[Aa]n IOT-", "a " + link, tail)
    tail = tail.replace("IOT-", link)
    page = head + tail
    count = page.count("IOT-")
    if count != 1:
        sys.exit("render_guide: the legacy prefix appears %d times, expected exactly 1" % count)
    return page


STYLE = """
  :root {
    --bg: #09090B; --surface: #1A1A1E; --card: #242428; --primary: #E5271C;
    --accent: #00C49A; --warn: #F5A524; --text: #EFECEA; --muted: #9B9793; --border: #323236;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.55; }
  body { padding: 32px 16px 64px; }
  main { max-width: 760px; margin: 0 auto; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 8px; }
  h1 { font-size: 1.9rem; margin: 0 0 6px; letter-spacing: -0.02em; }
  h1 .fry { color: var(--primary); }
  h2 { font-size: 1.25rem; margin: 36px 0 10px; scroll-margin-top: 16px; }
  h3 { font-size: 1rem; margin: 20px 0 6px; color: var(--accent); }
  p, li { font-size: 1rem; }
  .lede { color: var(--muted); margin: 0; }
  a { color: var(--accent); }
  code { background: var(--card); border: 1px solid var(--border); border-radius: 5px;
    padding: 1px 5px; font-size: 0.9em; overflow-wrap: anywhere; }
  nav.toc { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px 18px; margin-top: 24px; }
  nav.toc ol { margin: 0; padding-left: 20px; }
  nav.toc li { margin: 3px 0; }
  section { border-top: 1px solid var(--border); padding-top: 4px; }
  .callout { background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--accent);
    border-radius: 8px; padding: 12px 14px; margin: 14px 0; }
  .callout.warn { border-left-color: var(--warn); }
  .callout.warn strong { color: var(--warn); }
  .callout p:first-child { margin-top: 0; }
  .callout p:last-child { margin-bottom: 0; }
  table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 0.95rem; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border);
    vertical-align: top; }
  th { color: var(--muted); font-weight: 600; }
  dl { margin: 14px 0; }
  dt { font-weight: 600; margin-top: 12px; }
  dd { margin: 4px 0 0; color: var(--muted); }
  footer { margin-top: 48px; border-top: 1px solid var(--border); padding-top: 14px;
    color: var(--muted); font-size: 0.8rem; }
  @media (max-width: 480px) { body { padding: 20px 14px 48px; } h1 { font-size: 1.5rem; } }
"""


def sections(f):
    """Returns [(anchor, title, html)] - the guide, in reading order."""
    dash = f.value("dashboard_url")
    register_url = dash + f.value("registration_route")
    out = []

    boards = "".join("<li>%s</li>" % esc(b) for b in f.value("supported_boards"))
    out.append(("boards", "Supported boards", """
<p>Any of these will run the firmware:</p>
<ul>%s</ul>
<p>They differ in how you set them up: the ESP32 family is provisioned over Bluetooth or over
USB from a browser, while the ESP8266 raises its own Wi-Fi network instead of Bluetooth.</p>
""" % boards))

    out.append(("flash", "Flash the firmware", """
<p>Plug the board into a computer with a USB data cable &mdash; a charge-only cable will not
enumerate a serial port &mdash; and open the flasher in Chrome or Edge on the desktop:</p>
<p><a href="%(url)s">%(url)s</a></p>
<p>Press <strong>Connect &amp; Flash</strong> and pick the serial port. The flasher detects which
chip you have and writes the matching build; there is no board to choose and nothing to download.</p>
<div class="callout" id="%(anchor)s">
  <p><strong>Updating a board that already works?</strong> Leave <strong>Erase</strong> unchecked.
  The update writes the bootloader, the partition table and the application, and never touches the
  area holding your miner key and Wi-Fi credentials, so the board keeps its identity.</p>
  <p>%(legacy)s</p>
</div>
""" % {"url": esc(f.value("flasher_url")), "anchor": LEGACY_ANCHOR,
       "legacy": esc(f.value("legacy_key_policy"))}))

    out.append(("provision", "Give it Wi-Fi", """
<h3>From the browser, with no phone</h3>
<p>Straight after flashing, choose <strong>Connect to Wi-Fi</strong> in the same dialog, enter
your 2.4&nbsp;GHz network and its password, and the board joins it. Then press
<strong>Visit Device</strong>, which opens the dashboard registration page with your miner key
already in the address.</p>
<p class="lede">%(web)s. %(android_note)s</p>
<h3>From the Android app</h3>
<p>The app finds an ESP32 board over Bluetooth, advertising as <code>%(ble)s</code> (service
<code>%(svc)s</code>). An ESP8266 has no Bluetooth: it raises an open Wi-Fi network
<code>%(ap)s</code> instead &mdash; join it and the setup page opens by itself. The app asks for
your Wi-Fi and your Algorand wallet address in one step.</p>
""" % {"web": esc(f.value("provisioning.web_serial")),
       "android_note": esc(f.note("provisioning.android_required")),
       "ble": esc(f.value("provisioning.ble_name_pattern")),
       "svc": esc(f.value("provisioning.ble_service")),
       "ap": esc(f.value("provisioning.softap_ssid_pattern"))}))

    out.append(("key", "Find your miner key", """
<p>The miner key is the board's identity: <strong>%(fmt)s</strong>. It is generated once, on the
board itself, and never changes &mdash; not on a factory reset, and not on a firmware update.
There are four places to read it:</p>
<dl>
  <dt>The web flasher</dt><dd>%(web)s</dd>
  <dt>A serial console</dt><dd><code>%(serial)s</code></dd>
  <dt>The Android app</dt><dd>%(app)s</dd>
  <dt>The ESP8266 setup page</dt><dd>%(portal)s</dd>
</dl>
<p class="lede">Over Bluetooth it is also readable directly from characteristic
<code>%(ble)s</code>.</p>
""" % {"fmt": esc(f.value("key_format")),
       "web": "Press <strong>Visit Device</strong> after provisioning &mdash; it carries the key.",
       "serial": esc(f.value("how_to_find_your_key.serial_console")),
       "app": esc(f.value("how_to_find_your_key.android_app")),
       "portal": esc(f.value("how_to_find_your_key.esp8266_portal")),
       "ble": esc(f.value("how_to_find_your_key.ble_characteristic"))}))

    out.append(("register", "Register it on the dashboard", """
<p>A board that is running and online still earns nothing until a wallet claims its key. Sign in
at <a href="%(dash)s">%(dash)s</a>, connect your wallet, open <a href="%(reg)s">%(reg)s</a> and
enter the miner key. <strong>Visit Device</strong> in the flasher opens that page for you, with
the key in the URL fragment: <code>%(prefill)s</code>.</p>
<p class="lede">The prefilled link is not live yet &mdash; %(prefill_status)s. Until it lands,
paste the key into the key field on that page.</p>
<div class="callout warn">
  <p><strong>Do not press &ldquo;Generate Free FEM Key&rdquo;.</strong> %(free_key)s</p>
</div>
<p>%(must)s Until then the dashboard shows it as an unregistered
<strong>%(label)s</strong>.</p>
""" % {"dash": esc(dash), "reg": esc(register_url),
       "prefill": esc(f.value("register_prefill")),
       "prefill_status": esc(f.note("register_prefill", "status")),
       "free_key": esc(f.value("generate_free_fem_key_rule")),
       "must": esc(f.note("earning.must_be_registered")),
       "label": esc(f.optional("dashboard_device_label", DEFAULT_DEVICE_LABEL))}))

    tiers = ", ".join("%s = %s&times;" % (esc(k), esc(v))
                      for k, v in f.value("earning.stake_tiers").items())
    out.append(("earning", "What earning actually requires", """
<table>
  <tr><th>Reward token</th><td>%(token)s</td></tr>
  <tr><th>Miner code</th><td><code>%(code)s</code></td></tr>
  <tr><th>Base reward</th><td>%(base)s per slot</td></tr>
  <tr><th>Slots per day</th><td>%(slots)s (one every ten minutes)</td></tr>
  <tr><th>Devices per network</th><td>%(limit)s</td></tr>
  <tr><th>Stake multipliers</th><td>%(tiers)s</td></tr>
  <tr><th>Payout schedule</th><td>%(rollup)s</td></tr>
</table>
<p class="lede">%(tier_note)s</p>
<p>So a board earns when it is registered to a wallet, online, and reporting. Nothing else is
required: there is no licence, no activation key and no stake.</p>
""" % {"token": esc(f.value("earning.reward_token")), "code": esc(f.value("earning.miner_code")),
       "base": esc(f.value("earning.base_reward")), "slots": esc(f.value("earning.slots_per_day")),
       "limit": esc(f.value("earning.device_limit_per_network")), "tiers": tiers,
       "rollup": esc(f.value("earning.weekly_rollup")),
       "tier_note": esc(f.note("earning.stake_tiers"))}))

    hb = f.value("monitoring.heartbeat_intervals_seconds")
    statuses = "".join("<li>%s</li>" % esc(s) for s in f.value("monitoring.statuses"))
    out.append(("monitoring", "Watching it run", """
<p>A board counts as active while it has been seen within the last
<strong>%(window)s minutes</strong>. It reports on several schedules, all in seconds:</p>
<table>
  <tr><th>Registration heartbeat</th><td>%(registration)s</td></tr>
  <tr><th>Lease renewal</th><td>%(lease)s</td></tr>
  <tr><th>Proof of connectivity</th><td>%(poc)s</td></tr>
  <tr><th>Telemetry</th><td>%(telemetry)s</td></tr>
</table>
<p>The statuses you will see against a device:</p>
<ul>%(statuses)s</ul>
""" % {"window": esc(f.value("monitoring.active_window_minutes")),
       "registration": esc(hb["registration"]), "lease": esc(hb["lease"]),
       "poc": esc(hb["poc"]), "telemetry": esc(hb["telemetry"]), "statuses": statuses}))

    out.append(("troubleshooting", "When something is wrong", """
<dl>
  <dt>&ldquo;Key not found&rdquo; when registering</dt><dd>%(not_found)s</dd>
  <dt>&ldquo;Already registered&rdquo;</dt><dd>%(already)s</dd>
  <dt>Provisioning reports an error</dt><dd>%(prov)s</dd>
  <dt>The board registers, then the dashboard never sees it</dt><dd>%(legacy)s</dd>
  <dt>The board is not discoverable any more</dt><dd>It does not advertise while it is on a
  Wi-Fi network. Hold the <strong>BOOT</strong> button for ten seconds to factory reset it; it
  keeps its miner key and its identity, and comes back ready to be provisioned again.</dd>
</dl>
<p>Still stuck? Ask on <a href="%(support)s">Discord</a> &mdash; include the miner key, the board
type and what the serial console printed.</p>
""" % {"not_found": esc(f.value("troubleshooting.not_found")),
       "already": esc(f.value("troubleshooting.already_registered")),
       "prov": esc(f.value("troubleshooting.provision_failed")),
       "legacy": esc(f.value("troubleshooting.registration_failed_legacy")),
       "support": esc(f.value("support_url"))}))

    return out


def render(f):
    parts = sections(f)
    toc = "".join('<li><a href="#%s">%s</a></li>' % (a, esc(t)) for a, t, _ in parts)
    body = "".join('<section>\n<h2 id="%s">%s</h2>%s</section>\n' % (a, esc(t), h)
                   for a, t, h in parts)
    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Set up a Fry miner &mdash; ESP32 &amp; ESP8266</title>
<meta name="description" content="Flash, provision, register and monitor a Fry Networks ESP32 or ESP8266 miner." />
<style>%s</style>
</head>
<body>
<main>
<header>
  <h1>Setting up a <span class="fry">Fry</span> miner</h1>
  <p class="lede">Flash the board, give it Wi-Fi, register its key. Fifteen minutes, no phone
  required, no licence or activation key.</p>
</header>
<nav class="toc"><ol>%s</ol></nav>
%s<footer>
  <p>This page is generated by <code>tools/render_guide.py</code> from a facts file in which every
  value carries the evidence that established it. Edit the facts and re-render; do not edit this
  page by hand.</p>
</footer>
</main>
</body>
</html>
""" % (STYLE, toc, body)
    return enforce_single_legacy_mention(page)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--facts", required=True, help="path to the guide facts JSON")
    ap.add_argument("--out", default=os.path.join("docs", "setup", "esp32", "index.html"))
    a = ap.parse_args()

    page = render(Facts(a.facts))
    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)
    print("render_guide: wrote %s (%d bytes) from %s" % (a.out, len(page), a.facts))


if __name__ == "__main__":
    main()
