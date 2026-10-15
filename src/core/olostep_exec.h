#pragma once
// Executor interface for the opt-in "olostep" web-relay. Compiled OUT by default (see
// olostep_flag.h). The implementation is a separate, privately built module that provides the
// STRONG definitions of the fry_olostep_* functions; olostep_stubs.cpp supplies weak no-op defaults
// so a FRY_HAS_OLOSTEP build links without it. Every URL and job the module handles must first pass
// lib/fry_core/olostep_guard.h; this header names no endpoint and no protocol.
//
// Production call sites use the FRY_OLOSTEP_* macros below (empty defaults live at the end of
// provisioning_transport.h). A macro on an existing source line, rather than an #if block, keeps every
// line number of the production files unchanged, so default-build images stay byte-identical.
#include "olostep_flag.h"

#if FRY_HAS_OLOSTEP

#include "olostep_consent.h"
#include "olostep_guard.h"

extern "C" {

void fry_olostep_start();           // begin serving; only called when the owner has opted in
void fry_olostep_stop();            // stop serving and drop the connection
void fry_olostep_tick();            // called every loop() while the board is Ready
void fry_olostep_optin_changed();   // the stored opt-in flag changed (BLE write); re-read it
bool fry_olostep_running();
void fry_olostep_consent_write_failed(bool requested);  // the opt-in write did not persist; an OFF request must latch the relay dormant (RAM only)

}  // extern "C"

#if !defined(ARDUINO_ARCH_ESP8266)
class NimBLECharacteristic;
class NimBLECharacteristicCallbacks;
class NimBLEConnInfo;
class NimBLEService;
// src/esp32/olostep_ble.cpp: the opt-in characteristic (write-only, 1 byte; ON needs an encrypted link).
void fry_olostep_ble_create(NimBLEService* service, NimBLECharacteristicCallbacks* callbacks);
bool fry_olostep_ble_handle_write(NimBLECharacteristic* ch, NimBLEConnInfo& connInfo);
#define FRY_OLOSTEP_BLE_CREATE(svc, cb) fry_olostep_ble_create(svc, cb);
#define FRY_OLOSTEP_BLE_ONWRITE(ch, ci) if (fry_olostep_ble_handle_write(ch, ci)) return;
#endif

#define FRY_OLOSTEP_ON_READY() do { if (getOlostepOptIn()) fry_olostep_start(); } while (0);
#define FRY_OLOSTEP_TICK() fry_olostep_tick();

#endif  // FRY_HAS_OLOSTEP
