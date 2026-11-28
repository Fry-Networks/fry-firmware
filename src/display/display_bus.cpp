#include "display_dev.h"

#if defined(FRY_HAS_DISPLAY)

#if !defined(FRY_SOFT_I2C)
#include FRY_INC_SYS(Wire.h)
#endif

namespace fry_dispdev {

DevPins devPinsFor(uint8_t preset) {
  DevPins d = {-1, -1, -1};
  int clk = -1, mosi = -1, miso = -1;  // ESP32-2432S028R: XPT2046 on its own bus (CLK25 MOSI32 MISO39)
  if (fry::disp::presetTouchBus(preset, &clk, &mosi, &miso)) {
    d.xptClk = clk;
    d.xptMosi = mosi;
    d.xptMiso = miso;
  }
  return d;
}

namespace {

inline void half() { delayMicroseconds(2); }

// SPI mode 0, MSB first, bit-banged. Slow on purpose (~250 kHz): probing happens once at boot.
void sendBits(int sck, int mosi, uint8_t v, int nbits) {
  for (int i = nbits - 1; i >= 0; i--) {
    digitalWrite(mosi, (v >> i) & 1);
    half();
    digitalWrite(sck, HIGH);
    half();
    digitalWrite(sck, LOW);
  }
}

uint8_t readByte(int sck, int miso) {
  uint8_t v = 0;
  for (int i = 0; i < 8; i++) {
    digitalWrite(sck, HIGH);
    half();
    v = (uint8_t)((v << 1) | (digitalRead(miso) ? 1 : 0));
    digitalWrite(sck, LOW);
    half();
  }
  return v;
}

}  // namespace

#if defined(FRY_SOFT_I2C)
// Bit-banged I2C master (~100 kHz, open-drain emulation) for cores whose Wire is not reachable.
namespace {
int g_sda = -1, g_scl = -1;
inline void sdaHi() { pinMode(g_sda, INPUT_PULLUP); }
inline void sdaLo() { pinMode(g_sda, OUTPUT); digitalWrite(g_sda, LOW); }
inline void sclHi() { pinMode(g_scl, INPUT_PULLUP); }
inline void sclLo() { pinMode(g_scl, OUTPUT); digitalWrite(g_scl, LOW); }
inline void tick() { delayMicroseconds(5); }
// Release SCL and wait for slaves that stretch it; false = the bus is stuck (timeout), never loops forever.
bool sclRelease(uint32_t timeoutUs) {
  sclHi();
  const uint32_t t0 = micros();
  while (!digitalRead(g_scl)) {
    if ((uint32_t)(micros() - t0) > timeoutUs) return false;
  }
  return true;
}
bool i2cStart(uint32_t to) {
  sdaHi();
  if (!sclRelease(to)) return false;
  tick();
  sdaLo();
  tick();
  sclLo();
  return true;
}
void i2cStop() {
  sdaLo();
  tick();
  sclRelease(1000);
  tick();
  sdaHi();
  tick();
}
bool i2cWrite(uint8_t b, uint32_t to) {  // returns true on ACK
  for (int i = 7; i >= 0; i--) {
    if ((b >> i) & 1) sdaHi(); else sdaLo();
    tick();
    if (!sclRelease(to)) return false;
    tick();
    sclLo();
  }
  sdaHi();
  tick();
  if (!sclRelease(to)) return false;
  tick();
  const bool ack = !digitalRead(g_sda);
  sclLo();
  return ack;
}
uint8_t i2cRead(bool ack, uint32_t to) {
  uint8_t v = 0;
  sdaHi();
  for (int i = 0; i < 8; i++) {
    tick();
    sclRelease(to);
    tick();
    v = (uint8_t)((v << 1) | (digitalRead(g_sda) ? 1 : 0));
    sclLo();
  }
  if (ack) sdaLo(); else sdaHi();
  tick();
  sclRelease(to);
  tick();
  sclLo();
  sdaHi();
  return v;
}
}  // namespace

bool Bus::i2cBegin(int sda, int scl, uint32_t hz) {
  sda_ = g_sda = sda;
  scl_ = g_scl = scl;
  hz_ = hz;
  sdaHi();
  sclHi();
  return true;
}
bool Bus::i2cProbe(uint8_t addr, uint32_t timeoutUs) {
  if (!i2cStart(timeoutUs)) return false;
  const bool a = i2cWrite((uint8_t)(addr << 1), timeoutUs);
  i2cStop();
  return a;
}
bool Bus::i2cReadReg(uint8_t addr, uint16_t reg, bool reg16, uint8_t* buf, size_t n, uint32_t timeoutUs) {
  if (!i2cStart(timeoutUs)) return false;
  bool ok = i2cWrite((uint8_t)(addr << 1), timeoutUs);
  if (ok && reg16) ok = i2cWrite((uint8_t)(reg >> 8), timeoutUs);
  if (ok) ok = i2cWrite((uint8_t)(reg & 0xFF), timeoutUs);
  if (ok) ok = i2cStart(timeoutUs) && i2cWrite((uint8_t)((addr << 1) | 1), timeoutUs);
  if (ok) for (size_t i = 0; i < n; i++) buf[i] = i2cRead(i + 1 < n, timeoutUs);
  i2cStop();
  return ok;
}
#else
bool Bus::i2cBegin(int sda, int scl, uint32_t hz) {
  sda_ = sda;
  scl_ = scl;
  hz_ = hz;
#if defined(ARDUINO_ARCH_RP2040)
  Wire.setSDA(sda);
  Wire.setSCL(scl);
  Wire.begin();
#elif defined(ARDUINO_ARCH_ESP32)
  Wire.end();
  if (!Wire.begin(sda, scl, hz)) return false;
#else
  Wire.begin(sda, scl);
#endif
  Wire.setClock(hz);
  return true;
}

bool Bus::i2cProbe(uint8_t addr, uint32_t timeoutUs) {
#if defined(ARDUINO_ARCH_ESP32)
  Wire.setTimeOut((uint16_t)(timeoutUs / 1000 ? timeoutUs / 1000 : 1));
#else
  (void)timeoutUs;
#endif
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

bool Bus::i2cReadReg(uint8_t addr, uint16_t reg, bool reg16, uint8_t* buf, size_t n, uint32_t timeoutUs) {
#if defined(ARDUINO_ARCH_ESP32)
  Wire.setTimeOut((uint16_t)(timeoutUs / 1000 ? timeoutUs / 1000 : 1));
#else
  (void)timeoutUs;
#endif
  Wire.beginTransmission(addr);
  if (reg16) Wire.write((uint8_t)(reg >> 8));
  Wire.write((uint8_t)(reg & 0xFF));
  if (Wire.endTransmission(false) != 0) return false;
  const size_t got = Wire.requestFrom((int)addr, (int)n);
  if (got != n) return false;
  for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)Wire.read();
  return true;
}

#endif  // FRY_SOFT_I2C

void Bus::i2cRecover() {
  if (sda_ < 0 || scl_ < 0) return;
#if defined(ARDUINO_ARCH_ESP32) && !defined(FRY_SOFT_I2C)
  Wire.end();
#endif
  // 9 SCL pulses release a slave stuck mid-byte, then a STOP (SDA low->high while SCL high).
  pinMode(sda_, INPUT_PULLUP);
  for (int i = 0; i < 9; i++) {
    pinMode(scl_, OUTPUT);
    digitalWrite(scl_, LOW);
    delayMicroseconds(5);
    pinMode(scl_, INPUT_PULLUP);
    delayMicroseconds(5);
  }
  pinMode(sda_, OUTPUT);
  digitalWrite(sda_, LOW);
  delayMicroseconds(5);
  pinMode(sda_, INPUT_PULLUP);
  delayMicroseconds(5);
  i2cBegin(sda_, scl_, hz_);
}

void Bus::setMisoPull(int miso, int pull) {
  if (miso < 0) return;
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_RP2040)
  pinMode(miso, pull > 0 ? INPUT_PULLUP : (pull < 0 ? INPUT_PULLDOWN : INPUT));
#else
  pinMode(miso, pull > 0 ? INPUT_PULLUP : INPUT);
#endif
  delayMicroseconds(50);  // let the pull settle
}

bool Bus::spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool dummyBit) {
  if (sck_ < 0 || mosi_ < 0 || miso_ < 0 || cs < 0 || dc < 0) return false;
  pinMode(sck_, OUTPUT);
  pinMode(mosi_, OUTPUT);
  pinMode(cs, OUTPUT);
  pinMode(dc, OUTPUT);
  digitalWrite(sck_, LOW);
  digitalWrite(cs, LOW);
  digitalWrite(dc, LOW);
  sendBits(sck_, mosi_, cmd, 8);
  digitalWrite(dc, HIGH);
  if (dummyBit) {  // controllers insert one dummy clock before the first read parameter
    digitalWrite(sck_, HIGH);
    half();
    digitalWrite(sck_, LOW);
    half();
  }
  for (size_t i = 0; i < n; i++) buf[i] = readByte(sck_, miso_);
  digitalWrite(cs, HIGH);
  return true;
}

namespace {
// One XPT2046 conversion, 12-bit, bit-banged (mode 0, ~250 kHz): 8 control bits, one busy clock, 12 data bits, 3 tail clocks.
// `pd` bits stay in the control byte; the internal reference must be on (PD1=1) for the TEMP / VBAT / AUX channels.
uint16_t xptConv(int clk, int mosi, int miso, int cs, uint8_t ctl) {
  digitalWrite(cs, LOW);
  sendBits(clk, mosi, ctl, 8);
  digitalWrite(clk, HIGH);
  half();
  digitalWrite(clk, LOW);
  half();
  uint16_t v = 0;
  for (int i = 0; i < 12; i++) {
    digitalWrite(clk, HIGH);
    half();
    v = (uint16_t)((v << 1) | (digitalRead(miso) ? 1 : 0));
    digitalWrite(clk, LOW);
    half();
  }
  for (int i = 0; i < 3; i++) {
    digitalWrite(clk, HIGH);
    half();
    digitalWrite(clk, LOW);
    half();
  }
  digitalWrite(cs, HIGH);
  return v;
}
}  // namespace

bool Bus::xpt2046Pins(int cs, int* clk, int* mosi, int* miso) const {
  *clk = xpt_.xptClk >= 0 ? xpt_.xptClk : sck_;
  *mosi = xpt_.xptMosi >= 0 ? xpt_.xptMosi : mosi_;
  *miso = xpt_.xptMiso >= 0 ? xpt_.xptMiso : miso_;
  return *clk >= 0 && *mosi >= 0 && *miso >= 0 && cs >= 0;
}

bool Bus::xpt2046Sample(int cs, uint16_t* x, uint16_t* y, uint16_t* z) {
  int clk, mosi, miso;
  if (!xpt2046Pins(cs, &clk, &mosi, &miso)) return false;
  pinMode(clk, OUTPUT);
  pinMode(mosi, OUTPUT);
  pinMode(miso, INPUT);  // GPIO36/39 are input-only with no internal pull: INPUT is all there is
  pinMode(cs, OUTPUT);
  digitalWrite(cs, HIGH);
  digitalWrite(clk, LOW);
  *x = xptConv(clk, mosi, miso, cs, 0xD1);
  *y = xptConv(clk, mosi, miso, cs, 0x91);
  const uint16_t z1 = xptConv(clk, mosi, miso, cs, 0xB1), z2 = xptConv(clk, mosi, miso, cs, 0xC1);
  const int32_t zz = (int32_t)z1 + 4095 - (int32_t)z2;
  *z = (uint16_t)(zz < 0 ? 0 : (zz > 4095 ? 4095 : zz));
  xptConv(clk, mosi, miso, cs, 0x00);  // power-down command so the next PENIRQ cycle starts clean
  return true;
}

int Bus::xpt2046Channels(int cs, uint16_t out[6]) {
  int clk, mosi, miso;
  if (!xpt2046Pins(cs, &clk, &mosi, &miso)) return 0;
  pinMode(clk, OUTPUT);
  pinMode(mosi, OUTPUT);
  pinMode(miso, INPUT);
  pinMode(cs, OUTPUT);
  digitalWrite(cs, HIGH);
  digitalWrite(clk, LOW);
  // Single-ended, 12-bit, reference + ADC on (PD=11): TEMP0 0x87, VBAT 0xA7, AUX 0xE7. The first conversion after the reference is
  // switched on is discarded (settling), then TEMP0 is read twice.
  xptConv(clk, mosi, miso, cs, 0x87);
  out[0] = xptConv(clk, mosi, miso, cs, 0x87);
  out[1] = xptConv(clk, mosi, miso, cs, 0x87);
  out[2] = xptConv(clk, mosi, miso, cs, 0xA7);
  out[3] = xptConv(clk, mosi, miso, cs, 0xE7);
  out[4] = xptConv(clk, mosi, miso, cs, 0xB1);  // Z1
  out[5] = xptConv(clk, mosi, miso, cs, 0xC1);  // Z2
  xptConv(clk, mosi, miso, cs, 0x00);           // power down
  return 1;
}

void Bus::release(const fry::disp::BoardPins& p) {
  const int all[] = {p.sda,    p.scl,      p.spiSck,   p.spiMosi, p.spiMiso, p.tftCs, p.tftDc,
                     p.touchCs, p.touchIrq, p.touchSda, p.touchScl, xpt_.xptClk, xpt_.xptMosi, xpt_.xptMiso};
  for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
    if (all[i] >= 0 && !fry::disp::pinForbidden(p, all[i])) pinMode(all[i], INPUT);
}

}  // namespace fry_dispdev

#endif  // FRY_HAS_DISPLAY
