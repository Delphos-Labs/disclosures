# usbvideo.sys bLength=0 Denial of Service

This repository contains Delphos Labs research material for a Windows USB Video Class driver denial-of-service issue reported to MSRC.

The bug is an infinite loop in `usbvideo.sys` descriptor parsing. A single-function USB Video Class device can serve a configuration descriptor containing a zero-length descriptor. In the affected parser path, `bLength=0` is accepted, and the descriptor walk advances by zero bytes forever.

## Impact

On the tested Windows 11 system:

- the core handling USB parsing was pinned at 100% in kernel mode;
- USB enumeration failed system-wide;
- unplugging the device did not recover the system;
- normal reboot was blocked; forced reboot or power cycle was required.

On July 23, 2026, MSRC responded that they did not consider it a bug and closed the case without a fix.

## Timeline

```text
2026-05-02  Issue discovered and reproduced with Teensy firmware
2026-05-02  MSRC submission prepared
2026-07-23  MSRC responded that they did not consider it a bug
```

## Contents

- `writeup.md`: technical analysis and root cause.
- `firmware/`: firmware source for the malicious USB Video Class test device.

## Tested Driver

```text
Driver:  C:\Windows\System32\drivers\usbvideo.sys
Version: 10.0.26100.7705
SHA256:  AD366CD2992C5EFE2B8ACB08FADFC17B4B6C2D2F58D98C6540FF5C0AA6ED75A1
OS:      Windows 11 24H2 / build 26200.7840
```

## Reproduction Warning

This proof of concept is designed to make the Windows USB parsing path spin indefinitely and may require a forced reboot or power cycle to clear. Run only on systems you own or are explicitly authorized to test.

Build and flash the Teensy 3.2 firmware:

```text
teensy_loader_cli --mcu=mk20dx256 -w -v firmware/build/firmware.hex
```

Then plug the device into the target system. The bug triggers during device enumeration; no host-side application is needed.

## Hardware

The PoC was built for Teensy 3.2. Any USB-capable device that can serve arbitrary descriptors and enumerate as a single-function USB Video Class device can reproduce the descriptor shape.

## Legal Notice

This material is provided for defensive security research, validation, and remediation. Do not use it against systems without authorization.
