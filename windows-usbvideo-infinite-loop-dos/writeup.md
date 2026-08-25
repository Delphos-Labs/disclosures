# Technical Writeup: usbvideo.sys bLength=0 Infinite Loop

## Overview

`usbvideo.sys` version `10.0.26100.7705` contains a descriptor parser infinite loop. The issue is triggered when a single-function USB Video Class device serves a configuration descriptor containing a descriptor with `bLength=0`.

The affected parser accepts the zero-length descriptor as valid and then advances the parse pointer by zero bytes. The same descriptor is parsed forever.

## Tested Driver

```text
File:    C:\Windows\System32\drivers\usbvideo.sys
Version: 10.0.26100.7705
SHA256:  AD366CD2992C5EFE2B8ACB08FADFC17B4B6C2D2F58D98C6540FF5C0AA6ED75A1
```

## Root Cause

The relevant function is `DumpAndValidateGenericDescriptor`, called from descriptor-walking functions such as `DumpAndValidateAllDescriptorsEx`.

Two validation paths exist. The older path rejects `bLength=0` because it checks whether the next pointer would advance:

```c
if (&desc[desc->bLength] <= desc)
    return ERROR;
```

The newer feature-flagged path checks only whether the length fits inside the remaining buffer:

```c
if (desc > end || end - desc < desc->bLength)
    return ERROR;

return SUCCESS;
```

When `desc->bLength == 0`, the second condition passes and the function returns success.

The caller then does:

```c
desc = desc + desc->bLength;
```

With `bLength=0`, `desc` never changes.

## Trigger Descriptor

The PoC configuration descriptor is 34 bytes:

| Offset | Size | Descriptor | Notes |
| --- | ---: | --- | --- |
| 0 | 9 | Configuration | `wTotalLength=34` |
| 9 | 9 | Interface | VideoControl interface |
| 18 | 12 | VC_HEADER | Valid UVC header, `bInCollection=0` |
| 30 | 2 | Poison | `bLength=0`, `bDescriptorType=0xFF` |
| 32 | 2 | Padding | Keeps `desc+2 <= end` true |

The poison descriptor uses type `0xFF` so it routes to the generic descriptor validator.

## Why Single-Function Matters

The firmware enumerates as a single-function USB Video Class device:

```text
bDeviceClass    = 0x0E
bDeviceSubClass = 0x01
bDeviceProtocol = 0x00
```

There is no Interface Association Descriptor and no composite parent. This causes `usbvideo.sys` to receive the configuration descriptor directly.

A composite version did not work because `usbccgp.sys` rebuilds function descriptors and filters out descriptors with `bLength < 2` before `usbvideo.sys` sees them.

## Impact

The vulnerable thread spins in kernel code during PnP device start. The result observed during testing:

- the core handling USB parsing at 100% in the `System` process;
- system-wide USB enumeration blocked;
- unplugging the device does not recover the stuck thread;
- normal reboot was blocked; forced reboot or power cycle was required.

## Suggested Fix

Reject descriptors that cannot advance the parser:

```c
if (desc->bLength < 2)
    return ERROR;
```

This can be implemented in the generic descriptor validator or in the descriptor-walking caller before advancing the parse pointer.

## MSRC Outcome

The issue was reported to MSRC as a system-wide USB denial of service in `usbvideo.sys`. On July 23, 2026, MSRC responded that they did not consider it a bug and closed the case without a fix.
