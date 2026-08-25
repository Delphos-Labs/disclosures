# USB Video DoS Firmware

This firmware presents a single-function USB Video Class device designed to trigger a `usbvideo.sys` descriptor parser infinite loop.

Important properties:

- Device class: Video (`0x0E`).
- Device subclass: VideoControl (`0x01`).
- One VideoControl interface.
- No IAD and no composite parent.
- Configuration descriptor includes a vendor-specific descriptor with `bLength=0`.

The firmware does not stream video. The bug triggers during configuration descriptor parsing while Windows starts the device.
