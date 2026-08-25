# Delphos Labs - Vulnerability Disclosures

Public vulnerability disclosures and proof-of-concept exploits from [Delphos Labs](https://delphos.io).

## Disclosures

| Name | Description | Date |
|------|-------------|------|
| [CVE-2026-50321-winusb-uaf](CVE-2026-50321-winusb-uaf/) | Windows WinUSB pipe lifecycle use-after-free / double-free leading to local elevation of privilege. | 2026-07-14 |
| [windows-usbvideo-infinite-loop-dos](windows-usbvideo-infinite-loop-dos/) | Windows USB Video class driver device-triggered denial of service via malformed USB video descriptors. | 2026-08-11 |
| [DirtyCBC](DirtyCBC/) | Linux kernel page-cache poisoning via AF_RXRPC RxGK decrypt-before-MAC and `MSG_SPLICE_PAGES`. Local privilege escalation to root. | 2026-05-15 |

## Responsible Disclosure

All vulnerabilities listed here were reported to the affected maintainers and patched upstream before public disclosure. Proof-of-concept code is provided for defensive validation and research purposes only.

## License

Individual disclosures may carry their own license. See each directory for details.
