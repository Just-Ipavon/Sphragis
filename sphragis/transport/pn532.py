"""
PN532 backend via nfcpy — HARDWARE ONLY, NOT EXERCISED BY THE TEST SUITE.

nfcpy already implements ISO-DEP for Type 4 tags, so this backend forwards
whole APDUs to `Type4Tag.transceive`. Requires the optional `nfcpy` package
and a PN532 reachable by nfcpy (USB, or "tty:USB0:pn532" style paths).
Untested placeholder: verify on the hardware host before relying on it.
"""

from __future__ import annotations

from . import ApduTransport, TransportError


class Pn532Transport(ApduTransport):
    def __init__(self, tag, frontend=None) -> None:
        self._tag = tag
        self._clf = frontend

    @classmethod
    def open(cls, path: str = "usb", timeout_s: float = 10.0) -> "Pn532Transport":
        """Open the reader at nfcpy `path` and wait for a Type 4 tag."""
        import time

        try:
            import nfc  # type: ignore[import-not-found]
        except ImportError as exc:
            raise TransportError("nfcpy is not installed (pip install 'sphragis[hw]')") from exc

        clf = nfc.ContactlessFrontend(path)
        try:
            deadline = time.monotonic() + timeout_s
            tag = clf.connect(
                rdwr={"on-connect": lambda tag: False},
                terminate=lambda: time.monotonic() > deadline,
            )
            if tag is None or not hasattr(tag, "transceive"):
                raise TransportError("no ISO-DEP (Type 4) tag found")
        except BaseException:
            clf.close()                   # release the reader on every failure
            raise
        return cls(tag, clf)

    @property
    def anticollision_uid(self) -> bytes | None:
        """UID the tag gave during anticollision (nfcpy `identifier`)."""
        uid = getattr(self._tag, "identifier", None)
        return None if uid is None else bytes(uid)

    def transceive(self, apdu: bytes) -> bytes:
        try:
            return bytes(self._tag.transceive(bytes(apdu)))
        except Exception as exc:  # nfcpy raises its own error hierarchy
            raise TransportError(f"PN532 exchange failed: {exc}") from exc

    def close(self) -> None:
        if self._clf is not None:
            self._clf.close()
            self._clf = None
