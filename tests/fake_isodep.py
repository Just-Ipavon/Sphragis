"""Test-only ISO 14443-4 card speaking raw blocks over an APDU handler."""


class FakeCard:
    """
    Minimal ISO 14443-4 card on top of an APDU handler, speaking raw blocks
    (CRC handled by the 'link'). Supports chaining both ways and can inject
    one S(WTX) before each response.
    """

    def __init__(self, handler, fsd=256, card_fsc_fsci=0x02, wtx=False):
        self.handler = handler
        self.fsd = fsd                      # what the card may send per frame
        self.fsci = card_fsc_fsci
        self.wtx = wtx
        self.rx = b""
        self.pending = []
        self.frames = []
        self.bn = 0
        self._wtx_due = False

    def exchange(self, frame):
        self.frames.append(frame)
        pcb = frame[0]
        if frame == b"\xE0\x80":
            return bytes([0x05, 0x70 | self.fsci, 0x80, 0x80, 0x00])
        if pcb & 0xF7 == 0xF2:                      # WTX acknowledged
            return self._next_out()
        if pcb & 0xE2 == 0x02:                      # I-block
            assert pcb & 1 == self.bn
            self.bn = (pcb & 1) ^ 1
            self.rx += frame[1:]
            if pcb & 0x10:
                return bytes([0xA2 | (pcb & 1)])
            resp = self.handler(self.rx)
            self.rx = b""
            max_inf = self.fsd - 3
            self.pending = [resp[i:i + max_inf] for i in range(0, len(resp), max_inf)]
            self._last_bn = pcb & 1
            if self.wtx:
                self._wtx_due = True
                return b"\xF2\x01"
            return self._next_out()
        if pcb & 0xF6 == 0xA2:                      # R(ACK) during our chaining
            assert pcb & 1 == self.bn
            self.bn = (pcb & 1) ^ 1
            self._last_bn = pcb & 1
            return self._next_out()
        raise AssertionError(f"unexpected block {frame.hex()}")

    def _next_out(self):
        chunk = self.pending.pop(0)
        more = 0x10 if self.pending else 0
        return bytes([0x02 | self._last_bn | more]) + chunk
