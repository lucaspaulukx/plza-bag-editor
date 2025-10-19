class SCXorShift32:
    """
    Self-mutating value that returns a crypto value to be xor-ed with another (unaligned) byte stream.
    This implementation allows for yielding crypto bytes on demand.
    """

    def __init__(self, seed: int):
        self.counter = 0
        self.state = self._get_initial_state(seed)

    @staticmethod
    def _get_initial_state(state: int) -> int:
        """Get initial state based on seed."""
        pop_count = bin(state).count('1')
        for _ in range(pop_count):
            state = SCXorShift32._xorshift_advance(state)
        return state

    def next(self) -> int:
        """Gets a byte from the current state."""
        c = self.counter
        result = (self.state >> (c << 3)) & 0xFF
        if c == 3:
            self.state = self._xorshift_advance(self.state)
            self.counter = 0
        else:
            self.counter += 1
        return result

    def next32(self) -> int:
        """Gets a 32-bit integer from the current state."""
        return self.next() | (self.next() << 8) | (self.next() << 16) | (self.next() << 24)

    @staticmethod
    def _xorshift_advance(state: int) -> int:
        """Advance the xorshift state."""
        state ^= state << 2
        state &= 0xFFFFFFFF  # Keep it 32-bit
        state ^= state >> 15
        state ^= state << 13
        state &= 0xFFFFFFFF  # Keep it 32-bit
        return state