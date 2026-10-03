"""
tests/test_entropy.py — Unit tests for the entropy module.

Tests cover:
  - Shannon entropy calculation on known byte distributions.
  - Edge cases (empty data, single byte value, perfectly random).
"""

import math
import unittest

from analyzer.static.entropy import _shannon_entropy


class TestShannonEntropy(unittest.TestCase):
    """Test the _shannon_entropy helper function."""

    def test_empty_data(self):
        """Empty input should return entropy 0."""
        self.assertEqual(_shannon_entropy(b""), 0.0)

    def test_single_byte_value(self):
        """Data with all identical bytes should have entropy 0."""
        data = bytes([0xAA]) * 1000
        self.assertAlmostEqual(_shannon_entropy(data), 0.0, places=5)

    def test_two_equally_likely_values(self):
        """Two equally likely byte values should give entropy of 1.0.

        H = -(0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0
        """
        data = bytes([0x00, 0x01]) * 500
        self.assertAlmostEqual(_shannon_entropy(data), 1.0, places=3)

    def test_high_entropy(self):
        """Data with all 256 byte values equally distributed should
        have entropy close to 8.0."""
        # Each value appears exactly once → 256 values, each with p=1/256
        data = bytes(range(256)) * 100
        entropy = _shannon_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=2)

    def test_moderate_entropy(self):
        """English text typically has entropy around 3.5-5.0."""
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        entropy = _shannon_entropy(text)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 6.0)


if __name__ == "__main__":
    unittest.main()
