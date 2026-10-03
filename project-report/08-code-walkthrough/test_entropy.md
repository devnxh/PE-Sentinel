# Code Walkthrough: tests/test_entropy.py

- **Purpose**: Unit tests for Shannon entropy calculation.
- **Inputs**: Known byte distributions.
- **Outputs**: Test pass/fail.
- **Dependencies**: `math`, `unittest`, `analyzer.static.entropy._shannon_entropy`.
- **Callers**: `python -m unittest discover tests/`.
- **Callees**: `_shannon_entropy()`.

---

## Lines 1-7: Module docstring

Documents coverage: known distributions and edge cases.

## Lines 9-12: Imports

```python
import math
import unittest

from analyzer.static.entropy import _shannon_entropy
```

Imports the private function directly for unit testing. `math` is imported but unused in the test file.

## Lines 15-48: TestShannonEntropy class

Five test methods covering edge cases and expected entropy ranges:

```python
    def test_empty_data(self):
        self.assertEqual(_shannon_entropy(b""), 0.0)
```
Empty input returns 0. Verifies the guard at `entropy.py:73-74`.

```python
    def test_single_byte_value(self):
        data = bytes([0xAA]) * 1000
        self.assertAlmostEqual(_shannon_entropy(data), 0.0, places=5)
```
All identical bytes = zero entropy. Uses `assertAlmostEqual` for floating-point comparison.

```python
    def test_two_equally_likely_values(self):
        data = bytes([0x00, 0x01]) * 500
        self.assertAlmostEqual(_shannon_entropy(data), 1.0, places=3)
```
Two equiprobable values: H = -(0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0. The docstring shows the math.

```python
    def test_high_entropy(self):
        data = bytes(range(256)) * 100
        entropy = _shannon_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=2)
```
All 256 byte values equally distributed: maximum entropy of 8.0 bits.

```python
    def test_moderate_entropy(self):
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        entropy = _shannon_entropy(text)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 6.0)
```
English text has entropy around 3.5-5.0. Uses range assertion rather than exact value.

## Lines 51-52: Entry point

```python
if __name__ == "__main__":
    unittest.main()
```

Allows running the test file directly.
