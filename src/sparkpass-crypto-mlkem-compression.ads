pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;
with SparkPass.Types; use SparkPass.Types;

--  ========================================================================
--  ML-KEM-1024 Compression and Decompression (NIST FIPS 203)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4.2.1 (Compression and Decompression)
--              Algorithm 4 (Compress)
--              Algorithm 5 (Decompress)
--
--  **Purpose**: Reduce bandwidth for public key and ciphertext transmission
--
--  **Mathematical Foundation**:
--  - Compress_d:   Maps Z_q to {0, ..., 2^d - 1} with minimal distortion
--  - Decompress_d: Approximate inverse, maps {0, ..., 2^d - 1} back to Z_q
--
--  **Compression Parameters (ML-KEM-1024)**:
--  - d_u = 11: Compression factor for ciphertext u components
--  - d_v = 5:  Compression factor for ciphertext v component
--  - q = 3329: Modulus
--
--  **Algorithms**:
--
--  Compress_d(x):
--    Input: Integer x ∈ [0, q-1], integer d ∈ {1, ..., 11}
--    Output: Integer y ∈ [0, 2^d - 1]
--    Algorithm: y = ⌊(2^d / q) · x + 1/2⌋ mod 2^d
--
--    Example (d=5, x=1000):
--      Scale = 2^5 / 3329 ≈ 0.00961
--      Scaled = 0.00961 × 1000 = 9.61
--      Rounded = ⌊9.61 + 0.5⌋ = ⌊10.11⌋ = 10
--      Result = 10 mod 32 = 10
--
--  Decompress_d(y):
--    Input: Integer y ∈ [0, 2^d - 1], integer d ∈ {1, ..., 11}
--    Output: Integer x ∈ [0, q-1]
--    Algorithm: x = ⌊(q / 2^d) · y + 1/2⌋
--
--    Example (d=5, y=10):
--      Scale = 3329 / 2^5 = 104.03125
--      Scaled = 104.03125 × 10 = 1040.3125
--      Rounded = ⌊1040.3125 + 0.5⌋ = ⌊1040.8125⌋ = 1040
--      Result = 1040 (close to original 1000)
--
--  **Properties**:
--  - Compress is a lossy operation (not injective)
--  - Decompress(Compress(x)) ≈ x (close but not exact)
--  - Error: |Decompress(Compress(x)) - x| ≤ q / (2^(d+1))
--  - For d_u=11: max error ≤ 3329 / 4096 ≈ 0.81 coefficient
--  - For d_v=5:  max error ≤ 3329 / 64 ≈ 52 coefficient
--
--  **Implementation Strategy**:
--  - Use fixed-point arithmetic to avoid floating point
--  - Rounding: ⌊x + 1/2⌋ = ⌊2x + 1⌋ / 2 (integer division)
--  - Scaling: (2^d / q) × x = (2^d × x) / q
--  - Combined: ⌊(2^(d+1) × x + q) / (2×q)⌋ mod 2^d
--
--  **Overflow Prevention**:
--  - Max intermediate: (2^12 × 3328 + 3329) ≈ 13.6 million (fits in Integer)
--  - Use Long_Integer for intermediate calculations
--  - Final result always fits in range [0, 2^d - 1]
--
--  **Constant-Time Guarantees**:
--  - No secret-dependent branches
--  - No secret-dependent memory access
--  - Division by constants (compiler optimizes to shifts/multiplies)
--  - Modulo by powers of 2 (implemented as bitwise AND)
--
--  **SPARK Verification**:
--  - Bronze: Prove no overflow, all results in valid ranges
--  - Silver: Prove round-trip error bounds
--  - Platinum: Prove exact FIPS 203 compliance
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.Compression is
   

   --  Compression parameters for ML-KEM-1024
   D_U : constant := 11;  -- Ciphertext u compression (11 bits)
   D_V : constant := 5;   -- Ciphertext v compression (5 bits)

   --  ========================================================================
   --  Compress_d: Coefficient Compression (FIPS 203 Algorithm 4)
   --  ========================================================================
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 4):
   --    Input: x ∈ Z_q, d ∈ {1, ..., 11}
   --    Output: y ∈ {0, ..., 2^d - 1}
   --
   --    y ← ⌊(2^d / q) × x + 1/2⌋ mod 2^d
   --    return y
   --
   --  **Fixed-Point Implementation**:
   --    numerator = (2^(d+1) × x + q)
   --    y = (numerator / (2×q)) mod 2^d
   --
   --  **Example Calculation** (d=5, x=1000):
   --    numerator = (2^6 × 1000 + 3329) = 64000 + 3329 = 67329
   --    quotient = 67329 / 6658 = 10.11 → 10
   --    result = 10 mod 32 = 10 ✓
   --
   --  **Complexity**: O(1) - constant time
   --  **Precision**: Exact integer rounding (no floating point error)
   --
   --  ========================================================================

   function Compress_d (X : Coefficient; D : Positive) return Natural with
      Global => null,
      Pre    => D <= 11,
      Post   => Compress_d'Result < 2**D;
   --  **Purpose**: Compress coefficient X to D bits
   --  **Input**: X - coefficient in [0, Q-1], D - compression bits
   --  **Output**: Compressed value in [0, 2^D - 1]
   --  **Usage**: Called during encoding of public key and ciphertext

   --  ========================================================================
   --  Decompress_d: Coefficient Decompression (FIPS 203 Algorithm 5)
   --  ========================================================================
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 5):
   --    Input: y ∈ {0, ..., 2^d - 1}, d ∈ {1, ..., 11}
   --    Output: x ∈ Z_q
   --
   --    x ← ⌊(q / 2^d) × y + 1/2⌋
   --    return x mod q
   --
   --  **Fixed-Point Implementation**:
   --    numerator = q × y + 2^(d-1)
   --    x = (numerator / 2^d) mod q
   --
   --  **Example Calculation** (d=5, y=10):
   --    numerator = 3329 × 10 + 2^4 = 33290 + 16 = 33306
   --    quotient = 33306 / 32 = 1040.8 → 1040
   --    result = 1040 mod 3329 = 1040 ✓
   --
   --  **Complexity**: O(1) - constant time
   --  **Precision**: Exact integer rounding (no floating point error)
   --
   --  ========================================================================

   function Decompress_d (Y : Natural; D : Positive) return Coefficient with
      Global => null,
      Pre    => D <= 11 and then Y < 2**D,
      Post   => Decompress_d'Result in 0 .. Q - 1;
   --  **Purpose**: Decompress D-bit value Y back to coefficient
   --  **Input**: Y - compressed value in [0, 2^D - 1], D - compression bits
   --  **Output**: Decompressed coefficient in [0, Q-1]
   --  **Usage**: Called during decoding of public key and ciphertext

   --  ========================================================================
   --  Polynomial-Level Compression (Convenience Functions)
   --  ========================================================================

   procedure Compress_Poly (
      P : in Polynomial;
      D : in Positive;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => D <= 11 and then
                Output'Length = ((256 * D + 7) / 8),
      Post   => True;
   --  **Purpose**: Compress entire polynomial to byte array
   --  **Input**: P - polynomial, D - compression bits
   --  **Output**: Packed bit representation
   --  **Packing**: Coefficients packed sequentially in little-endian

   procedure Decompress_Poly (
      Input : in Byte_Array;
      D : in Positive;
      P : out Polynomial
   ) with
      Global => null,
      Pre    => D <= 11 and then
                Input'Length = ((256 * D + 7) / 8),
      Post   => (for all I in Polynomial'Range => P(I) in 0 .. Q - 1);
   --  **Purpose**: Decompress byte array to polynomial
   --  **Input**: Packed bit representation, D - compression bits
   --  **Output**: P - decompressed polynomial
   --  **Unpacking**: Little-endian bit extraction

   --  ========================================================================
   --  Implementation Notes
   --  ========================================================================
   --
   --  **Bit Packing Format**:
   --    For d=5 (5 bits/coefficient, 256 coefficients):
   --      Total bits = 256 × 5 = 1280 bits = 160 bytes
   --      Coefficient 0: bits [0..4]
   --      Coefficient 1: bits [5..9]
   --      Coefficient 2: bits [10..14]
   --      ...
   --
   --    For d=11 (11 bits/coefficient, 256 coefficients):
   --      Total bits = 256 × 11 = 2816 bits = 352 bytes
   --
   --  **Endianness**: Little-endian (LSB first)
   --    Example: Value 0b10110 (22) in 5-bit field
   --      Byte 0, bits [0..4]: 0b00010110 (LSB to MSB)
   --
   --  **Overflow Safety**:
   --    Compress:   Max = (2^12 × 3328 + 3329) ≈ 13.6M < Integer'Last
   --    Decompress: Max = (3329 × 2047 + 1024) ≈ 6.8M < Integer'Last
   --
   --  **Verification Strategy**:
   --    1. Prove all intermediate values fit in Integer/Long_Integer
   --    2. Prove final results within specified ranges
   --    3. Prove round-trip error bounds: |Decompress(Compress(x)) - x| ≤ ε
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Compression;
