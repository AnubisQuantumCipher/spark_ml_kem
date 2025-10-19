pragma SPARK_Mode (On);

with Interfaces; use Interfaces;

--  ========================================================================
--  ML-KEM-1024 Compression Implementation
--  ========================================================================
--
--  **Implementation Strategy**:
--  - Use fixed-point arithmetic (no floating point)
--  - Rounding via (2x + 1)/2 pattern
--  - Long_Integer for intermediate calculations
--  - Constant-time operations (no secret-dependent branches)
--
--  **Key Insight**: Rounding ⌊x + 1/2⌋ = ⌊(2x + 1)/2⌋
--    This converts float rounding to integer division
--
--  ========================================================================

package body SparkPass.Crypto.MLKEM.Compression is

   --  ========================================================================
   --  Compress_d Implementation
   --  ========================================================================
   --
   --  **Mathematical Derivation**:
   --    Goal: y = ⌊(2^d / q) × x + 1/2⌋ mod 2^d
   --
   --    Step 1: Convert rounding to integer arithmetic
   --      ⌊a + 1/2⌋ = ⌊(2a + 1) / 2⌋
   --
   --    Step 2: Substitute a = (2^d / q) × x
   --      ⌊(2^d / q) × x + 1/2⌋ = ⌊(2 × (2^d / q) × x + 1) / 2⌋
   --                            = ⌊((2^(d+1) / q) × x + 1) / 2⌋
   --
   --    Step 3: Combine divisions
   --      = ⌊(2^(d+1) × x + q) / (2×q)⌋
   --
   --    Step 4: Apply modulo
   --      result = ⌊(2^(d+1) × x + q) / (2×q)⌋ mod 2^d
   --
   --  **Example** (d=5, x=1000, q=3329):
   --    numerator = 2^6 × 1000 + 3329 = 67329
   --    quotient = 67329 / 6658 = 10.11... → 10
   --    result = 10 mod 32 = 10
   --
   --  **Overflow Analysis**:
   --    Max numerator = 2^12 × 3328 + 3329 ≈ 13.6M
   --    Integer'Last ≈ 2.1B on 32-bit, 9.2×10^18 on 64-bit
   --    Safe: 13.6M << Integer'Last
   --
   --  ========================================================================

   function Compress_d (X : Coefficient; D : Positive) return Natural is
      --  Use Long_Integer to prevent overflow in exponentiation
      Numerator   : Long_Integer;
      Denominator : constant Long_Integer := 2 * Long_Integer(Q);
      Quotient    : Natural;
      Modulus     : constant Natural := 2**D;
   begin
      --  Step 1: Compute numerator = 2^(d+1) × x + q
      --  Use exponentiation instead of shift for Long_Integer
      Numerator := Long_Integer(X) * (2 ** (D + 1)) + Long_Integer(Q);

      --  Step 2: Divide by 2×q (rounding down)
      Quotient := Natural(Numerator / Denominator);

      --  Step 3: Take modulo 2^d
      return Quotient mod Modulus;
   end Compress_d;

   --  ========================================================================
   --  Decompress_d Implementation
   --  ========================================================================
   --
   --  **Mathematical Derivation**:
   --    Goal: x = ⌊(q / 2^d) × y + 1/2⌋
   --
   --    Step 1: Convert rounding to integer arithmetic
   --      ⌊a + 1/2⌋ = ⌊(2a + 1) / 2⌋
   --
   --    Step 2: Substitute a = (q / 2^d) × y
   --      ⌊(q / 2^d) × y + 1/2⌋ = ⌊((2q / 2^d) × y + 1) / 2⌋
   --                            = ⌊(q × y + 2^(d-1)) / 2^d⌋
   --
   --  **Example** (d=5, y=10, q=3329):
   --    numerator = 3329 × 10 + 2^4 = 33306
   --    quotient = 33306 / 32 = 1040.8... → 1040
   --    result = 1040 mod 3329 = 1040
   --
   --  **Overflow Analysis**:
   --    Max numerator = 3329 × 2047 + 1024 ≈ 6.8M
   --    Safe: 6.8M << Integer'Last
   --
   --  ========================================================================

   function Decompress_d (Y : Natural; D : Positive) return Coefficient is
      --  Use Long_Integer to prevent overflow
      Numerator : Long_Integer;
      Divisor   : Long_Integer;
      Quotient  : Integer;
   begin
      --  Step 1: Compute numerator = q × y + 2^(d-1)
      --  Use exponentiation instead of shift for Long_Integer
      Numerator := Long_Integer(Q) * Long_Integer(Y)
                   + Long_Integer(2 ** (D - 1));

      --  Step 2: Compute divisor = 2^d
      Divisor := Long_Integer(2 ** D);

      --  Step 3: Divide (rounding down)
      Quotient := Integer(Numerator / Divisor);

      --  Step 4: Reduce modulo q (should already be < q, but enforce contract)
      if Quotient >= Q then
         return Quotient mod Q;
      else
         return Quotient;
      end if;
   end Decompress_d;

   --  ========================================================================
   --  Polynomial Compression: Pack 256 coefficients into byte array
   --  ========================================================================
   --
   --  **Bit Packing Strategy**:
   --    - Each coefficient compressed to D bits
   --    - Pack sequentially in little-endian bit order
   --    - Total size = ⌈(256 × D) / 8⌉ bytes
   --
   --  **Example** (d=5, first 3 coefficients = [10, 22, 7]):
   --    Coefficient 0 (10 = 0b01010): bits [0..4]   of byte stream
   --    Coefficient 1 (22 = 0b10110): bits [5..9]   of byte stream
   --    Coefficient 2 (7  = 0b00111): bits [10..14] of byte stream
   --
   --    Byte 0: bits [0..7]   = 0bX1010_010  (parts of coeff 0 and 1)
   --    Byte 1: bits [8..15]  = 0b0111_10XX  (parts of coeff 1 and 2)
   --    ...
   --
   --  **Implementation**:
   --    Use bit buffer to accumulate bits across byte boundaries
   --
   --  ========================================================================

   procedure Compress_Poly (
      P : in Polynomial;
      D : in Positive;
      Output : out Byte_Array
   ) is
      Bit_Buffer : Unsigned_32 := 0;  -- Accumulator for bits
      Bit_Count  : Natural := 0;       -- Number of bits in buffer
      Byte_Index : Natural := Output'First;
      Compressed : Natural;
   begin
      --  Initialize output to zero
      Output := (others => 0);

      --  Process each coefficient
      for I in Polynomial'Range loop
         --  Compress coefficient to D bits
         Compressed := Compress_d(P(I), D);

         --  Add D bits to buffer
         Bit_Buffer := Bit_Buffer or Shift_Left(Unsigned_32(Compressed), Bit_Count);
         Bit_Count := Bit_Count + D;

         --  Flush complete bytes from buffer
         while Bit_Count >= 8 and then Byte_Index <= Output'Last loop
            Output(Byte_Index) := Unsigned_8(Bit_Buffer and 16#FF#);
            Bit_Buffer := Shift_Right(Bit_Buffer, 8);
            Bit_Count := Bit_Count - 8;
            Byte_Index := Byte_Index + 1;
         end loop;
      end loop;

      --  Flush remaining bits (partial byte)
      if Bit_Count > 0 and then Byte_Index <= Output'Last then
         Output(Byte_Index) := Unsigned_8(Bit_Buffer and 16#FF#);
      end if;
   end Compress_Poly;

   --  ========================================================================
   --  Polynomial Decompression: Unpack byte array to 256 coefficients
   --  ========================================================================

   procedure Decompress_Poly (
      Input : in Byte_Array;
      D : in Positive;
      P : out Polynomial
   ) is
      Bit_Buffer : Unsigned_32 := 0;  -- Accumulator for bits
      Bit_Count  : Natural := 0;       -- Number of bits in buffer
      Byte_Index : Natural := Input'First;
      Mask       : Unsigned_32;
      Compressed : Natural;
   begin
      --  Compute mask for D bits (2^D - 1)
      Mask := Shift_Left(1, D) - 1;

      --  Process each coefficient
      for I in Polynomial'Range loop
         --  Ensure buffer has at least D bits
         while Bit_Count < D and then Byte_Index <= Input'Last loop
            Bit_Buffer := Bit_Buffer or Shift_Left(Unsigned_32(Input(Byte_Index)), Bit_Count);
            Bit_Count := Bit_Count + 8;
            Byte_Index := Byte_Index + 1;
         end loop;

         --  Extract D bits
         Compressed := Natural(Bit_Buffer and Mask);

         --  Decompress to coefficient
         P(I) := Decompress_d(Compressed, D);

         --  Remove D bits from buffer
         Bit_Buffer := Shift_Right(Bit_Buffer, D);
         Bit_Count := Bit_Count - D;
      end loop;
   end Decompress_Poly;

   --  ========================================================================
   --  SPARK Verification Notes
   --  ========================================================================
   --
   --  **Proof Obligations**:
   --    1. No overflow in Long_Integer arithmetic
   --    2. Compress_d result < 2^D
   --    3. Decompress_d result < Q
   --    4. Array bounds respected in bit packing/unpacking
   --    5. Bit buffer operations don't overflow Unsigned_32
   --
   --  **Expected Results**:
   --    Bronze: All panic freedom checks proven
   --    Silver: Round-trip property: |Decompress(Compress(x)) - x| ≤ ε
   --    Platinum: Exact FIPS 203 compliance
   --
   --  **Potential Issues**:
   --    - Bit packing loop invariants may need manual annotations
   --    - Division by variable (Divisor) needs range proof
   --    - Unsigned_32 shifts need bit count bounds
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Compression;
