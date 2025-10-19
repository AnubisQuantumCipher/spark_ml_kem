--  ========================================================================
--  SparkPass ML-KEM Encoding/Decoding Implementation
--  ========================================================================

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;

package body SparkPass.Crypto.MLKEM.Encoding is

   --  =====================================================================
   --  ByteEncode_12: Encode polynomial with 12 bits per coefficient
   --  =====================================================================
   --
   --  **Bit-Packing Pattern** (every 3 bytes encodes 2 coefficients):
   --    Byte 0: [coeff[0]₇..coeff[0]₀]
   --    Byte 1: [coeff[1]₃..coeff[1]₀ coeff[0]₁₁..coeff[0]₈]
   --    Byte 2: [coeff[1]₁₁..coeff[1]₄]
   --
   --  **Loop Structure**: Process 2 coefficients per iteration (128 iterations)
   --  =====================================================================

   procedure ByteEncode_12 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) is
      Coeff_0, Coeff_1 : Coefficient;
      Byte_Pos : Positive;
   begin
      --  Process pairs of coefficients
      for I in 0 .. 127 loop
         pragma Loop_Invariant (Output'First = 1);
         pragma Loop_Invariant (Output'Last = Bytes_Per_Poly_12);

         --  Get two coefficients
         Coeff_0 := Poly(2 * I);
         Coeff_1 := Poly(2 * I + 1);

         --  Calculate byte position (3 bytes per 2 coefficients)
         Byte_Pos := 1 + (3 * I);

         --  Encode coeff_0 and coeff_1 into 3 bytes
         --  Byte 0: Low 8 bits of coeff_0 (a[0:7])
         Output(Byte_Pos) := U8(Unsigned_16(Coeff_0) and 16#FF#);

         --  Byte 1: FIPS 203: ⌊a[i]/256⌋ + 16·(a[i+1] mod 16)
         --  Low nibble (bits 0-3): high 4 bits of coeff_0 (⌊Coeff_0/256⌋)
         --  High nibble (bits 4-7): low 4 bits of coeff_1 (16·(Coeff_1 mod 16))
         Output(Byte_Pos + 1) := U8((Unsigned_16(Coeff_0) / 256) or
                                     ((Unsigned_16(Coeff_1) and 16#0F#) * 16));

         --  Byte 2: High 8 bits of coeff_1 (b[4:11])
         Output(Byte_Pos + 2) := U8((Unsigned_16(Coeff_1) / 16) and 16#FF#);
      end loop;
   end ByteEncode_12;

   --  =====================================================================
   --  ByteDecode_12: Decode polynomial from 12-bit encoding
   --  =====================================================================

   procedure ByteDecode_12 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) is
      Byte_0, Byte_1, Byte_2 : U8;
      Coeff_0, Coeff_1 : Coefficient;
      Byte_Pos : Positive;
   begin
      --  Initialize polynomial
      Poly := Zero_Polynomial;

      --  Process pairs of coefficients
      for I in 0 .. 127 loop
         pragma Loop_Invariant (Input'First = 1);
         pragma Loop_Invariant (Input'Last = Bytes_Per_Poly_12);

         --  Calculate byte position
         Byte_Pos := 1 + (3 * I);

         --  Read 3 bytes
         Byte_0 := Input(Byte_Pos);
         Byte_1 := Input(Byte_Pos + 1);
         Byte_2 := Input(Byte_Pos + 2);

         --  Decode coeff_0: a[0:7] from byte_0, a[8:11] from LOW nibble of byte_1
         --  FIPS 203: Extract ⌊a[i]/256⌋ from low nibble
         Coeff_0 := Coefficient(Unsigned_16(Byte_0) or
                                ((Unsigned_16(Byte_1 and 16#0F#)) * 256));

         --  Decode coeff_1: b[0:3] from HIGH nibble of byte_1, b[4:11] from byte_2
         --  FIPS 203: Extract (a[i+1] mod 16) from high nibble
         Coeff_1 := Coefficient((Unsigned_16(Byte_1) / 16) or
                                (Unsigned_16(Byte_2) * 16));

         --  Modular reduction to ensure coefficient < q
         Poly(2 * I) := Coeff_0 mod Q;
         Poly(2 * I + 1) := Coeff_1 mod Q;
      end loop;
   end ByteDecode_12;

   --  =====================================================================
   --  ByteEncode_10: Encode polynomial with 10 bits per coefficient
   --  =====================================================================
   --
   --  **Bit-Packing Pattern** (every 5 bytes encodes 4 coefficients):
   --    256 coeffs × 10 bits = 2560 bits = 320 bytes
   --    Process 4 coefficients per iteration (64 iterations)
   --  =====================================================================

   procedure ByteEncode_10 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) is
      C0, C1, C2, C3 : Coefficient;
      Byte_Pos : Positive;
      Temp : Unsigned_64;
   begin
      --  Process 4 coefficients per iteration
      for I in 0 .. 63 loop
         pragma Loop_Invariant (Output'First = 1);
         pragma Loop_Invariant (Output'Last = Bytes_Per_Poly_10);

         --  Get 4 coefficients
         C0 := Poly(4 * I);
         C1 := Poly(4 * I + 1);
         C2 := Poly(4 * I + 2);
         C3 := Poly(4 * I + 3);

         --  Calculate byte position (5 bytes per 4 coefficients)
         Byte_Pos := 1 + (5 * I);

         --  Pack 4 × 10-bit values into 5 bytes
         --  Use 40-bit intermediate to avoid overflow
         Temp := Unsigned_64(C0) or
                 (Unsigned_64(C1) * 2**10) or
                 (Unsigned_64(C2) * 2**20) or
                 (Unsigned_64(C3) * 2**30);

         Output(Byte_Pos)     := U8(Temp and 16#FF#);
         Output(Byte_Pos + 1) := U8((Temp / 2**8) and 16#FF#);
         Output(Byte_Pos + 2) := U8((Temp / 2**16) and 16#FF#);
         Output(Byte_Pos + 3) := U8((Temp / 2**24) and 16#FF#);
         Output(Byte_Pos + 4) := U8((Temp / 2**32) and 16#FF#);
      end loop;
   end ByteEncode_10;

   --  =====================================================================
   --  ByteDecode_10: Decode polynomial from 10-bit encoding
   --  =====================================================================

   procedure ByteDecode_10 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) is
      B0, B1, B2, B3, B4 : U8;
      Byte_Pos : Positive;
      Temp : Unsigned_64;
   begin
      --  Initialize polynomial
      Poly := Zero_Polynomial;

      --  Process 4 coefficients per iteration
      for I in 0 .. 63 loop
         pragma Loop_Invariant (Input'First = 1);
         pragma Loop_Invariant (Input'Last = Bytes_Per_Poly_10);

         --  Calculate byte position
         Byte_Pos := 1 + (5 * I);

         --  Read 5 bytes
         B0 := Input(Byte_Pos);
         B1 := Input(Byte_Pos + 1);
         B2 := Input(Byte_Pos + 2);
         B3 := Input(Byte_Pos + 3);
         B4 := Input(Byte_Pos + 4);

         --  Reconstruct 40-bit value
         Temp := Unsigned_64(B0) or
                 (Unsigned_64(B1) * 2**8) or
                 (Unsigned_64(B2) * 2**16) or
                 (Unsigned_64(B3) * 2**24) or
                 (Unsigned_64(B4) * 2**32);

         --  Extract 4 × 10-bit coefficients
         Poly(4 * I)     := Coefficient(Temp and 16#3FF#);
         Poly(4 * I + 1) := Coefficient((Temp / 2**10) and 16#3FF#);
         Poly(4 * I + 2) := Coefficient((Temp / 2**20) and 16#3FF#);
         Poly(4 * I + 3) := Coefficient((Temp / 2**30) and 16#3FF#);
      end loop;
   end ByteDecode_10;

   --  =====================================================================
   --  ByteEncode_4: Encode polynomial with 4 bits per coefficient
   --  =====================================================================
   --
   --  **Bit-Packing Pattern** (1 byte encodes 2 coefficients):
   --    256 coeffs × 4 bits = 1024 bits = 128 bytes
   --  =====================================================================

   procedure ByteEncode_4 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) is
      Coeff_0, Coeff_1 : Coefficient;
      Byte_Pos : Positive;
   begin
      --  Process pairs of coefficients
      for I in 0 .. 127 loop
         pragma Loop_Invariant (Output'First = 1);
         pragma Loop_Invariant (Output'Last = Bytes_Per_Poly_4);

         --  Get two coefficients
         Coeff_0 := Poly(2 * I);
         Coeff_1 := Poly(2 * I + 1);

         --  Calculate byte position
         Byte_Pos := 1 + I;

         --  Pack 2 × 4-bit values into 1 byte
         --  Low nibble: coeff_0, High nibble: coeff_1
         Output(Byte_Pos) := U8((Unsigned_16(Coeff_0) and 16#0F#) or
                                ((Unsigned_16(Coeff_1) and 16#0F#) * 16));
      end loop;
   end ByteEncode_4;

   --  =====================================================================
   --  ByteDecode_4: Decode polynomial from 4-bit encoding
   --  =====================================================================

   procedure ByteDecode_4 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) is
      Byte_Val : U8;
      Byte_Pos : Positive;
   begin
      --  Initialize polynomial
      Poly := Zero_Polynomial;

      --  Process pairs of coefficients
      for I in 0 .. 127 loop
         pragma Loop_Invariant (Input'First = 1);
         pragma Loop_Invariant (Input'Last = Bytes_Per_Poly_4);

         --  Calculate byte position
         Byte_Pos := 1 + I;

         --  Read byte
         Byte_Val := Input(Byte_Pos);

         --  Extract 2 × 4-bit coefficients
         Poly(2 * I)     := Coefficient(Byte_Val and 16#0F#);
         Poly(2 * I + 1) := Coefficient(Byte_Val / 16);
      end loop;
   end ByteDecode_4;

   --  =====================================================================
   --  Compress_10: Compress coefficient to 10 bits
   --  =====================================================================
   --
   --  **Formula**: ⌈(2^10 / q) × x⌋ mod 2^10
   --  **Expanded**: ⌈(1024 / 3329) × x⌋ mod 1024
   --  **Rounding**: ((1024 × x + q/2) / q) mod 1024
   --  =====================================================================

   function Compress_10 (X : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(X) * 1024 + 1664) / 3329;
   begin
      return Coefficient(Temp mod 1024);
   end Compress_10;

   --  =====================================================================
   --  Compress_4: Compress coefficient to 4 bits
   --  =====================================================================

   function Compress_4 (X : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(X) * 16 + 1664) / 3329;
   begin
      return Coefficient(Temp mod 16);
   end Compress_4;

   --  =====================================================================
   --  Decompress_10: Decompress coefficient from 10 bits
   --  =====================================================================
   --
   --  **Formula**: ⌈(q / 2^10) × y⌋
   --  **Expanded**: ⌈(3329 / 1024) × y⌋
   --  **Rounding**: (3329 × y + 512) / 1024
   --  =====================================================================

   function Decompress_10 (Y : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(Y) * 3329 + 512) / 1024;
   begin
      return Coefficient(Temp mod Q);
   end Decompress_10;

   --  =====================================================================
   --  Decompress_4: Decompress coefficient from 4 bits
   --  =====================================================================

   function Decompress_4 (Y : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(Y) * 3329 + 8) / 16;
   begin
      return Coefficient(Temp mod Q);
   end Decompress_4;

   --  =====================================================================
   --  Encode_Vector_12: Encode 4-vector with 12 bits per coefficient
   --  =====================================================================

   procedure Encode_Vector_12 (
      Vec    : in Polynomial_Vector;
      Output : out Byte_Array
   ) is
      Offset : Positive := 1;
   begin
      --  Encode each polynomial in the vector
      for I in 0 .. K - 1 loop
         pragma Loop_Invariant (Output'First = 1);
         pragma Loop_Invariant (Output'Last = Bytes_Per_Vector_12);
         pragma Loop_Invariant (Offset = 1 + (I * Bytes_Per_Poly_12));

         declare
            Poly_Bytes : Byte_Array(1 .. Bytes_Per_Poly_12);
         begin
            ByteEncode_12(Vec(I), Poly_Bytes);

            --  Copy to output
            for J in Poly_Bytes'Range loop
               Output(Offset + J - 1) := Poly_Bytes(J);
            end loop;
         end;

         Offset := Offset + Bytes_Per_Poly_12;
      end loop;
   end Encode_Vector_12;

   --  =====================================================================
   --  Decode_Vector_12: Decode byte array to 4-vector
   --  =====================================================================

   procedure Decode_Vector_12 (
      Input : in Byte_Array;
      Vec   : out Polynomial_Vector
   ) is
      Offset : Positive := 1;
   begin
      --  Initialize vector
      Vec := (others => Zero_Polynomial);

      --  Decode each polynomial in the vector
      for I in 0 .. K - 1 loop
         pragma Loop_Invariant (Input'First = 1);
         pragma Loop_Invariant (Input'Last = Bytes_Per_Vector_12);
         pragma Loop_Invariant (Offset = 1 + (I * Bytes_Per_Poly_12));

         declare
            Poly_Bytes : Byte_Array(1 .. Bytes_Per_Poly_12);
         begin
            --  Extract bytes for this polynomial
            for J in Poly_Bytes'Range loop
               Poly_Bytes(J) := Input(Offset + J - 1);
            end loop;

            ByteDecode_12(Poly_Bytes, Vec(I));
         end;

         Offset := Offset + Bytes_Per_Poly_12;
      end loop;
   end Decode_Vector_12;

   --  =====================================================================
   --  Encode_Vector_10: Encode 4-vector with 10 bits per coefficient
   --  =====================================================================

   procedure Encode_Vector_10 (
      Vec    : in Polynomial_Vector;
      Output : out Byte_Array
   ) is
      Offset : Positive := 1;
   begin
      --  Encode each polynomial in the vector
      for I in 0 .. K - 1 loop
         pragma Loop_Invariant (Output'First = 1);
         pragma Loop_Invariant (Output'Last = Bytes_Per_Vector_10);
         pragma Loop_Invariant (Offset = 1 + (I * Bytes_Per_Poly_10));

         declare
            Poly_Bytes : Byte_Array(1 .. Bytes_Per_Poly_10);
         begin
            ByteEncode_10(Vec(I), Poly_Bytes);

            --  Copy to output
            for J in Poly_Bytes'Range loop
               Output(Offset + J - 1) := Poly_Bytes(J);
            end loop;
         end;

         Offset := Offset + Bytes_Per_Poly_10;
      end loop;
   end Encode_Vector_10;

   --  =====================================================================
   --  Decode_Vector_10: Decode byte array to 4-vector
   --  =====================================================================

   procedure Decode_Vector_10 (
      Input : in Byte_Array;
      Vec   : out Polynomial_Vector
   ) is
      Offset : Positive := 1;
   begin
      --  Initialize vector
      Vec := (others => Zero_Polynomial);

      --  Decode each polynomial in the vector
      for I in 0 .. K - 1 loop
         pragma Loop_Invariant (Input'First = 1);
         pragma Loop_Invariant (Input'Last = Bytes_Per_Vector_10);
         pragma Loop_Invariant (Offset = 1 + (I * Bytes_Per_Poly_10));

         declare
            Poly_Bytes : Byte_Array(1 .. Bytes_Per_Poly_10);
         begin
            --  Extract bytes for this polynomial
            for J in Poly_Bytes'Range loop
               Poly_Bytes(J) := Input(Offset + J - 1);
            end loop;

            ByteDecode_10(Poly_Bytes, Vec(I));
         end;

         Offset := Offset + Bytes_Per_Poly_10;
      end loop;
   end Decode_Vector_10;

   --  =====================================================================
   --  ML-KEM-1024 Encoding: 11-bit and 5-bit Functions
   --  =====================================================================

   --  =====================================================================
   --  Compress_11: Compress coefficient to 11 bits (ML-KEM-1024)
   --  =====================================================================

   function Compress_11 (X : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(X) * 2048 + 1664) / 3329;
   begin
      return Coefficient(Temp mod 2048);
   end Compress_11;

   --  =====================================================================
   --  Decompress_11: Decompress coefficient from 11 bits
   --  =====================================================================

   function Decompress_11 (Y : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(Y) * 3329 + 1024) / 2048;
   begin
      return Coefficient(Temp mod Q);
   end Decompress_11;

   --  =====================================================================
   --  Compress_5: Compress coefficient to 5 bits (ML-KEM-1024)
   --  =====================================================================

   function Compress_5 (X : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(X) * 32 + 1664) / 3329;
   begin
      return Coefficient(Temp mod 32);
   end Compress_5;

   --  =====================================================================
   --  Decompress_5: Decompress coefficient from 5 bits
   --  =====================================================================

   function Decompress_5 (Y : Coefficient) return Coefficient is
      Temp : constant Unsigned_32 := (Unsigned_32(Y) * 3329 + 16) / 32;
   begin
      return Coefficient(Temp mod Q);
   end Decompress_5;

   --  =====================================================================
   --  ByteEncode_11: Encode polynomial with 11 bits per coefficient
   --  =====================================================================
   --  Simple sequential bit-packing: treat output as bit stream
   --  256 coeffs × 11 bits = 2816 bits = 352 bytes
   --  =====================================================================

   procedure ByteEncode_11 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) is
      Bit_Pos : Natural := 0;  -- Current bit position in output
   begin
      Output := (others => 0);

      for I in 0 .. 255 loop
         declare
            Val : constant Unsigned_16 := Unsigned_16(Poly(I));
            Byte_Offset : constant Natural := Bit_Pos / 8;
            Bit_Offset  : constant Natural := Bit_Pos mod 8;
         begin
            --  Write 11 bits starting at Bit_Pos
            if Bit_Offset + 11 <= 8 then
               --  Fits entirely in one byte
               Output(Byte_Offset + 1) := Output(Byte_Offset + 1) or
                  U8((Val and 16#7FF#) * 2**Bit_Offset);
            elsif Bit_Offset + 11 <= 16 then
               --  Spans two bytes
               Output(Byte_Offset + 1) := Output(Byte_Offset + 1) or
                  U8((Val * 2**Bit_Offset) and 16#FF#);
               Output(Byte_Offset + 2) := Output(Byte_Offset + 2) or
                  U8((Val / 2**(8 - Bit_Offset)) and 16#FF#);
            else
               --  Spans three bytes
               Output(Byte_Offset + 1) := Output(Byte_Offset + 1) or
                  U8((Val * 2**Bit_Offset) and 16#FF#);
               Output(Byte_Offset + 2) := Output(Byte_Offset + 2) or
                  U8((Val / 2**(8 - Bit_Offset)) and 16#FF#);
               Output(Byte_Offset + 3) := Output(Byte_Offset + 3) or
                  U8((Val / 2**(16 - Bit_Offset)) and 16#FF#);
            end if;

            Bit_Pos := Bit_Pos + 11;
         end;
      end loop;
   end ByteEncode_11;

   --  =====================================================================
   --  ByteDecode_11: Decode polynomial from 11-bit encoding
   --  =====================================================================

   procedure ByteDecode_11 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) is
      Bit_Pos : Natural := 0;
   begin
      Poly := Zero_Polynomial;

      for I in 0 .. 255 loop
         declare
            Byte_Offset : constant Natural := Bit_Pos / 8;
            Bit_Offset  : constant Natural := Bit_Pos mod 8;
            Val : Unsigned_32;
         begin
            --  Read 11 bits starting at Bit_Pos
            if Bit_Offset + 11 <= 8 then
               --  Fits entirely in one byte
               Val := Unsigned_32(Input(Byte_Offset + 1) / 2**Bit_Offset) and 16#7FF#;
            elsif Bit_Offset + 11 <= 16 then
               --  Spans two bytes
               Val := Unsigned_32(Input(Byte_Offset + 1) / 2**Bit_Offset) or
                      (Unsigned_32(Input(Byte_Offset + 2)) * 2**(8 - Bit_Offset));
               Val := Val and 16#7FF#;
            else
               --  Spans three bytes
               Val := Unsigned_32(Input(Byte_Offset + 1) / 2**Bit_Offset) or
                      (Unsigned_32(Input(Byte_Offset + 2)) * 2**(8 - Bit_Offset)) or
                      (Unsigned_32(Input(Byte_Offset + 3)) * 2**(16 - Bit_Offset));
               Val := Val and 16#7FF#;
            end if;

            Poly(I) := Coefficient(Val);
            Bit_Pos := Bit_Pos + 11;
         end;
      end loop;
   end ByteDecode_11;

   --  =====================================================================
   --  ByteEncode_5: Encode polynomial with 5 bits per coefficient
   --  =====================================================================
   --  8 coefficients encode to 5 bytes (8 × 5 = 40 bits = 5 bytes)
   --  =====================================================================

   procedure ByteEncode_5 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) is
      Temp : Unsigned_64;
      Byte_Pos : Positive;
   begin
      --  Process 8 coefficients per iteration (32 iterations)
      for I in 0 .. 31 loop
         Byte_Pos := 1 + (5 * I);

         --  Pack 8 × 5-bit values into 5 bytes
         Temp := Unsigned_64(Poly(8 * I)) or
                 (Unsigned_64(Poly(8 * I + 1)) * 2**5) or
                 (Unsigned_64(Poly(8 * I + 2)) * 2**10) or
                 (Unsigned_64(Poly(8 * I + 3)) * 2**15) or
                 (Unsigned_64(Poly(8 * I + 4)) * 2**20) or
                 (Unsigned_64(Poly(8 * I + 5)) * 2**25) or
                 (Unsigned_64(Poly(8 * I + 6)) * 2**30) or
                 (Unsigned_64(Poly(8 * I + 7)) * 2**35);

         Output(Byte_Pos)     := U8(Temp and 16#FF#);
         Output(Byte_Pos + 1) := U8((Temp / 2**8) and 16#FF#);
         Output(Byte_Pos + 2) := U8((Temp / 2**16) and 16#FF#);
         Output(Byte_Pos + 3) := U8((Temp / 2**24) and 16#FF#);
         Output(Byte_Pos + 4) := U8((Temp / 2**32) and 16#FF#);
      end loop;
   end ByteEncode_5;

   --  =====================================================================
   --  ByteDecode_5: Decode polynomial from 5-bit encoding
   --  =====================================================================

   procedure ByteDecode_5 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) is
      Temp : Unsigned_64;
      Byte_Pos : Positive;
   begin
      Poly := Zero_Polynomial;

      --  Process 8 coefficients per iteration
      for I in 0 .. 31 loop
         Byte_Pos := 1 + (5 * I);

         --  Read 5 bytes
         Temp := Unsigned_64(Input(Byte_Pos)) or
                 (Unsigned_64(Input(Byte_Pos + 1)) * 2**8) or
                 (Unsigned_64(Input(Byte_Pos + 2)) * 2**16) or
                 (Unsigned_64(Input(Byte_Pos + 3)) * 2**24) or
                 (Unsigned_64(Input(Byte_Pos + 4)) * 2**32);

         --  Extract 8 × 5-bit coefficients
         Poly(8 * I)     := Coefficient(Temp and 16#1F#);
         Poly(8 * I + 1) := Coefficient((Temp / 2**5) and 16#1F#);
         Poly(8 * I + 2) := Coefficient((Temp / 2**10) and 16#1F#);
         Poly(8 * I + 3) := Coefficient((Temp / 2**15) and 16#1F#);
         Poly(8 * I + 4) := Coefficient((Temp / 2**20) and 16#1F#);
         Poly(8 * I + 5) := Coefficient((Temp / 2**25) and 16#1F#);
         Poly(8 * I + 6) := Coefficient((Temp / 2**30) and 16#1F#);
         Poly(8 * I + 7) := Coefficient((Temp / 2**35) and 16#1F#);
      end loop;
   end ByteDecode_5;

   --  =====================================================================
   --  Encode_Vector_11: Encode 4-vector with 11 bits per coefficient
   --  =====================================================================

   procedure Encode_Vector_11 (
      Vec    : in Polynomial_Vector;
      Output : out Byte_Array
   ) is
      Offset : Positive := 1;
   begin
      for I in 0 .. K - 1 loop
         declare
            Poly_Bytes : Byte_Array(1 .. Bytes_Per_Poly_11);
         begin
            ByteEncode_11(Vec(I), Poly_Bytes);

            for J in Poly_Bytes'Range loop
               Output(Offset + J - 1) := Poly_Bytes(J);
            end loop;
         end;

         Offset := Offset + Bytes_Per_Poly_11;
      end loop;
   end Encode_Vector_11;

   --  =====================================================================
   --  Decode_Vector_11: Decode byte array to 4-vector
   --  =====================================================================

   procedure Decode_Vector_11 (
      Input : in Byte_Array;
      Vec   : out Polynomial_Vector
   ) is
      Offset : Positive := 1;
   begin
      Vec := (others => Zero_Polynomial);

      for I in 0 .. K - 1 loop
         declare
            Poly_Bytes : Byte_Array(1 .. Bytes_Per_Poly_11);
         begin
            for J in Poly_Bytes'Range loop
               Poly_Bytes(J) := Input(Offset + J - 1);
            end loop;

            ByteDecode_11(Poly_Bytes, Vec(I));
         end;

         Offset := Offset + Bytes_Per_Poly_11;
      end loop;
   end Decode_Vector_11;

end SparkPass.Crypto.MLKEM.Encoding;
