--  ========================================================================
--  SparkPass ML-KEM Decapsulate Implementation (Pure SPARK)
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.NTT; use SparkPass.Crypto.MLKEM.NTT;
with SparkPass.Crypto.MLKEM.Matrix; use SparkPass.Crypto.MLKEM.Matrix;
with SparkPass.Crypto.MLKEM.Hash; use SparkPass.Crypto.MLKEM.Hash;
with SparkPass.Crypto.MLKEM.Encoding; use SparkPass.Crypto.MLKEM.Encoding;
with SparkPass.Crypto.MLKEM.Poly;
with SparkPass.Crypto.MLKEM.Encaps;
with SparkPass.Crypto.Keccak; use SparkPass.Crypto.Keccak;

package body SparkPass.Crypto.MLKEM.Decaps is

   --  ========================================================================
   --  Internal: K-PKE.Decrypt (NIST FIPS 203, Algorithm 14)
   --  ========================================================================
   --
   --  **Algorithm**:
   --    Input: dk_pke = s, ciphertext c
   --    Output: Message m (32 bytes)
   --
   --    1. Decode ciphertext:
   --       c₁ ← c[0:1408), c₂ ← c[1408:1568)
   --       u ← Decompress₁₀(Decode₁₀(c₁))
   --       v ← Decompress₄(Decode₄(c₂))
   --    2. Compute: w ← v - s^T·u (in coefficient domain)
   --    3. Compress message: m ← Compress₁(w)
   --       (extract 256 bits from polynomial)
   --    4. Return m
   --
   --  ========================================================================

   procedure K_PKE_Decrypt (
      Secret_Vector : in Polynomial_Vector;  -- s in coefficient form
      Ciphertext    : in Ciphertext_Array;
      Message       : out Seed_Array
   ) is
      U_Vector     : Polynomial_Vector;
      V_Polynomial : Polynomial;
      U_NTT        : Polynomial_Vector;
      S_NTT        : Polynomial_Vector;
      W_Polynomial : Polynomial;
      Dot_Prod     : Polynomial;
   begin
      --  Step 1: Decode and decompress ciphertext
      --  ML-KEM-1024 uses 11/5-bit encoding
      declare
         C1_Bytes : Byte_Array(1 .. Bytes_Per_Vector_11);  -- 1408 bytes
         C2_Bytes : Byte_Array(1 .. Bytes_Per_Poly_5);     -- 160 bytes
         U_Compressed : Polynomial_Vector;
         V_Compressed : Polynomial;
      begin
         --  Extract c₁ and c₂ from ciphertext
         C1_Bytes := Ciphertext(1 .. Bytes_Per_Vector_11);
         C2_Bytes := Ciphertext(Bytes_Per_Vector_11 + 1 ..
                                Bytes_Per_Vector_11 + Bytes_Per_Poly_5);

         --  Decode from byte arrays
         Decode_Vector_11(C1_Bytes, U_Compressed);
         ByteDecode_5(C2_Bytes, V_Compressed);

         --  Decompress (11 bits → 12 bits, 5 bits → 12 bits)
         for I in 0 .. K - 1 loop
            for J in 0 .. 255 loop
               U_Vector(I)(J) := Decompress_11(U_Compressed(I)(J));
            end loop;
         end loop;

         for I in 0 .. 255 loop
            V_Polynomial(I) := Decompress_5(V_Compressed(I));
         end loop;
      end;

      --  Step 2: Transform s and u to NTT domain for multiplication
      for I in 0 .. K - 1 loop
         S_NTT(I) := Secret_Vector(I);
         SparkPass.Crypto.MLKEM.NTT.NTT(S_NTT(I));

         U_NTT(I) := U_Vector(I);
         SparkPass.Crypto.MLKEM.NTT.NTT(U_NTT(I));
      end loop;

      --  Step 3: Compute w = v - s^T·u
      --  First compute s^T·u as dot product in NTT domain
      Dot_Product(S_NTT, U_NTT, Dot_Prod);

      --  Transform back to coefficient domain
      W_Polynomial := Dot_Prod;
      SparkPass.Crypto.MLKEM.NTT.INTT(W_Polynomial);

      --  Subtract from v: w = v - s^T·u
      SparkPass.Crypto.MLKEM.Poly.Sub(V_Polynomial, W_Polynomial, W_Polynomial);

      --  Step 4: Compress to message bits (Compress₁)
      --  Each coefficient → 1 bit based on rounding
      --  Compress₁(x) = ⌊(2/q) × x + 1/2⌋ mod 2
      --  FIPS 203: Result is 0 for x ∈ [0, q/4) ∪ [3q/4, q), 1 for x ∈ [q/4, 3q/4)
      --  Threshold: q/4 = 3329/4 = 832.25, so use 833 as boundary
      for I in 0 .. 255 loop
         declare
            Byte_Index : constant Natural := I / 8;
            Bit_Index  : constant Natural := I mod 8;
            --  Compress: round(2×x/q) mod 2
            --  Threshold at q/4 and 3q/4: x ∈ [833, 2496] → bit 1
            Bit_Value  : constant U8 := (if W_Polynomial(I) >= 833 and W_Polynomial(I) < 2497
                                         then 1 else 0);
         begin
            if I mod 8 = 0 then
               Message(Byte_Index + 1) := 0;  -- Initialize byte
            end if;
            Message(Byte_Index + 1) := Message(Byte_Index + 1) or (Bit_Value * (2 ** Bit_Index));
         end;
      end loop;

   end K_PKE_Decrypt;

   --  ========================================================================
   --  Decapsulate: ML-KEM.Decaps (NIST FIPS 203, Algorithm 18)
   --  ========================================================================

   procedure Decapsulate (
      Secret_Key    : in Secret_Key_Array;
      Ciphertext    : in Ciphertext_Array;
      Shared_Secret : out Shared_Secret_Array
   ) is
      Recovered : Seed_Array;
      Valid     : Boolean;
   begin
      Decapsulate_Expanded(Secret_Key, Ciphertext, Shared_Secret,
                          Recovered, Valid);
   end Decapsulate;

   --  ========================================================================
   --  Decapsulate_Expanded: Decapsulate with Component Access
   --  ========================================================================

   procedure Decapsulate_Expanded (
      Secret_Key       : in Secret_Key_Array;
      Ciphertext       : in Ciphertext_Array;
      Shared_Secret    : out Shared_Secret_Array;
      Recovered_Msg    : out Seed_Array;
      Valid            : out Boolean
   ) is
      S_Vector       : Polynomial_Vector;
      PK_Copy        : Public_Key_Array;
      EK_Hash        : Seed_Array;
      Z_Random       : Seed_Array;
      K_Bar          : Seed_Array;
      C_Prime        : Ciphertext_Array;
      U_Vec          : Polynomial_Vector;
      V_Poly         : Polynomial;
   begin
      --  Step 1: Parse secret key dk = (s || ek || h || z)
      --  Total: 1536 + 1568 + 32 + 32 = 3168 bytes
      declare
         S_Bytes : Byte_Array(1 .. Bytes_Per_Vector_12);  -- 1536 bytes
         Offset  : Positive := 1;
      begin
         --  Extract s vector (1536 bytes)
         S_Bytes := Secret_Key(Offset .. Offset + Bytes_Per_Vector_12 - 1);
         Decode_Vector_12(S_Bytes, S_Vector);
         Offset := Offset + Bytes_Per_Vector_12;

         --  Extract public key copy (1568 bytes)
         PK_Copy := Secret_Key(Offset .. Offset + 1567);
         Offset := Offset + 1568;

         --  Extract H(ek) hash (32 bytes)
         EK_Hash := Secret_Key(Offset .. Offset + 31);
         Offset := Offset + 32;

         --  Extract z random value (32 bytes)
         Z_Random := Secret_Key(Offset .. Offset + 31);
      end;

      --  Self-check: Verify H(ekPKE) = stored h (catches parsing bugs)
      --  This is the #1 detector for off-by-32 errors in dk slicing
      declare
         Computed_H : Seed_Array;
      begin
         SparkPass.Crypto.MLKEM.Hash.SHA3_256_Hash(PK_Copy, Computed_H);
         --  If this fails, dk parsing offsets are wrong!
         pragma Assert (Computed_H = EK_Hash);
      end;

      --  Step 2: Decrypt ciphertext: m' ← K-PKE.Decrypt(s, c)
      K_PKE_Decrypt(S_Vector, Ciphertext, Recovered_Msg);

      --  Step 3: Re-encrypt and compute K̄: (c', K̄) ← Encaps(ekPKE, m')
      --  FIPS 203 Algorithm 18 line 3 & 5:
      --    (K̄, r') ← G(m' || h)
      --    c' ← K-PKE.Encrypt(ekPKE, m', r')
      --
      --  NOTE: Since H(ekPKE) = h (verified by assert above),
      --        Encapsulate_Expanded will compute same (K̄, r') and c'
      SparkPass.Crypto.MLKEM.Encaps.Encapsulate_Expanded(
         PK_Copy, Recovered_Msg, C_Prime, K_Bar, U_Vec, V_Poly
      );

      --  Step 4: Verify ciphertext authenticity (constant-time comparison)
      --  Use XOR accumulator to avoid timing leaks
      declare
         Diff : U8 := 0;
      begin
         for I in Ciphertext'Range loop
            Diff := Diff or (Ciphertext(I) xor C_Prime(I));
         end loop;
         Valid := (Diff = 0);
      end;

      --  Step 5: Derive final shared secret with implicit rejection
      --  FIPS 203 Algorithm 18 line 4 & 12:
      --    - Line 4: K ← J(z || c) where J = SHAKE256(·, 32)
      --    - Line 12: if c' ≠ c return K (implicit reject), else return K̄
      --
      --  NOTE: FIPS 203 uses SHAKE256(z || c), NOT SHA3-256(z || SHA3-256(c))
      if Valid then
         --  Success path: return K̄ (from G)
         Shared_Secret := K_Bar;
      else
         --  Implicit rejection: K ← SHAKE256(z || c, 32 bytes)
         declare
            Reject_Input : Byte_Array(1 .. 32 + Ciphertext'Length);
         begin
            Reject_Input(1 .. 32) := Z_Random;
            Reject_Input(33 .. Reject_Input'Last) := Ciphertext;
            SHAKE_256(Reject_Input, Shared_Secret);
         end;
      end if;

   end Decapsulate_Expanded;

end SparkPass.Crypto.MLKEM.Decaps;
