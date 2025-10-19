--  ========================================================================
--  SparkPass ML-KEM Encapsulate Implementation (Pure SPARK)
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.NTT; use SparkPass.Crypto.MLKEM.NTT;
with SparkPass.Crypto.MLKEM.Matrix; use SparkPass.Crypto.MLKEM.Matrix;
with SparkPass.Crypto.MLKEM.Sampling; use SparkPass.Crypto.MLKEM.Sampling;
with SparkPass.Crypto.MLKEM.Hash; use SparkPass.Crypto.MLKEM.Hash;
with SparkPass.Crypto.MLKEM.PRF; use SparkPass.Crypto.MLKEM.PRF;
with SparkPass.Crypto.MLKEM.XOF; use SparkPass.Crypto.MLKEM.XOF;
with SparkPass.Crypto.MLKEM.Encoding; use SparkPass.Crypto.MLKEM.Encoding;
with SparkPass.Crypto.MLKEM.Poly;
with SparkPass.Crypto.Random;

package body SparkPass.Crypto.MLKEM.Encaps is

   --  ========================================================================
   --  Internal: K-PKE.Encrypt (NIST FIPS 203, Algorithm 13)
   --  ========================================================================
   --
   --  **Algorithm**:
   --    Input: ek_pke = (t̂, ρ), message m, randomness r
   --    Output: Ciphertext c
   --
   --    1. Decode public key: t̂ ← Decode₁₂(ek[0:1536)), ρ ← ek[1536:1568)
   --    2. Generate matrix A from ρ:
   --       For i, j ∈ [0, 3]:
   --         Â[i,j] ← SampleNTT(XOF(ρ || i || j))
   --    3. Generate random vector r:
   --       For i ∈ [0, 3]:
   --         r[i] ← SamplePolyCBD(PRF(r_seed, N), η₁=2)
   --         r̂[i] ← NTT(r[i])
   --         N ← N + 1
   --    4. Generate error vector e₁:
   --       For i ∈ [0, 3]:
   --         e₁[i] ← SamplePolyCBD(PRF(r_seed, N), η₁=2)
   --         N ← N + 1
   --    5. Generate error e₂:
   --         e₂ ← SamplePolyCBD(PRF(r_seed, N), η₂=2)
   --    6. Compute u:
   --         u ← INTT(Âᵀ·r̂) + e₁
   --    7. Compute v:
   --         μ ← Decompress₁(m)  (expand message to polynomial)
   --         v ← INTT(t̂ᵀ·r̂) + e₂ + μ
   --    8. Encode ciphertext:
   --         c₁ ← Encode₁₀(Compress₁₀(u))  (1280 bytes)
   --         c₂ ← Encode₄(Compress₄(v))     (128 bytes)
   --         c ← c₁ || c₂                    (1408 bytes)
   --
   --  ========================================================================

   procedure K_PKE_Encrypt (
      Public_Key    : in Public_Key_Array;
      Message       : in Seed_Array;
      Randomness    : in Seed_Array;
      Ciphertext    : out Ciphertext_Array;
      U_Vector      : out Polynomial_Vector;
      V_Polynomial  : out Polynomial
   ) is
      T_Vector_NTT : Polynomial_Vector;
      Rho_Seed     : Seed_Array;
      A_Matrix     : Polynomial_Matrix;
      R_Vector     : Polynomial_Vector;
      R_Vector_NTT : Polynomial_Vector;
      E1_Vector    : Polynomial_Vector;
      E2_Poly      : Polynomial;
      Message_Poly : Polynomial;
      Temp_Vector  : Polynomial_Vector;
      N : Natural := 0;
   begin
      --  Step 1: Decode public key: t || ρ
      --  NOTE: t is stored in NTT domain (per FIPS 203 and KeyGen implementation)
      declare
         T_Bytes : Byte_Array(1 .. Bytes_Per_Vector_12);  -- 1536 bytes
      begin
         --  Decode t vector (already in NTT domain from encoding)
         T_Bytes := Public_Key(1 .. Bytes_Per_Vector_12);
         Decode_Vector_12(T_Bytes, T_Vector_NTT);

         --  NO NTT transformation needed - t is already in NTT domain!
         --  (KeyGen stores t in NTT domain without INTT)

         Rho_Seed := Public_Key(Bytes_Per_Vector_12 + 1 .. 1568);
      end;

      --  Step 2: Generate matrix A from ρ (same as KeyGen)
      --  FIPS 203 Algorithm 13, Line 6:
      --    For i, j ∈ [0, k-1]: Â[i,j] ← SampleNTT(XOF(ρ || j || i))
      --  NOTE: Column index j comes before row index i (same as KeyGen)
      for I in 0 .. K - 1 loop
         for J in 0 .. K - 1 loop
            declare
               XOF_Out    : XOF_Output;
               Bytes_Used : Natural;
            begin
               --  CRITICAL: Use (J, I) ordering to match FIPS 203 and KeyGen!
               XOF_Uniform(Rho_Seed, U8(J), U8(I), XOF_Out);
               SampleNTT(XOF_Out, A_Matrix(I, J), Bytes_Used);
            end;
         end loop;
      end loop;

      --  Step 3: Generate random vector r
      --  For i ∈ [0, k-1]:
      --    r[i] ← SamplePolyCBD(PRF(randomness, N), η₁=2)
      --    r̂[i] ← NTT(r[i])
      for I in 0 .. K - 1 loop
         declare
            PRF_Out : PRF_Output;
         begin
            PRF_CBD(Randomness, U8(N), PRF_Out);
            N := N + 1;

            SamplePolyCBD(PRF_Out, Eta => 2, Poly => R_Vector(I));

            --  Transform to NTT domain
            R_Vector_NTT(I) := R_Vector(I);
            SparkPass.Crypto.MLKEM.NTT.NTT(R_Vector_NTT(I));
         end;
      end loop;

      --  Step 4: Generate error vector e₁
      --  For i ∈ [0, k-1]:
      --    e₁[i] ← SamplePolyCBD(PRF(randomness, N), η₁=2)
      for I in 0 .. K - 1 loop
         declare
            PRF_Out : PRF_Output;
         begin
            PRF_CBD(Randomness, U8(N), PRF_Out);
            N := N + 1;

            SamplePolyCBD(PRF_Out, Eta => 2, Poly => E1_Vector(I));
         end;
      end loop;

      --  Step 5: Generate error e₂
      --  e₂ ← SamplePolyCBD(PRF(randomness, N), η₂=2)
      declare
         PRF_Out : PRF_Output;
      begin
         PRF_CBD(Randomness, U8(N), PRF_Out);
         SamplePolyCBD(PRF_Out, Eta => 2, Poly => E2_Poly);
      end;

      --  Step 6: Compute u = INTT(Âᵀ·r̂) + e₁
      --  Note: Âᵀ·r̂ computed in NTT domain
      Matrix_Transpose_Vector_Mul(A_Matrix, R_Vector_NTT, Temp_Vector);

      --  Transform back to coefficient domain
      for I in 0 .. K - 1 loop
         U_Vector(I) := Temp_Vector(I);
         SparkPass.Crypto.MLKEM.NTT.INTT(U_Vector(I));
      end loop;

      --  Add error e₁
      Vector_Add(U_Vector, E1_Vector, U_Vector);

      --  Step 7: Compute v = INTT(t̂ᵀ·r̂) + e₂ + μ
      --  First, compute t̂ᵀ·r̂ (dot product in NTT domain)
      declare
         Dot_Prod : Polynomial;
      begin
         --  Use Matrix.Dot_Product helper
         Dot_Product(T_Vector_NTT, R_Vector_NTT, Dot_Prod);

         --  Transform back to coefficient domain
         V_Polynomial := Dot_Prod;
         SparkPass.Crypto.MLKEM.NTT.INTT(V_Polynomial);
      end;

      --  Add error e₂
      SparkPass.Crypto.MLKEM.Poly.Add(V_Polynomial, E2_Poly, V_Polynomial);

      --  Decompress message to polynomial (each bit → coefficient)
      --  Message is 32 bytes = 256 bits → 256 coefficients
      --  Decompress_1(b) = b × ⌈q/2⌋ = b × 1665
      for I in 0 .. 255 loop
         declare
            Byte_Index : constant Natural := I / 8;
            Bit_Index  : constant Natural := I mod 8;
            Bit_Value  : constant U8 := (Message(Byte_Index + 1) / (2 ** Bit_Index)) and 1;
         begin
            if Bit_Value = 0 then
               Message_Poly(I) := 0;
            else
               Message_Poly(I) := 1665;  -- ⌈3329/2⌋
            end if;
         end;
      end loop;

      --  Add message μ
      SparkPass.Crypto.MLKEM.Poly.Add(V_Polynomial, Message_Poly, V_Polynomial);

      --  Step 8: Encode ciphertext c = c₁ || c₂
      --  ML-KEM-1024 uses d_u=11, d_v=5 (1408+160=1568 bytes)
      declare
         C1_Bytes : Byte_Array(1 .. Bytes_Per_Vector_11);  -- 1408 bytes
         C2_Bytes : Byte_Array(1 .. Bytes_Per_Poly_5);     -- 160 bytes
         U_Compressed : Polynomial_Vector;
         V_Compressed : Polynomial;
      begin
         --  Compress u vector (12 bits → 11 bits per coefficient)
         for I in 0 .. K - 1 loop
            for J in 0 .. 255 loop
               U_Compressed(I)(J) := Compress_11(U_Vector(I)(J));
            end loop;
         end loop;

         --  Compress v polynomial (12 bits → 5 bits per coefficient)
         for I in 0 .. 255 loop
            V_Compressed(I) := Compress_5(V_Polynomial(I));
         end loop;

         --  Encode compressed values
         Encode_Vector_11(U_Compressed, C1_Bytes);
         ByteEncode_5(V_Compressed, C2_Bytes);

         --  Concatenate c₁ || c₂ (exactly 1568 bytes)
         Ciphertext(1 .. Bytes_Per_Vector_11) := C1_Bytes;
         Ciphertext(Bytes_Per_Vector_11 + 1 .. Bytes_Per_Vector_11 + Bytes_Per_Poly_5) := C2_Bytes;
      end;

   end K_PKE_Encrypt;

   --  ========================================================================
   --  Encapsulate: ML-KEM.Encaps (NIST FIPS 203, Algorithm 16)
   --  ========================================================================

   procedure Encapsulate (
      Public_Key    : in Public_Key_Array;
      Ciphertext    : out Ciphertext_Array;
      Shared_Secret : out Shared_Secret_Array
   ) is
      Random_Message : Seed_Array;
      U_Vec : Polynomial_Vector;
      V_Poly : Polynomial;
   begin
      --  Step 1: Generate random message m ← {0,1}^256
      SparkPass.Crypto.Random.Fill(Random_Message);

      --  Step 2-4: Call expanded version
      Encapsulate_Expanded(Public_Key, Random_Message, Ciphertext,
                          Shared_Secret, U_Vec, V_Poly);
   end Encapsulate;

   --  ========================================================================
   --  Encapsulate_Expanded: Encapsulate with Component Access
   --  ========================================================================

   procedure Encapsulate_Expanded (
      Public_Key       : in Public_Key_Array;
      Random_Message   : in Seed_Array;
      Ciphertext       : out Ciphertext_Array;
      Shared_Secret    : out Shared_Secret_Array;
      U_Vector         : out Polynomial_Vector;
      V_Polynomial     : out Polynomial
   ) is
      K_Bar            : Seed_Array;
      Randomness       : Seed_Array;
      PK_Hash          : Seed_Array;
   begin
      --  Step 1: Compute (K̄, r) ← G(m || H(ek))
      --  FIPS 203 Algorithm 16: Use SHA3-512 for G
      declare
         G_Input  : Byte_Array(1 .. 64);   -- m || H(ek)
         G_Output : SHA3_512_Digest;       -- 64 bytes from G
      begin
         --  Hash public key: H(ek)
         SHA3_256_Hash(Public_Key, PK_Hash);

         --  Concatenate: m || H(ek)
         G_Input(1 .. 32) := Random_Message;
         G_Input(33 .. 64) := PK_Hash;

         --  Apply G (SHA3-512)
         SHA3_512_Hash(G_Input, G_Output);

         --  Split output: K̄ = G[0:32), r = G[32:64)
         K_Bar := G_Output(1 .. 32);
         Randomness := G_Output(33 .. 64);
      end;

      --  Step 2: Encrypt: c ← K-PKE.Encrypt(ek, m, r)
      K_PKE_Encrypt(Public_Key, Random_Message, Randomness,
                    Ciphertext, U_Vector, V_Polynomial);

      --  Step 3: Return shared secret K
      --  FIPS 203 Algorithm 16: Shared secret is K = G(m || H(ek))[0:32)
      --  NOTE: In finalized ML-KEM (FIPS 203), K is returned directly.
      --        Original Kyber used K ← H(K̄ || H(c)), but this was removed.
      --  Per FIPS 203 Section 7.2:
      --    "The shared key K is the first 32 bytes of G(m || H(ek))"
      Shared_Secret := K_Bar;

   end Encapsulate_Expanded;

end SparkPass.Crypto.MLKEM.Encaps;
