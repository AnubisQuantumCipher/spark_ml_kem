pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.NTT; use SparkPass.Crypto.MLKEM.NTT;
with SparkPass.Crypto.MLKEM.Matrix; use SparkPass.Crypto.MLKEM.Matrix;
with SparkPass.Crypto.MLKEM.Sampling; use SparkPass.Crypto.MLKEM.Sampling;
with SparkPass.Crypto.MLKEM.Hash; use SparkPass.Crypto.MLKEM.Hash;
with SparkPass.Crypto.MLKEM.PRF; use SparkPass.Crypto.MLKEM.PRF;
with SparkPass.Crypto.MLKEM.XOF; use SparkPass.Crypto.MLKEM.XOF;
with SparkPass.Crypto.MLKEM.Encoding; use SparkPass.Crypto.MLKEM.Encoding;
with SparkPass.Crypto.MLKEM.Arithmetic;
with SparkPass.Crypto.Random;

--  ========================================================================
--  ML-KEM-1024 Key Generation Implementation (Pure SPARK)
--  ========================================================================
--
--  **Implementation Status**: COMPLETE (All dependencies ready)
--
--  **Modules Used**:
--    ✅ SparkPass.Crypto.MLKEM.Hash - G(d||k), H(ek) for seed expansion
--    ✅ SparkPass.Crypto.MLKEM.PRF - SHAKE-256 for CBD sampling
--    ✅ SparkPass.Crypto.MLKEM.XOF - SHAKE-128 for matrix generation
--    ✅ SparkPass.Crypto.MLKEM.Encoding - ByteEncode/Decode functions
--    ✅ SparkPass.Crypto.MLKEM.NTT - Number Theoretic Transform
--    ✅ SparkPass.Crypto.MLKEM.Matrix - Matrix operations
--    ✅ SparkPass.Crypto.MLKEM.Sampling - CBD & rejection sampling
--
--  **Algorithm**: NIST FIPS 203, Algorithm 15 (ML-KEM.KeyGen)
--
--  ========================================================================

package body SparkPass.Crypto.MLKEM.KeyGen is

   --  ========================================================================
   --  Internal: K-PKE.KeyGen (NIST FIPS 203, Algorithm 12)
   --  ========================================================================
   --
   --  **Algorithm**:
   --    Input: d ∈ {0,1}^256
   --    Output: (ek_pke, dk_pke) where ek_pke = (t, ρ), dk_pke = s
   --
   --    1. (ρ, σ) ← G(d || k) where k=4
   --    2. N ← 0
   --    3. Generate matrix A:
   --       For i, j ∈ [0, 3]:
   --         Â[i,j] ← SampleNTT(XOF(ρ || i || j))
   --    4. Generate secret s:
   --       For i ∈ [0, 3]:
   --         s[i] ← SamplePolyCBD(PRF(σ, N), η=2)
   --         ŝ[i] ← NTT(s[i])
   --         N ← N + 1
   --    5. Generate error e:
   --       For i ∈ [0, 3]:
   --         e[i] ← SamplePolyCBD(PRF(σ, N), η=2)
   --         ê[i] ← NTT(e[i])
   --         N ← N + 1
   --    6. Compute t:
   --       t̂ ← Â·ŝ + ê
   --       t ← INTT(t̂)
   --    7. Return (ek_pke, dk_pke)
   --
   --  ========================================================================

   procedure K_PKE_KeyGen (
      Seed_D            : in Seed_Bytes;
      Public_Components : out Public_Key_Components;
      S_Vector_NTT      : out Polynomial_Vector
   ) is
      Rho, Sigma : Seed_Bytes;
      A_Matrix   : Polynomial_Matrix;
      S_Vector   : Polynomial_Vector;
      E_Vector   : Polynomial_Vector;
      T_Vector_NTT : Polynomial_Vector;
      N : Natural := 0;
   begin
      --  Step 1: Expand seed to (ρ, σ) using G = SHA3-512
      --  FIPS 203 Algorithm 12: G(d || k) where k=4 for ML-KEM-1024
      declare
         G_Output : SHA3_512_Digest;
      begin
         --  Use wrapper: G(d || k) = SHA3-512(d || k)
         G_Expand_Seed(Seed_D, 4, G_Output);

         --  Split output: ρ = G_Output[0:32), σ = G_Output[32:64)
         Rho   := G_Output(1 .. 32);
         Sigma := G_Output(33 .. 64);
      end;

      --  Step 2: Generate matrix A from seed ρ
      --  For i, j ∈ [0, k-1]:
      --    Â[i,j] ← SampleNTT(XOF(ρ || i || j))
      for I in 0 .. K - 1 loop
         for J in 0 .. K - 1 loop
            declare
               XOF_Out    : XOF_Output;  -- 672-byte buffer for rejection sampling
               Bytes_Used : Natural;
            begin
               --  NIST reference: A[row][col] ← SampleNTT(XOF(ρ || col || row))
               --  For non-transposed matrix generation (used in KeyGen)
               XOF_Uniform(Rho, U8(J), U8(I), XOF_Out);

               --  Sample polynomial from XOF output
               --  NOTE: Reference says "matrix generated in NTT domain" but this refers
               --  to the USAGE/INTERPRETATION, not that NTT transform is applied.
               --  The sampled coefficients are USED as-is in NTT-domain operations.
               SampleNTT(XOF_Out, A_Matrix(I, J), Bytes_Used);
            end;
         end loop;
      end loop;

      --  Step 3: Generate secret vector s
      --  For i ∈ [0, k-1]:
      --    s[i] ← SamplePolyCBD(PRF(σ, N), η=2)
      --    ŝ[i] ← NTT(s[i])
      for I in 0 .. K - 1 loop
         declare
            PRF_Out : PRF_Output;  -- 128-byte output for CBD sampling
         begin
            --  Use wrapper: PRF(σ, N) = SHAKE-256(σ || N, 128)
            PRF_CBD(Sigma, U8(N), PRF_Out);
            N := N + 1;

            --  Sample from CBD
            SamplePolyCBD(PRF_Out, Eta => 2, Poly => S_Vector(I));

            --  Transform to NTT domain (copy then transform in place)
            S_Vector_NTT(I) := S_Vector(I);
            SparkPass.Crypto.MLKEM.NTT.NTT(S_Vector_NTT(I));
         end;
      end loop;

      --  Step 4: Generate error vector e
      --  For i ∈ [0, k-1]:
      --    e[i] ← SamplePolyCBD(PRF(σ, N), η=2)
      --    ê[i] ← NTT(e[i])
      for I in 0 .. K - 1 loop
         declare
            PRF_Out : PRF_Output;  -- 128-byte output for CBD sampling
         begin
            --  Use wrapper: PRF(σ, N) = SHAKE-256(σ || N, 128)
            PRF_CBD(Sigma, U8(N), PRF_Out);
            N := N + 1;

            --  Sample from CBD
            SamplePolyCBD(PRF_Out, Eta => 2, Poly => E_Vector(I));

            --  Transform to NTT domain
            SparkPass.Crypto.MLKEM.NTT.NTT(E_Vector(I));
         end;
      end loop;

      --  Step 5: Compute t = A·s + e in NTT domain
      --  t̂ ← Â·ŝ + ê
      --  Use regular matrix-vector multiply (reference uses matvec_mul, not transpose)
      Matrix_Vector_Mul(A_Matrix, S_Vector_NTT, T_Vector_NTT);
      Vector_Add(T_Vector_NTT, E_Vector, T_Vector_NTT);

      --  Step 6: Store t in NTT domain for encoding
      --  CRITICAL: Reference implementation does NOT do INTT here!
      --  t is encoded in NTT/Montgomery domain, not coefficient domain
      --  NOTE: During Decaps, t will be decoded and is already in NTT domain
      for I in 0 .. K - 1 loop
         Public_Components.T_Vector(I) := T_Vector_NTT(I);
         --  NO INTT - keep in NTT domain!
      end loop;

      --  Step 7: Store ρ seed in public components
      Public_Components.Rho_Seed := Rho;

   end K_PKE_KeyGen;

   --  ========================================================================
   --  KeyGen: ML-KEM.KeyGen (NIST FIPS 203, Algorithm 15)
   --  ========================================================================
   --
   --  **Algorithm**:
   --    Input: d ∈ {0,1}^256
   --    Output: (ek, dk)
   --
   --    1. (ek_pke, dk_pke) ← K-PKE.KeyGen(d)
   --    2. ek ← ek_pke
   --    3. dk ← dk_pke || ek || H(ek) || z
   --       where z ←_R {0,1}^256
   --    4. return (ek, dk)
   --
   --  ========================================================================

   procedure KeyGen (
      Random_Seed : in Seed_Bytes;
      PK          : out Public_Key;
      SK          : out Secret_Key
   ) is
      PK_Components : Public_Key_Components;
      SK_Components : Secret_Key_Components;
   begin
      --  Call expanded version with components
      KeyGen_Expanded(Random_Seed, PK, SK,
                     PK_Components, SK_Components);
   end KeyGen;

   --  ========================================================================
   --  KeyGen_Expanded: KeyGen with Component Access
   --  ========================================================================

   procedure KeyGen_Expanded (
      Random_Seed       : in Seed_Bytes;
      PK                : out Public_Key;
      SK                : out Secret_Key;
      Public_Components : out Public_Key_Components;
      Secret_Components : out Secret_Key_Components
   ) is
      S_Vector_NTT : Polynomial_Vector;
      Z_Random     : Seed_Bytes;
      EK_Hash      : Seed_Bytes;
   begin
      --  Step 1: Generate PKE keys (t, ρ, s)
      K_PKE_KeyGen(Random_Seed, Public_Components, S_Vector_NTT);

      --  Step 2: Encode public key: ek = ByteEncode₁₂(t) || ρ
      --  FIPS 203: ek_pke = (t, ρ) where t is k-vector, ρ is 32-byte seed
      --  Size: 4 × 384 bytes (t vector) + 32 bytes (ρ) = 1568 bytes
      declare
         T_Bytes : Byte_Array(1 .. Bytes_Per_Vector_12);  -- 1536 bytes
      begin
         Encode_Vector_12(Public_Components.T_Vector, T_Bytes);
         PK(1 .. Bytes_Per_Vector_12) := T_Bytes;
         PK(Bytes_Per_Vector_12 + 1 .. 1568) := Public_Components.Rho_Seed;
      end;

      --  Step 3: Generate z for implicit rejection
      --  FIPS 203 Section 7.2: z ← {0,1}^256 (32 random bytes)
      SparkPass.Crypto.Random.Fill(Z_Random);

      --  Step 4: Hash public key: H(ek) using SHA3-256
      --  FIPS 203 Section 7.1: H is instantiated as SHA3-256
      H_Hash_Public_Key(PK, EK_Hash);

      --  Step 5: Assemble secret key components
      --  NOTE: We need to transform S_Vector_NTT back to coefficient domain
      --        for encoding
      declare
         S_Vector_Coeff : Polynomial_Vector;
      begin
         for I in 0 .. K - 1 loop
            S_Vector_Coeff(I) := S_Vector_NTT(I);
            SparkPass.Crypto.MLKEM.NTT.INTT(S_Vector_Coeff(I));
         end loop;

         Secret_Components.S_Vector := S_Vector_Coeff;
      end;

      Secret_Components.PK_Copy := PK;
      Secret_Components.EK_Hash    := EK_Hash;
      Secret_Components.Z_Random   := Z_Random;

      --  Step 6: Encode secret key: dk = ByteEncode₁₂(s) || ek || H(ek) || z
      --  FIPS 203: dk = (dk_pke || ek || H(ek) || z)
      --  Size: 1536 (s vector) + 1568 (ek) + 32 (H(ek)) + 32 (z) = 3168 bytes
      declare
         S_Bytes : Byte_Array(1 .. Bytes_Per_Vector_12);  -- 1536 bytes
         Offset  : Positive := 1;
      begin
         --  Encode s vector (1536 bytes)
         Encode_Vector_12(Secret_Components.S_Vector, S_Bytes);
         SK(Offset .. Offset + Bytes_Per_Vector_12 - 1) := S_Bytes;
         Offset := Offset + Bytes_Per_Vector_12;

         --  Append public key (1568 bytes)
         SK(Offset .. Offset + 1567) := PK;
         Offset := Offset + 1568;

         --  Append H(ek) hash (32 bytes)
         SK(Offset .. Offset + 31) := EK_Hash;
         Offset := Offset + 32;

         --  Append z random value (32 bytes)
         SK(Offset .. Offset + 31) := Z_Random;
      end;

   end KeyGen_Expanded;

   --  ========================================================================
   --  SPARK Verification Notes
   --  ========================================================================
   --
   --  **Implementation Status**: COMPLETE ✅
   --
   --  **Modules Used**:
   --    ✅ Hash.G_Expand_Seed - SHA3-512 for (ρ, σ) generation
   --    ✅ Hash.H_Hash_Public_Key - SHA3-256 for implicit rejection
   --    ✅ PRF.PRF_CBD - SHAKE-256 for CBD sampling (s, e vectors)
   --    ✅ XOF.XOF_Uniform - SHAKE-128 for matrix A generation
   --    ✅ Encoding.Encode_Vector_12 - 12-bit encoding for t, s vectors
   --    ✅ Random.Fill - CSPRNG for z value
   --
   --  **Proof Obligations**:
   --    1. K_PKE_KeyGen:
   --       - All array indices in bounds (I, J ∈ [0,3], coeffs ∈ [0,255])
   --       - T_Vector coefficients in [0, q-1] after INTT
   --       - Algebraic correctness: t = INTT(Â·ŝ + ê)
   --       - PRF nonce N increments correctly [0..7]
   --
   --    2. KeyGen_Expanded:
   --       - Public_Key length = 1568 bytes (verified by type system)
   --       - Secret_Key length = 3168 bytes (verified by type system)
   --       - All components properly initialized (no uninitialized reads)
   --       - Encoding offset calculations correct (no buffer overflows)
   --
   --  **Expected GNATprove Results**:
   --    - Flow analysis: All variables initialized before use
   --    - Proof (Bronze): All array accesses proven safe
   --    - Proof (Silver): Postconditions proven (key sizes, ranges)
   --    - Proof (Gold): Algebraic properties proven (if loop invariants added)
   --
   --  **Testing Strategy**:
   --    1. Validate against NIST FIPS 203 test vectors
   --    2. Verify determinism (same seed → same keys)
   --    3. Verify correctness (Encaps/Decaps roundtrip)
   --    4. Timing analysis (constant-time operations)
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.KeyGen;
