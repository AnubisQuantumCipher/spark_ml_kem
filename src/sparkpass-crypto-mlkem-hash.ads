--  ========================================================================
--  SparkPass ML-KEM Hash Functions (Pure SPARK)
--  ========================================================================
--
--  **Purpose**: Cryptographic hash functions for ML-KEM-1024
--               Thin wrapper around Keccak SHA3 implementation
--
--  **Specification**: NIST FIPS 203 (ML-KEM), Section 4.1
--
--  **Functions**:
--    - G(x): SHA3-512 for seed expansion (d || k) → (ρ, σ)
--    - H(x): SHA3-256 for public key hashing ek → H(ek)
--
--  **Source**: NIST FIPS 203, Algorithm 12 (K-PKE.KeyGen)
--              NIST FIPS 203, Algorithm 15 (ML-KEM.KeyGen)
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.Keccak;

package SparkPass.Crypto.MLKEM.Hash is
   

   --  =====================================================================
   --  Hash Output Types
   --  =====================================================================

   --  SHA3-512 output: 64 bytes
   subtype SHA3_512_Digest is Byte_Array(1 .. 64);

   --  SHA3-256 output: 32 bytes
   subtype SHA3_256_Digest is Byte_Array(1 .. 32);

   --  =====================================================================
   --  G Function: SHA3-512 Seed Expansion
   --  =====================================================================
   --
   --  **Purpose**: Expand seed d to (ρ, σ) for ML-KEM key generation
   --
   --  **Algorithm** (NIST FIPS 203, Algorithm 12):
   --    Input: d ∈ {0,1}^256 (32 bytes), k ∈ {0,1}^8 (1 byte)
   --    Output: G(d || k) = SHA3-512(d || k) ∈ {0,1}^512 (64 bytes)
   --    Split: ρ := G(d||k)[0:32), σ := G(d||k)[32:64)
   --
   --  **Usage in ML-KEM-1024**:
   --    (ρ, σ) ← G(d || 4)  where k=4 for ML-KEM-1024
   --    ρ: Public seed for matrix A generation (32 bytes)
   --    σ: Private seed for secret/error sampling (32 bytes)
   --
   --  **Example**:
   --    d = [0x7c, 0x99, ...] (32 bytes random seed)
   --    k = 4 (ML-KEM-1024 rank parameter)
   --    Output = SHA3-512(d || [0x04])
   --           = [ρ₀, ρ₁, ..., ρ₃₁, σ₀, σ₁, ..., σ₃₁]
   --
   --  **Source**: NIST FIPS 203, Section 4.1.1
   --  =====================================================================

   procedure G_Expand_Seed (
      Seed   : in Byte_Array;
      K      : in U8;
      Output : out SHA3_512_Digest
   ) with
      Global => null,
      Pre    => Seed'Length = 32 and Seed'First = 1,
      Post   => Output'Length = 64 and Output'First = 1;
   --  **Purpose**: SHA3-512 seed expansion for ML-KEM
   --  **Input**:
   --    - Seed: 32-byte random seed d
   --    - K: Rank parameter (4 for ML-KEM-1024)
   --  **Output**:
   --    - Output: 64-byte hash (first 32 = ρ, last 32 = σ)
   --  **Usage**:
   --      Rho   := Output(1..32);   -- Public seed
   --      Sigma := Output(33..64);  -- Private seed

   --  =====================================================================
   --  H Function: SHA3-256 Public Key Hash
   --  =====================================================================
   --
   --  **Purpose**: Hash public key for implicit rejection in ML-KEM
   --
   --  **Algorithm** (NIST FIPS 203, Algorithm 15):
   --    Input: ek ∈ {0,1}^{1568×8} (public key, 1568 bytes)
   --    Output: H(ek) = SHA3-256(ek) ∈ {0,1}^256 (32 bytes)
   --
   --  **Usage in ML-KEM-1024**:
   --    dk ← s || ek || H(ek) || z
   --    Secret key includes H(ek) for FO⊥ transform (implicit rejection)
   --
   --  **Security Purpose**:
   --    - Implicit rejection: Use H(ek) to generate pseudorandom shared
   --      secret when decapsulation fails (CCA security)
   --    - Binds secret key to public key cryptographically
   --
   --  **Source**: NIST FIPS 203, Section 4.1.1, Algorithm 15
   --  =====================================================================

   procedure H_Hash_Public_Key (
      Public_Key : in Byte_Array;
      Output     : out SHA3_256_Digest
   ) with
      Global => null,
      Pre    => Public_Key'Length = 1568 and Public_Key'First = 1,
      Post   => Output'Length = 32 and Output'First = 1;
   --  **Purpose**: SHA3-256 hash of ML-KEM-1024 public key
   --  **Input**:
   --    - Public_Key: 1568-byte public key ek
   --  **Output**:
   --    - Output: 32-byte hash H(ek)
   --  **Usage**:
   --      Secret_Key(3104..3135) := H_Hash_Public_Key(Public_Key);

   --  =====================================================================
   --  SHA3-256 Generic (for arbitrary-length inputs)
   --  =====================================================================
   --
   --  **Purpose**: General SHA3-256 for variable-length messages
   --  **Use Case**: Hashing messages, signatures, or other data
   --  =====================================================================

   procedure SHA3_256_Hash (
      Input  : in Byte_Array;
      Output : out SHA3_256_Digest
   ) with
      Global => null,
      Pre    => Input'Length > 0 and Input'Length <= 65536,
      Post   => Output'Length = 32 and Output'First = 1;
   --  **Purpose**: General-purpose SHA3-256
   --  **Input**: Arbitrary-length byte array (up to 64KB)
   --  **Output**: 32-byte hash digest

   --  =====================================================================
   --  SHA3-512 Generic (for arbitrary-length inputs)
   --  =====================================================================
   --
   --  **Purpose**: General SHA3-512 for variable-length messages
   --  **Use Case**: Testing, verification, or protocol extensions
   --  =====================================================================

   procedure SHA3_512_Hash (
      Input  : in Byte_Array;
      Output : out SHA3_512_Digest
   ) with
      Global => null,
      Pre    => Input'Length > 0 and Input'Length <= 65536,
      Post   => Output'Length = 64 and Output'First = 1;
   --  **Purpose**: General-purpose SHA3-512
   --  **Input**: Arbitrary-length byte array (up to 64KB)
   --  **Output**: 64-byte hash digest

end SparkPass.Crypto.MLKEM.Hash;
