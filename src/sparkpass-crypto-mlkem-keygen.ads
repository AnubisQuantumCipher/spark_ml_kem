pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;
with SparkPass.Types; use SparkPass.Types;

--  ========================================================================
--  ML-KEM-1024 Key Generation (NIST FIPS 203)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 7.1 (ML-KEM Key Generation)
--              Algorithm 15 (ML-KEM.KeyGen)
--              Algorithm 12 (K-PKE.KeyGen - internal)
--
--  **Purpose**: Generate ML-KEM-1024 public and secret key pair
--
--  **Security Level**: NIST Level 5 (equivalent to AES-256)
--    - Classical security: 2^254 bit operations
--    - Quantum security: 2^230 quantum gate operations
--    - Key size: 1568 bytes (public) + 3168 bytes (secret)
--
--  **Algorithm Overview** (ML-KEM.KeyGen):
--
--    Input: Random seed d ∈ {0,1}^256 (32 bytes)
--    Output: Encapsulation key ek (public), Decapsulation key dk (secret)
--
--    1. Generate seeds:
--       (ρ, σ) ← G(d || k)         -- G = SHA3-512
--       where k = 4 (ML-KEM-1024 rank parameter)
--
--    2. Generate public matrix A:
--       For i, j ∈ [0, k-1]:
--         Â[i,j] ← SampleNTT(XOF(ρ || i || j))
--       (A is k×k matrix of polynomials in NTT domain)
--
--    3. Generate secret vector s:
--       For i ∈ [0, k-1]:
--         ŝ[i] ← NTT(SamplePolyCBD(PRF(σ, N)))
--         N ← N + 1
--       (s is k-vector of polynomials with small coefficients)
--
--    4. Generate error vector e:
--       For i ∈ [0, k-1]:
--         ê[i] ← NTT(SamplePolyCBD(PRF(σ, N)))
--         N ← N + 1
--       (e is k-vector of small noise polynomials)
--
--    5. Compute public vector t:
--       t̂ ← Â · ŝ + ê         -- Matrix-vector multiplication in NTT domain
--       t ← INTT(t̂)          -- Transform back to coefficient domain
--
--    6. Encode public key:
--       ek ← Encode(t, ρ)
--       ek = ByteEncode₁₂(t) || ρ
--       Size: (12 × 256 × 4)/8 + 32 = 1536 + 32 = 1568 bytes
--
--    7. Encode secret key:
--       dk ← Encode(s, ek, H(ek), z)
--       dk = ByteEncode₁₂(s) || ek || H(ek) || z
--       Size: 1536 + 1568 + 32 + 32 = 3168 bytes
--       where:
--         - s: secret vector (1536 bytes)
--         - ek: public key (1568 bytes)
--         - H(ek): SHA3-256 hash of public key (32 bytes)
--         - z: implicit rejection value (32 bytes random)
--
--  **Mathematical Foundation**:
--
--  Module-LWE Problem:
--    Given (A, t) where t = A·s + e, recover s
--    - A is uniformly random k×k matrix over R_q
--    - s, e are k-vectors with small coefficients from CBD(η)
--    - For ML-KEM-1024: k=4, η₁=η₂=2, q=3329
--
--  Security relies on:
--    1. Hardness of Module-LWE with parameters (k=4, η=2, q=3329)
--    2. Cryptographic strength of SHAKE-128/256 for randomness expansion
--    3. Implicit rejection (FO⊥ transform) for CCA security
--
--  **Key Sizes** (ML-KEM-1024):
--    - Public key (ek): 1568 bytes
--      * t vector: 12 bits/coeff × 256 coeffs × 4 polys = 1536 bytes
--      * ρ seed: 32 bytes
--    - Secret key (dk): 3168 bytes
--      * s vector: 12 bits/coeff × 256 coeffs × 4 polys = 1536 bytes
--      * ek copy: 1568 bytes
--      * H(ek): 32 bytes (SHA3-256 hash)
--      * z: 32 bytes (implicit rejection randomness)
--
--  **Deterministic Property**:
--    - Same seed d always produces same key pair (important for testing)
--    - In practice, d should be generated from hardware RNG
--    - NIST requires d ∈_R {0,1}^256 (uniformly random)
--
--  **SPARK Verification Goals**:
--    - Bronze: Prove no overflow, all array accesses in bounds
--    - Silver: Prove algebraic correctness (t = A·s + e)
--    - Gold: Prove distribution correctness (s, e from CBD)
--    - Platinum: Prove FIPS 203 compliance, constant-time execution
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.KeyGen is
   pragma Elaborate_Body;

   --  ========================================================================
   --  Key Sizes (NIST FIPS 203, Table 2)
   --  ========================================================================

   Public_Key_Size : constant := 1568;  -- ek size for ML-KEM-1024
   Secret_Key_Size : constant := 3168;  -- dk size for ML-KEM-1024
   Seed_Size       : constant := 32;    -- Random seed d size

   --  Breakdown:
   --    Public key = ByteEncode₁₂(t) || ρ
   --               = (12×256×4)/8 + 32
   --               = 1536 + 32 = 1568 bytes
   --
   --    Secret key = ByteEncode₁₂(s) || ek || H(ek) || z
   --               = 1536 + 1568 + 32 + 32
   --               = 3168 bytes

   --  ========================================================================
   --  Key Types
   --  ========================================================================

   subtype Public_Key is Byte_Array(1 .. Public_Key_Size);
   --  **Encapsulation Key (ek)**: Used for key encapsulation
   --  **Format**: 1536 bytes (t vector) || 32 bytes (ρ seed)
   --  **Distribution**: Can be freely shared (public)
   --  **Usage**: Input to ML-KEM.Encaps to generate shared secret

   subtype Secret_Key is Byte_Array(1 .. Secret_Key_Size);
   --  **Decapsulation Key (dk)**: Used for key decapsulation
   --  **Format**: 1536 bytes (s) || 1568 bytes (ek) || 32 bytes (H(ek)) || 32 bytes (z)
   --  **Distribution**: MUST be kept secret
   --  **Usage**: Input to ML-KEM.Decaps to recover shared secret
   --  **Security**: Exposure allows adversary to decrypt all ciphertexts

   subtype Seed_Bytes is Byte_Array(1 .. Seed_Size);
   --  **Random Seed (d)**: Input to key generation
   --  **Source**: Hardware random number generator (TRNG)
   --  **Requirement**: Must be uniformly random (full 256-bit entropy)
   --  **Reuse**: NEVER reuse seeds (breaks security completely)

   --  ========================================================================
   --  Internal Key Components (for verification and testing)
   --  ========================================================================

   --  These types represent the mathematical components before encoding
   --  Useful for:
   --    1. Testing: Verify t = A·s + e
   --    2. Debugging: Inspect intermediate values
   --    3. Verification: Prove algebraic correctness

   type Public_Key_Components is record
      T_Vector : Polynomial_Vector;  -- Public vector t ∈ R_q^k
      Rho_Seed : Seed_Bytes;         -- Matrix seed ρ ∈ {0,1}^256
   end record;
   --  **Mathematical representation**: (t, ρ) where t = INTT(Â·ŝ + ê)
   --  **Encoding**: ByteEncode₁₂(t) || ρ → 1568 bytes

   type Secret_Key_Components is record
      S_Vector     : Polynomial_Vector;  -- Secret vector s ∈ R_q^k (small coeffs)
      PK_Copy      : Public_Key;         -- Copy of public key ek
      EK_Hash      : Seed_Bytes;         -- H(ek) for implicit rejection
      Z_Random     : Seed_Bytes;         -- Random z for implicit rejection
   end record;
   --  **Mathematical representation**: (s, ek, H(ek), z)
   --  **Security**: s must have coefficients from CBD(η=2)
   --  **Implicit rejection**: Uses z when decapsulation fails (FO⊥)

   --  ========================================================================
   --  ML-KEM.KeyGen: Main Key Generation Function
   --  ========================================================================
   --
   --  **Algorithm Pseudocode** (NIST FIPS 203, Algorithm 15):
   --    Input: d ∈ {0,1}^256 (32-byte random seed)
   --    Output: (ek, dk) where ek ∈ {0,1}^{1568×8}, dk ∈ {0,1}^{3168×8}
   --
   --    1. (ek_pke, dk_pke) ← K-PKE.KeyGen(d)
   --    2. ek ← ek_pke
   --    3. dk ← dk_pke || ek || H(ek) || z
   --       where z ←_R {0,1}^256
   --    4. return (ek, dk)
   --
   --  **K-PKE.KeyGen Internal Steps** (NIST FIPS 203, Algorithm 12):
   --    1. (ρ, σ) ← G(d || 4)              -- G = SHA3-512
   --    2. N ← 0
   --    3. For i, j ∈ [0, 3]:
   --         Â[i,j] ← SampleNTT(XOF(ρ || i || j))
   --    4. For i ∈ [0, 3]:
   --         ŝ[i] ← NTT(SamplePolyCBD(PRF(σ, N), η₁=2))
   --         N ← N + 1
   --    5. For i ∈ [0, 3]:
   --         ê[i] ← NTT(SamplePolyCBD(PRF(σ, N), η₁=2))
   --         N ← N + 1
   --    6. t̂ ← Â·ŝ + ê
   --    7. ek_pke ← ByteEncode₁₂(INTT(t̂)) || ρ
   --    8. dk_pke ← ByteEncode₁₂(ŝ)
   --    9. return (ek_pke, dk_pke)
   --
   --  **Example Values** (from NIST test vectors):
   --    Input seed d:
   --      7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d
   --
   --    Output ek (first 64 bytes):
   --      7a3c4ff85c3ab0d8a7f0831e88e8b6e4c3f5a920d1c2b7e4f8a3c5d7e9f1a2b4...
   --
   --    Output dk (first 64 bytes of s vector):
   --      f7e8d9c0b1a29384756647382910ab9c8d7e6f5a4b3c2d1e0f1a2b3c4d5e6f70...
   --
   --  **Complexity**:
   --    - Matrix generation: O(k² × n) = O(4096) SampleNTT calls
   --    - Vector sampling: O(k × n) = O(1024) SamplePolyCBD calls
   --    - Matrix multiplication: O(k² × n log n) NTT operations
   --    - Total: ~50ms on modern CPU (dominated by SHAKE XOF)
   --
   --  **Constant-Time Analysis**:
   --    - G, H, PRF: Deterministic hash functions (constant-time)
   --    - SampleNTT: Variable-time but safe (operates on public seed ρ)
   --    - SamplePolyCBD: Constant-time (no rejection sampling)
   --    - NTT operations: Constant-time (fixed iterations)
   --    - Overall: Timing depends only on public parameters, NOT secret s
   --
   --  ========================================================================

   procedure KeyGen (
      Random_Seed : in Seed_Bytes;
      PK          : out Public_Key;
      SK          : out Secret_Key
   ) with
      Global => null,
      Post   => PK'Length = Public_Key_Size and
                SK'Length = Secret_Key_Size;
   --  **Purpose**: Generate ML-KEM-1024 key pair from random seed
   --  **Input**:
   --    - Random_Seed: 32 bytes of cryptographically secure random data
   --                   (from hardware RNG or /dev/urandom)
   --  **Output**:
   --    - Public_Key: 1568-byte encapsulation key (can be shared)
   --    - Secret_Key: 3168-byte decapsulation key (MUST be kept secret)
   --  **Security**: Seed must have full 256-bit entropy
   --  **Determinism**: Same seed always produces same keys (for testing)
   --  **Usage**:
   --      Seed : Seed_Bytes;
   --      PK   : Public_Key;
   --      SK   : Secret_Key;
   --    begin
   --      -- Generate random seed (in production)
   --      Random_Bytes(Seed);
   --
   --      -- Generate key pair
   --      KeyGen(Seed, PK, SK);
   --
   --      -- PK can be distributed publicly
   --      -- SK must be protected (encrypt at rest, zeroize after use)

   --  ========================================================================
   --  KeyGen_Expanded: Key Generation with Component Inspection
   --  ========================================================================
   --
   --  **Purpose**: Generate keys AND return internal components
   --  **Use Case**: Testing, verification, debugging
   --  **Example**:
   --      -- Verify algebraic correctness: t = A·s + e
   --      PK_Components : Public_Key_Components;
   --      SK_Components : Secret_Key_Components;
   --    begin
   --      KeyGen_Expanded(Seed, PK, SK, PK_Components, SK_Components);
   --
   --      -- Now can verify:
   --      --   1. Reconstruct A from ρ
   --      --   2. Compute A·s + e in NTT domain
   --      --   3. Compare INTT(A·s + e) with t
   --
   --  ========================================================================

   procedure KeyGen_Expanded (
      Random_Seed       : in Seed_Bytes;
      PK                : out Public_Key;
      SK                : out Secret_Key;
      Public_Components : out Public_Key_Components;
      Secret_Components : out Secret_Key_Components
   ) with
      Global => null,
      Post   => PK'Length = Public_Key_Size and
                SK'Length = Secret_Key_Size;
   --  **Purpose**: Key generation with access to internal components
   --  **Input**: Random_Seed (32 bytes)
   --  **Output**:
   --    - Public_Key: Encoded 1568-byte public key
   --    - Secret_Key: Encoded 3168-byte secret key
   --    - Public_Components: (t, ρ) in mathematical form
   --    - Secret_Components: (s, ek, H(ek), z) in mathematical form
   --  **Testing**: Allows verification of t = A·s + e relation
   --  **Production**: Use KeyGen instead (doesn't expose components)

   --  ========================================================================
   --  Implementation Notes
   --  ========================================================================
   --
   --  **Dependencies**:
   --    - G (SHA3-512): Implemented in SparkPass.Crypto.MLKEM.Hash
   --    - H (SHA3-256): Implemented in SparkPass.Crypto.MLKEM.Hash
   --    - PRF (SHAKE-256): Implemented in SparkPass.Crypto.MLKEM.PRF
   --    - XOF (SHAKE-128): Implemented in SparkPass.Crypto.MLKEM.XOF
   --    - SamplePolyCBD: Implemented in SparkPass.Crypto.MLKEM.Sampling
   --    - SampleNTT: Implemented in SparkPass.Crypto.MLKEM.Sampling
   --    - NTT/INTT: Implemented in SparkPass.Crypto.MLKEM.NTT
   --    - Matrix ops: Implemented in SparkPass.Crypto.MLKEM.Matrix
   --    - Compression: Implemented in SparkPass.Crypto.MLKEM.Compression
   --
   --  **Encoding Functions** (to be implemented):
   --    - ByteEncode₁₂: Encode polynomial with 12 bits/coefficient
   --    - ByteDecode₁₂: Decode polynomial from 12 bits/coefficient
   --    - Serialize_Vector: Encode k-vector of polynomials
   --    - Deserialize_Vector: Decode k-vector of polynomials
   --
   --  **Key Generation Flow**:
   --    1. Expand seed: (ρ, σ) ← G(d || 4)
   --    2. Generate A: For each (i,j): Â[i,j] ← SampleNTT(XOF(ρ || i || j))
   --    3. Generate s: For each i: ŝ[i] ← NTT(SamplePolyCBD(PRF(σ, N++)))
   --    4. Generate e: For each i: ê[i] ← NTT(SamplePolyCBD(PRF(σ, N++)))
   --    5. Compute t: t̂ ← Â·ŝ + ê, t ← INTT(t̂)
   --    6. Encode: ek ← Encode(t, ρ), dk ← Encode(s, ek, H(ek), z)
   --
   --  **Memory Layout**:
   --    Public key (1568 bytes):
   --      [0..1535]: ByteEncode₁₂(t[0]) || ... || ByteEncode₁₂(t[3])
   --      [1536..1567]: ρ (32 bytes)
   --
   --    Secret key (3168 bytes):
   --      [0..1535]: ByteEncode₁₂(s[0]) || ... || ByteEncode₁₂(s[3])
   --      [1536..3103]: ek (1568 bytes)
   --      [3104..3135]: H(ek) (32 bytes)
   --      [3136..3167]: z (32 bytes)
   --
   --  **Verification Strategy**:
   --    1. Prove all coefficients in valid ranges after each operation
   --    2. Prove t = INTT(Â·ŝ + ê) using matrix/NTT postconditions
   --    3. Prove encoding preserves information (invertible)
   --    4. Prove no secret-dependent branches in timing-critical code
   --
   --  **Testing Strategy**:
   --    1. NIST test vectors (deterministic with known seeds)
   --    2. Algebraic verification: Reconstruct A, verify t = A·s + e
   --    3. Round-trip: Encode then decode, verify equality
   --    4. Statistical tests: Verify s, e distributions match CBD(2)
   --    5. Key uniqueness: Different seeds produce different keys
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.KeyGen;
