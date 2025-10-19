pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;
with SparkPass.Types; use SparkPass.Types;

--  ========================================================================
--  ML-KEM-1024 Sampling Functions (NIST FIPS 203)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4.2.2 (Sampling)
--              Algorithm 6 (SamplePolyCBD)
--              Algorithm 7 (SampleNTT)
--
--  **Purpose**: Generate pseudorandom polynomials for ML-KEM key generation
--               and encryption using extendable-output functions (XOFs)
--
--  **Sampling Methods**:
--
--  1. **Centered Binomial Distribution (CBD)**:
--     - Used for secret key and error polynomials
--     - Parameter η controls noise magnitude
--     - For ML-KEM-1024: η₁ = η₂ = 2
--     - Produces small coefficients with binomial distribution
--
--  2. **Uniform Sampling (Rejection)**:
--     - Used for public matrix A
--     - Uniformly samples from Z_q = {0, 1, ..., q-1}
--     - Uses rejection sampling to ensure uniformity
--
--  **Mathematical Foundation**:
--
--  CBD(η) Distribution:
--    - Sample 2η bits: (a₀, a₁, ..., a_{η-1}, b₀, b₁, ..., b_{η-1})
--    - Compute: x = Σᵢ aᵢ - Σᵢ bᵢ
--    - Result: x ∈ [-η, η] with binomial probability
--
--  Example (η=2):
--    - Sample 4 bits: (a₀, a₁, b₀, b₁)
--    - x = (a₀ + a₁) - (b₀ + b₁)
--    - Possible values: {-2, -1, 0, 1, 2}
--    - Distribution: P(x=0) = 3/8, P(x=±1) = 1/4, P(x=±2) = 1/16
--
--  Uniform Sampling (Rejection):
--    - Read 3 bytes from XOF
--    - Interpret as two 12-bit values d₁, d₂
--    - If dᵢ < q, accept as coefficient
--    - If dᵢ ≥ q, reject and continue
--    - Ensures uniform distribution over [0, q-1]
--
--  **XOF (Extendable-Output Function)**:
--  - ML-KEM uses SHAKE-128 and SHAKE-256 (from FIPS 202)
--  - SHAKE-128: 128-bit security (for public matrix A)
--  - SHAKE-256: 256-bit security (for secret/error vectors)
--  - Provides arbitrary-length pseudorandom output
--
--  **ML-KEM-1024 Parameters**:
--  - η₁ = 2 (secret vector s noise)
--  - η₂ = 2 (error vector e noise)
--  - q = 3329
--  - n = 256 (polynomial degree)
--  - k = 4 (rank of matrix/vector)
--
--  **Security Considerations**:
--  - CBD provides constant-time sampling (no rejection, fixed iterations)
--  - Uniform sampling has variable time due to rejection, but independent of secret
--  - XOF output must be cryptographically secure (SHAKE provides this)
--  - Seed/nonce must be unique for each polynomial to ensure independence
--
--  **Implementation Strategy**:
--  - Use PRF (G) from SparkPass.Crypto.MLKEM.PRF for XOF instantiation
--  - SamplePolyCBD: Read 64η bytes (for 256 coefficients), process in parallel
--  - SampleNTT: Rejection sampling with 3-byte chunks until 256 coefficients
--  - Both functions are deterministic given seed and nonce
--
--  **SPARK Verification**:
--  - Bronze: Prove no overflow, all results in valid ranges
--  - Silver: Prove statistical properties (distribution correctness)
--  - Platinum: Prove FIPS 203 compliance and timing independence
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.Sampling is
   

   --  ========================================================================
   --  SamplePolyCBD: Sample from Centered Binomial Distribution
   --  ========================================================================
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 6):
   --    Input: byte stream B ∈ {0,1}^{64η} (from XOF), parameter η
   --    Output: polynomial f ∈ R_q with coefficients from CBD(η)
   --
   --    for i = 0 to 255:
   --      x ← Σⱼ₌₀^{η-1} B[2iη + j]      -- sum of first η bits
   --      y ← Σⱼ₌₀^{η-1} B[2iη + η + j]  -- sum of second η bits
   --      f[i] ← x - y mod q
   --    return f
   --
   --  **Example Calculation** (η=2, i=0, bits=[1,0,1,1,...]):
   --    x = B[0] + B[1] = 1 + 0 = 1
   --    y = B[2] + B[3] = 1 + 1 = 2
   --    f[0] = (1 - 2) mod 3329 = -1 mod 3329 = 3328
   --
   --  **Byte Stream Format**:
   --    For η=2, each coefficient needs 4 bits (2η)
   --    Total: 256 coefficients × 4 bits = 1024 bits = 128 bytes
   --
   --    Byte layout (little-endian bit order):
   --      Coefficient 0: bits [0..3]   (a₀, a₁, b₀, b₁)
   --      Coefficient 1: bits [4..7]   (a₀, a₁, b₀, b₁)
   --      Coefficient 2: bits [8..11]  (a₀, a₁, b₀, b₁)
   --      ...
   --
   --  **Constant-Time Guarantee**:
   --    - No rejection sampling (always exactly 256 coefficients)
   --    - Fixed number of iterations (256)
   --    - No secret-dependent branches
   --    - Execution time depends only on η (public parameter)
   --
   --  **Complexity**: O(n) where n=256 (constant time)
   --
   --  ========================================================================

   procedure SamplePolyCBD (
      Byte_Stream : in Byte_Array;
      Eta : in Positive;
      Poly : out Polynomial
   ) with
      Global => null,
      Pre    => Eta in 1 .. 3 and then
                Byte_Stream'Length = 64 * Eta,
      Post   => (for all I in Polynomial'Range => Poly(I) in 0 .. Q - 1);
   --  **Purpose**: Sample polynomial from centered binomial distribution
   --  **Input**:
   --    - Byte_Stream: 64η bytes from XOF (SHAKE-256(seed || nonce))
   --    - Eta: CBD parameter (η = 2 for ML-KEM-1024)
   --  **Output**: Polynomial with coefficients from CBD(η)
   --  **Usage**:
   --    - Secret vector s generation: SamplePolyCBD(PRF(d, N), η₁)
   --    - Error vector e generation: SamplePolyCBD(PRF(d, N), η₂)
   --  **Distribution**: Coefficients centered at 0 with spread ±η

   --  ========================================================================
   --  SampleNTT: Sample Uniformly from R_q in NTT Representation
   --  ========================================================================
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 7):
   --    Input: byte stream B from XOF (SHAKE-128(ρ || i || j))
   --    Output: polynomial â ∈ R̂_q (NTT representation)
   --
   --    i ← 0, j ← 0
   --    while i < 256:
   --      d₁ ← B[j] + 256·(B[j+1] mod 16)      -- first 12-bit value
   --      d₂ ← ⌊B[j+1]/16⌋ + 16·B[j+2]         -- second 12-bit value
   --      if d₁ < q:
   --        â[i] ← d₁
   --        i ← i + 1
   --      if d₂ < q and i < 256:
   --        â[i] ← d₂
   --        i ← i + 1
   --      j ← j + 3
   --    return â
   --
   --  **Example Calculation** (bytes=[0xAB, 0xCD, 0xEF]):
   --    Binary: AB=10101011, CD=11001101, EF=11101111
   --
   --    d₁ = 0xAB + 256·(0xCD mod 16)
   --       = 171 + 256·13 = 171 + 3328 = 3499
   --    Check: 3499 ≥ 3329, REJECT d₁
   --
   --    d₂ = ⌊0xCD/16⌋ + 16·0xEF
   --       = 12 + 16·239 = 12 + 3824 = 3836
   --    Check: 3836 ≥ 3329, REJECT d₂
   --
   --    Continue to next 3 bytes...
   --
   --  **Byte Packing Format** (12-bit values in 3 bytes):
   --    Byte 0: d₁[0..7]    (low 8 bits of d₁)
   --    Byte 1: d₁[8..11] | d₂[0..3]  (high 4 bits of d₁, low 4 bits of d₂)
   --    Byte 2: d₂[4..11]   (high 8 bits of d₂)
   --
   --  **Rejection Sampling**:
   --    - Max value from 12 bits: 4095
   --    - Valid range: [0, 3328] (q-1)
   --    - Rejection rate: (4096 - 3329) / 4096 ≈ 18.7%
   --    - Expected bytes: 256 × 3 × (1 / 0.813) ≈ 945 bytes
   --    - Worst case: unbounded (but probability exponentially decreasing)
   --
   --  **Variable-Time but Safe**:
   --    - Number of iterations depends on XOF output (public randomness)
   --    - NOT secret-dependent (matrix A is public)
   --    - Timing variation acceptable for public matrix generation
   --
   --  **Complexity**: O(n) expected, where n=256 coefficients
   --
   --  ========================================================================

   procedure SampleNTT (
      XOF_Stream : in Byte_Array;
      Poly : out Polynomial;
      Bytes_Consumed : out Natural
   ) with
      Global => null,
      Pre    => XOF_Stream'Length >= 672,  -- 256 × 3 × 0.88 buffer
      Post   => (for all I in Polynomial'Range => Poly(I) in 0 .. Q - 1) and
                Bytes_Consumed <= XOF_Stream'Length;
   --  **Purpose**: Sample polynomial uniformly from Z_q in NTT representation
   --  **Input**:
   --    - XOF_Stream: Byte stream from XOF (SHAKE-128(ρ || i || j))
   --    - Must be at least 672 bytes (generous buffer for rejection sampling)
   --  **Output**:
   --    - Poly: Uniformly sampled polynomial â in NTT domain
   --    - Bytes_Consumed: Number of bytes read from XOF_Stream
   --  **Usage**: Public matrix A generation: Â[i,j] = SampleNTT(XOF(ρ || i || j))
   --  **Distribution**: Each coefficient uniformly distributed in [0, q-1]

   --  ========================================================================
   --  Helper: BytesToBits (for SamplePolyCBD)
   --  ========================================================================

   function Get_Bit (Bytes : Byte_Array; Bit_Index : Natural) return Natural with
      Global => null,
      Pre    => Bit_Index / 8 < Bytes'Length,
      Post   => Get_Bit'Result in 0 .. 1;
   --  **Purpose**: Extract single bit from byte array
   --  **Input**: Byte array and bit index (0 = LSB of first byte)
   --  **Output**: Bit value (0 or 1)

   --  ========================================================================
   --  Implementation Notes
   --  ========================================================================
   --
   --  **XOF Integration**:
   --    - Use PRF from SparkPass.Crypto.MLKEM.PRF (wraps SHAKE)
   --    - PRF(seed, nonce) produces deterministic byte stream
   --    - Each polynomial gets unique (seed, nonce) pair
   --
   --  **SamplePolyCBD Implementation Strategy**:
   --    1. For each coefficient i ∈ [0, 255]:
   --       a. Extract 2η bits starting at bit position 2ηi
   --       b. Sum first η bits → x
   --       c. Sum second η bits → y
   --       d. Compute (x - y) mod q
   --    2. No rejection needed (always 256 coefficients)
   --    3. Constant-time (fixed iterations)
   --
   --  **SampleNTT Implementation Strategy**:
   --    1. Initialize coefficient counter i = 0, byte position j = 0
   --    2. While i < 256:
   --       a. Read 3 bytes: B[j], B[j+1], B[j+2]
   --       b. Extract d₁ (12 bits): B[j] + 256·(B[j+1] mod 16)
   --       c. Extract d₂ (12 bits): ⌊B[j+1]/16⌋ + 16·B[j+2]
   --       d. If d₁ < q: accept â[i] ← d₁, i++
   --       e. If d₂ < q and i < 256: accept â[i] ← d₂, i++
   --       f. j ← j + 3
   --    3. Return Bytes_Consumed = j
   --
   --  **Overflow Prevention**:
   --    - SamplePolyCBD: Max sum = η (for η=2: max 2), fits in Natural
   --    - SampleNTT: 12-bit values max 4095, fits in Integer
   --    - All arithmetic uses Integer intermediate types
   --
   --  **Verification Strategy**:
   --    1. Prove all bit/byte accesses within bounds
   --    2. Prove all coefficients in [0, q-1]
   --    3. Prove SampleNTT terminates (probabilistic argument)
   --    4. Prove constant-time for SamplePolyCBD
   --
   --  **Testing Strategy**:
   --    1. Test SamplePolyCBD output distribution (chi-squared test)
   --    2. Test SampleNTT uniformity (Kolmogorov-Smirnov test)
   --    3. Verify against NIST test vectors
   --    4. Test edge cases (all-zero bytes, all-one bytes)
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Sampling;
