pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with SparkPass.Types; use SparkPass.Types;

--  ========================================================================
--  ML-KEM-1024 Type Definitions (NIST FIPS 203, August 2024)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4 (Parameters)
--              Table 2 (page 39) - ML-KEM-1024 Parameter Set
--
--  **Security Level**: Category 5 (256-bit quantum security)
--
--  **Mathematical Foundation**:
--  - Ring: R_q = Z_q[X]/(X^256 + 1) - cyclotomic polynomial ring
--  - Modulus: q = 3329 (prime)
--  - Module rank: k = 4 (lattice dimension)
--  - NTT: Number-Theoretic Transform for polynomial multiplication
--
--  **Design Rationale**:
--  1. All array indices start at 0 to match FIPS 203 notation
--  2. Coefficient type enforces range [0, q-1] via subtype
--  3. Fixed-size arrays prevent dynamic allocation (SPARK requirement)
--  4. Byte arrays use 1-based indexing to match SparkPass.Types.Byte_Array
--
--  **Security Properties**:
--  - IND-CCA2 security under Module-LWE hardness assumption
--  - Decapsulation failure probability: δ = 2^(-174.8)
--  - Post-quantum secure (resistant to Shor's algorithm)
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.Types is

   --  ========================================================================
   --  ML-KEM-1024 Parameters (FIPS 203 Table 2, Page 39)
   --  ========================================================================

   --  Module rank (lattice dimension)
   --  Determines size of public/secret keys and ciphertext
   K : constant := 4;

   --  Polynomial degree (coefficients per ring element)
   --  All polynomials are elements of Z_q[X]/(X^256 + 1)
   N : constant := 256;

   --  Modulus for coefficient ring (prime)
   --  Chosen such that q ≡ 1 (mod 2n) for efficient NTT
   --  q = 13 × 256 + 1 = 3329
   Q : constant := 3329;

   --  Noise distribution parameter for key generation
   --  Controls magnitude of secret key coefficients: {-η₁, ..., η₁}
   Eta_1 : constant := 2;

   --  Noise distribution parameter for encryption
   --  Controls magnitude of error terms: {-η₂, ..., η₂}
   Eta_2 : constant := 2;

   --  Compression parameter for ciphertext vector u
   --  Each coefficient compressed to d_u bits
   D_U : constant := 11;

   --  Compression parameter for ciphertext scalar v
   --  Each coefficient compressed to d_v bits
   D_V : constant := 5;

   --  ========================================================================
   --  Core Algebraic Types
   --  ========================================================================

   --  Coefficient in Z_q (modular arithmetic mod q)
   --  **Security Property**: All coefficients proven to be in [0, q-1]
   --  **SPARK Verification**: Subtype ensures no overflow in modular ops
   subtype Coefficient is Integer range 0 .. Q - 1;

   --  Polynomial with 256 coefficients (element of R_q)
   --  **Indexing**: 0 .. 255 to match FIPS 203 notation
   --  **Representation**: Coefficient form (not NTT domain by default)
   --  **SPARK Verification**: Fixed size prevents heap allocation
   type Polynomial is array (0 .. N - 1) of Coefficient
     with Pack;

   --  Vector of k polynomials (element of R_q^k)
   --  Used for public key matrix rows, secret keys, ciphertexts
   --  **Size**: 4 polynomials × 256 coefficients = 1,024 coefficients
   type Polynomial_Vector is array (0 .. K - 1) of Polynomial
     with Pack;

   --  Matrix of k×k polynomials (element of R_q^(k×k))
   --  Used for public key matrix A
   --  **Size**: 4×4 = 16 polynomials
   --  **Generation**: Via XOF from seed (deterministic expansion)
   type Polynomial_Matrix is array (0 .. K - 1, 0 .. K - 1) of Polynomial
     with Pack;

   --  ========================================================================
   --  Byte Encoding Types (FIPS 203 Section 5)
   --  ========================================================================
   --
   --  **Note**: These types use 1-based indexing to match SparkPass.Types
   --            conversion functions handle index translation
   --
   --  **Encoding Schemes**:
   --  - Polynomials: ByteEncode/ByteDecode (12 bits per coefficient for q=3329)
   --  - Public key: Concatenation of k polynomials + seed
   --  - Secret key: Concatenation of secret polynomials + additional data
   --  - Ciphertext: Compressed u (d_u bits) + compressed v (d_v bits)
   --
   --  ========================================================================

   --  32-byte seed for deterministic key generation
   --  Used for: ρ (public matrix seed), σ (PRF seed), H (hash)
   subtype Seed_Array is Byte_Array (1 .. 32);

   --  Public key (encapsulation key): 1568 bytes
   --  **Structure**: (12·k·n/8) + 32 = (12·4·256/8) + 32 = 1536 + 32
   --  **Components**: k polynomials (1536 bytes) + seed ρ (32 bytes)
   --  **FIPS 203**: Algorithm 13, line 13 (K-PKE.KeyGen output)
   subtype Public_Key_Array is Byte_Array (1 .. 1568);

   --  Secret key (decapsulation key): 3168 bytes
   --  **Structure**: dk = (dk_PKE || ek || H(ek) || z)
   --  **Sizes**: 1536 + 1568 + 32 + 32 = 3168 bytes
   --  **Components**:
   --    - dk_PKE: secret polynomial vector (1536 bytes)
   --    - ek: public key (1568 bytes)
   --    - H(ek): hash of public key (32 bytes)
   --    - z: implicit rejection value (32 bytes)
   --  **FIPS 203**: Algorithm 15, line 8 (ML-KEM.KeyGen output)
   subtype Secret_Key_Array is Byte_Array (1 .. 3168);

   --  Ciphertext: 1568 bytes
   --  **Structure**: (32·d_u·k/8) + (32·d_v/8) = (32·11·4/8) + (32·5/8) = 1408 + 160
   --  **Components**:
   --    - u: compressed polynomial vector (1408 bytes, d_u=11 bits/coeff)
   --    - v: compressed polynomial (160 bytes, d_v=5 bits/coeff)
   --  **FIPS 203**: Algorithm 17, line 13 (ML-KEM.Encaps output)
   subtype Ciphertext_Array is Byte_Array (1 .. 1568);

   --  Shared secret: 32 bytes
   --  **Generation**: K = SHA3-256(K' || H(c))
   --  **FIPS 203**: Algorithm 17, line 14 (ML-KEM.Encaps output)
   --               Algorithm 18, line 11 (ML-KEM.Decaps output)
   subtype Shared_Secret_Array is Byte_Array (1 .. 32);

   --  ========================================================================
   --  Derived Constants for Byte Encoding
   --  ========================================================================

   --  Bytes per polynomial in NTT form (12 bits per coefficient)
   --  **Calculation**: (256 coefficients × 12 bits) / 8 = 384 bytes
   --  **FIPS 203**: Section 5.1 (ByteEncode)
   Bytes_Per_Polynomial : constant := (12 * N) / 8;  -- 384 bytes

   --  Bytes per compressed polynomial (u component)
   --  **Calculation**: (256 coefficients × 11 bits) / 8 = 352 bytes
   Bytes_Per_U_Poly : constant := (D_U * N) / 8;  -- 352 bytes

   --  Bytes per compressed polynomial (v component)
   --  **Calculation**: (256 coefficients × 5 bits) / 8 = 160 bytes
   Bytes_Per_V_Poly : constant := (D_V * N) / 8;  -- 160 bytes

   --  Total bytes for secret polynomial vector
   --  **Calculation**: 4 polynomials × 384 bytes = 1536 bytes
   Secret_Vector_Bytes : constant := K * Bytes_Per_Polynomial;  -- 1536 bytes

   --  Total bytes for ciphertext u component
   --  **Calculation**: 4 polynomials × 352 bytes = 1408 bytes
   Ciphertext_U_Bytes : constant := K * Bytes_Per_U_Poly;  -- 1408 bytes

   --  ========================================================================
   --  ========================================================================
   --  Helper Functions (for initialization and zeroization)
   --  ========================================================================
   --
   --  **Note**: Constants removed due to SPARK preelaborate restrictions
   --            Use these functions instead for zero initialization
   --
   --  ========================================================================

   function Zero_Polynomial return Polynomial is ((others => 0));
   --  **Purpose**: Return zero polynomial (additive identity in R_q)
   --  **Usage**: Initialization, error handling, zeroization

end SparkPass.Crypto.MLKEM.Types;
