pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

--  ========================================================================
--  ML-KEM-1024 Polynomial Operations (NIST FIPS 203)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4 (Polynomial Arithmetic)
--              Algorithms 9-11 (NTT operations) - to be implemented in Phase 2.2
--
--  **Purpose**: Basic polynomial operations in R_q = Z_q[X]/(X^256 + 1)
--
--  **Ring Structure**:
--  - Coefficient ring: Z_q where q = 3329 (prime)
--  - Polynomial ring: R_q = Z_q[X]/(X^256 + 1)
--  - Reduction polynomial: X^256 + 1 (cyclotomic)
--
--  **Operations Implemented** (Phase 2.1):
--  1. Zero polynomial (initialization)
--  2. Polynomial addition (coefficient-wise)
--  3. Polynomial subtraction (coefficient-wise)
--
--  **Future Operations** (Phase 2.2+):
--  4. NTT (Number-Theoretic Transform) - forward transform
--  5. INTT (Inverse NTT) - inverse transform
--  6. Polynomial multiplication via NTT (pointwise multiply in NTT domain)
--  7. Compression/decompression for ciphertext encoding
--  8. Sampling from centered binomial distribution (CBD)
--  9. Rejection sampling for matrix generation
--
--  **Design Philosophy**:
--  - Explicit output parameters (not functions) for large types
--  - Coefficient-wise operations proven separately from NTT
--  - Clear separation between representation domains (coefficient vs NTT)
--
--  **SPARK Contracts**:
--  - Postconditions specify exact mathematical properties
--  - Quantified expressions verify all coefficients
--  - Range preservation proven automatically
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.Poly is
   

   --  ========================================================================
   --  Initialization and Zero Values
   --  ========================================================================

   function Zero_Poly return Polynomial with
      Global => null,
      Post   => (for all I in Polynomial'Range => Zero_Poly'Result(I) = 0);
   --  **Purpose**: Return zero polynomial (additive identity in R_q)
   --  **Output**: Polynomial with all coefficients = 0
   --  **Usage**: Initialization, zeroization, error handling
   --  **Complexity**: O(1) - constant reference
   --  **Note**: Could use Types.Zero_Poly constant directly, but this
   --            function provides explicit SPARK contract

   --  ========================================================================
   --  Polynomial Addition (Ring Operation)
   --  ========================================================================
   --
   --  **Mathematical Definition**:
   --    Let a(X) = Σ aᵢXⁱ and b(X) = Σ bᵢXⁱ in R_q
   --    Then c(X) = a(X) + b(X) = Σ (aᵢ + bᵢ mod q)Xⁱ
   --
   --  **Algorithm**:
   --    For i = 0 to n-1:
   --      c[i] ← (a[i] + b[i]) mod q
   --
   --  **Complexity**: O(n) = O(256) = 256 modular additions
   --
   --  **Security Note**: Not constant-time (uses conditional subtraction in Mod_Add)
   --                     Acceptable for ML-KEM since inputs are public or fresh randomness
   --
   --  ========================================================================

   procedure Add (
      A : in Polynomial;
      B : in Polynomial;
      C : out Polynomial
   ) with
      Global => null,
      Post   => (for all I in Polynomial'Range =>
                   C(I) = ((A(I) + B(I)) mod Q));
   --  **Purpose**: Add two polynomials coefficient-wise in R_q
   --  **Inputs**: A, B - polynomials in R_q (coefficients in [0, q-1])
   --  **Output**: C - polynomial sum A + B in R_q
   --  **Verification**: SPARK proves all coefficients in [0, q-1]
   --  **Note**: Postcondition uses Ada mod operator for specification clarity
   --            Implementation calls Mod_Add which handles range normalization

   --  ========================================================================
   --  Polynomial Subtraction (Ring Operation)
   --  ========================================================================
   --
   --  **Mathematical Definition**:
   --    Let a(X) = Σ aᵢXⁱ and b(X) = Σ bᵢXⁱ in R_q
   --    Then c(X) = a(X) - b(X) = Σ (aᵢ - bᵢ mod q)Xⁱ
   --
   --  **Algorithm**:
   --    For i = 0 to n-1:
   --      c[i] ← (a[i] - b[i]) mod q
   --
   --  **Complexity**: O(n) = O(256) = 256 modular subtractions
   --
   --  **Note**: Ada's mod operator is symmetric (can return negative values)
   --            Our Mod_Sub ensures result is in [0, q-1]
   --
   --  ========================================================================

   procedure Sub (
      A : in Polynomial;
      B : in Polynomial;
      C : out Polynomial
   ) with
      Global => null,
      Post   => (for all I in Polynomial'Range =>
                   C(I) = ((A(I) - B(I) + Q) mod Q));
   --  **Purpose**: Subtract two polynomials coefficient-wise in R_q
   --  **Inputs**: A, B - polynomials in R_q (coefficients in [0, q-1])
   --  **Output**: C - polynomial difference A - B in R_q
   --  **Verification**: SPARK proves all coefficients in [0, q-1]
   --  **Note**: Postcondition uses (A(I) - B(I) + Q) mod Q to match Ada semantics
   --            This ensures non-negative result for specification

   --  ========================================================================
   --  Vector Operations (To Be Implemented in Phase 2.2)
   --  ========================================================================
   --
   --  Future procedures for polynomial vectors:
   --
   --  procedure Add_Vector (A, B : Polynomial_Vector; C : out Polynomial_Vector);
   --    Component-wise addition of k polynomials
   --
   --  procedure Sub_Vector (A, B : Polynomial_Vector; C : out Polynomial_Vector);
   --    Component-wise subtraction of k polynomials
   --
   --  procedure Mul_Vector_By_Poly (V : Polynomial_Vector; P : Polynomial; Result : out Polynomial_Vector);
   --    Multiply each polynomial in vector by scalar polynomial
   --
   --  procedure Inner_Product_NTT (A, B : Polynomial_Vector; Result : out Polynomial);
   --    Compute Σ (aᵢ × bᵢ) in NTT domain (for encryption/decryption)
   --
   --  ========================================================================

   --  ========================================================================
   --  Matrix Operations (To Be Implemented in Phase 2.2)
   --  ========================================================================
   --
   --  Future procedures for polynomial matrices:
   --
   --  procedure Matrix_Vector_Mul_NTT (
   --    A : Polynomial_Matrix;
   --    V : Polynomial_Vector;
   --    Result : out Polynomial_Vector
   --  );
   --    Compute A × V in NTT domain (for key generation and encryption)
   --
   --  ========================================================================

   --  ========================================================================
   --  NTT Operations (To Be Implemented in Phase 2.2)
   --  ========================================================================
   --
   --  **NTT (Number-Theoretic Transform)**:
   --    Forward transform: Coefficient form → NTT form
   --    Algorithm: Cooley-Tukey butterfly network (7 layers, 128 butterflies/layer)
   --    Source: FIPS 203 Algorithm 9
   --
   --  procedure NTT (Input : in Polynomial; Output : out Polynomial);
   --
   --  **INTT (Inverse NTT)**:
   --    Inverse transform: NTT form → Coefficient form
   --    Algorithm: Gentleman-Sande butterfly network + normalization
   --    Source: FIPS 203 Algorithm 10
   --
   --  procedure INTT (Input : in Polynomial; Output : out Polynomial);
   --
   --  **Pointwise Multiplication in NTT Domain**:
   --    Multiply two polynomials in NTT representation
   --    Algorithm: Basemul (2 coefficients per multiplication)
   --    Source: FIPS 203 Algorithm 11
   --
   --  procedure Multiply_NTT (A, B : in Polynomial; C : out Polynomial);
   --
   --  **Twiddle Factors**:
   --    Precomputed roots of unity for NTT
   --    Generation: ζ = 17 (primitive 512-th root of unity mod 3329)
   --    Storage: 128 values (bit-reversed order for Cooley-Tukey)
   --
   --  ========================================================================

   --  ========================================================================
   --  Compression/Decompression (To Be Implemented in Phase 2.3)
   --  ========================================================================
   --
   --  **Compress**:
   --    Reduce coefficient precision from 12 bits to d bits
   --    Formula: Compress_d(x) = ⌊(2^d / q) × x⌉ mod 2^d
   --    Used for: Ciphertext encoding (d_u = 11, d_v = 5)
   --
   --  **Decompress**:
   --    Expand coefficient precision from d bits to 12 bits
   --    Formula: Decompress_d(x) = ⌊(q / 2^d) × x⌉
   --    Used for: Ciphertext decoding
   --
   --  ========================================================================

   --  ========================================================================
   --  Sampling Operations (To Be Implemented in Phase 2.4)
   --  ========================================================================
   --
   --  **SamplePolyCBD** (Centered Binomial Distribution):
   --    Sample polynomial with small coefficients from CBD
   --    Source: FIPS 203 Algorithm 7
   --    Parameters: η ∈ {2, 3} (noise level)
   --
   --  **SampleNTT** (Rejection Sampling):
   --    Sample uniform polynomial in NTT domain
   --    Source: FIPS 203 Algorithm 12
   --    Input: SHAKE-128 XOF stream
   --    Output: Polynomial with coefficients uniformly in [0, q-1]
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Poly;
