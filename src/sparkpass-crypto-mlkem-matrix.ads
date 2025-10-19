pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

--  ========================================================================
--  ML-KEM-1024 Matrix and Vector Operations (NIST FIPS 203)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4.4 (ML-KEM Algorithms)
--              Algorithm 12 (K-PKE.KeyGen)
--              Algorithm 13 (K-PKE.Encrypt)
--              Algorithm 14 (K-PKE.Decrypt)
--
--  **Purpose**: Linear algebra operations over module-lattice R_q^k
--
--  **Mathematical Foundation**:
--  - Module rank k = 4 (ML-KEM-1024)
--  - Ring R_q = Z_q[X]/(X^256 + 1)
--  - All operations in NTT representation for efficiency
--  - Polynomial multiplication via NTT (O(n log n) vs O(n²))
--
--  **Key Operations**:
--
--  1. **Vector Addition**: v₃ = v₁ + v₂ (component-wise)
--     - Used in: Key generation (A·s + e), Encryption (t + e₁)
--     - Complexity: O(kn) = O(4·256) = 1024 coefficient additions
--
--  2. **Dot Product**: p = v₁ · v₂ = Σᵢ v₁[i] × v₂[i]
--     - Used in: Encryption (tᵀ·r), Decryption (sᵀ·u)
--     - Complexity: O(kn log n) for k NTT multiplications
--
--  3. **Matrix-Vector Multiplication**: v = A·u
--     - Used in: Key generation (A·s), Encryption (Aᵀ·r)
--     - Complexity: O(k²n log n) for k² NTT multiplications
--
--  **NTT Representation**:
--  - All input vectors/matrices assumed in NTT domain
--  - Polynomial multiplication via Poly_Multiply (element-wise in NTT)
--  - Addition remains coefficient-wise (same in both domains)
--  - Result returned in NTT domain
--
--  **Example Workflow** (Key Generation):
--    1. Generate matrix A in NTT form: Â = NTT(SampleNTT(...))
--    2. Generate secret s: ŝ = NTT(SamplePolyCBD(...))
--    3. Generate error e: ê = NTT(SamplePolyCBD(...))
--    4. Compute public key: t̂ = Matrix_Vector_Mul(Â, ŝ) + ê
--    5. Return (t, A seed) where t = INTT(t̂)
--
--  **Security Properties**:
--  - Operations are deterministic and constant-time
--  - No secret-dependent branches (addition is always full-length)
--  - NTT domain prevents timing leaks from polynomial multiplication
--
--  **SPARK Verification**:
--  - Bronze: Prove no overflow, all results in valid coefficient ranges
--  - Silver: Prove algebraic correctness (distributivity, associativity)
--  - Platinum: Prove FIPS 203 compliance
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.Matrix is
   

   --  ========================================================================
   --  Vector_Add: Component-wise Vector Addition
   --  ========================================================================
   --
   --  **Mathematical Definition**:
   --    (v₁ + v₂)[i] = v₁[i] + v₂[i] mod q, for i ∈ [0, k-1]
   --
   --  **Algorithm Pseudocode**:
   --    Input: v₁, v₂ ∈ R̂_q^k (vectors in NTT domain)
   --    Output: v₃ ∈ R̂_q^k where v₃ = v₁ + v₂
   --
   --    for i = 0 to k-1:
   --      for j = 0 to n-1:
   --        v₃[i][j] = (v₁[i][j] + v₂[i][j]) mod q
   --    return v₃
   --
   --  **Example** (k=4, showing first coefficient of each polynomial):
   --    v₁ = [[1000, ...], [2000, ...], [3000, ...], [100, ...]]
   --    v₂ = [[500, ...],  [1000, ...], [200, ...],  [50, ...]]
   --    result = [[1500, ...], [3000, ...], [3200, ...], [150, ...]]
   --
   --  **Properties**:
   --  - Commutative: v₁ + v₂ = v₂ + v₁
   --  - Associative: (v₁ + v₂) + v₃ = v₁ + (v₂ + v₃)
   --  - Identity: v + 0 = v
   --  - Works in both coefficient and NTT domains
   --
   --  **Complexity**: O(kn) = O(1024) modular additions
   --  **Constant-Time**: Yes (no secret-dependent branches)
   --
   --  ========================================================================

   procedure Vector_Add (
      V1 : in Polynomial_Vector;
      V2 : in Polynomial_Vector;
      Result : out Polynomial_Vector
   ) with
      Global => null,
      Post   => (for all I in Polynomial_Vector'Range =>
                   (for all J in Polynomial'Range =>
                      Result(I)(J) in 0 .. Q - 1));
   --  **Purpose**: Add two polynomial vectors component-wise
   --  **Input**: V1, V2 - vectors in R̂_q^k (NTT domain)
   --  **Output**: Result = V1 + V2 (component-wise modular addition)
   --  **Usage**: t = A·s + e (key generation), u = A^T·r + e₁ (encryption)

   --  ========================================================================
   --  Dot_Product: Inner Product of Two Vectors
   --  ========================================================================
   --
   --  **Mathematical Definition**:
   --    v₁ · v₂ = Σᵢ₌₀^{k-1} v₁[i] × v₂[i]
   --
   --  **Algorithm Pseudocode**:
   --    Input: v₁, v₂ ∈ R̂_q^k (vectors in NTT domain)
   --    Output: p ∈ R̂_q (polynomial in NTT domain)
   --
   --    result = 0 (zero polynomial)
   --    for i = 0 to k-1:
   --      product = Poly_Multiply(v₁[i], v₂[i])  -- NTT multiplication
   --      result = Poly_Add(result, product)
   --    return result
   --
   --  **Example** (k=4):
   --    v₁ = [p₀, p₁, p₂, p₃]
   --    v₂ = [q₀, q₁, q₂, q₃]
   --    result = (p₀×q₀) + (p₁×q₁) + (p₂×q₂) + (p₃×q₃)
   --
   --  **Properties**:
   --  - Commutative: v₁ · v₂ = v₂ · v₁
   --  - Distributive: (v₁ + v₂) · v₃ = v₁ · v₃ + v₂ · v₃
   --  - Bilinear: α(v₁ · v₂) = (αv₁) · v₂ = v₁ · (αv₂)
   --
   --  **Complexity**: O(kn) = O(1024) modular ops (NTT domain)
   --  **Constant-Time**: Yes (fixed k iterations, NTT multiply is constant-time)
   --
   --  ========================================================================

   procedure Dot_Product (
      V1 : in Polynomial_Vector;
      V2 : in Polynomial_Vector;
      Result : out Polynomial
   ) with
      Global => null,
      Post   => (for all I in Polynomial'Range => Result(I) in 0 .. Q - 1);
   --  **Purpose**: Compute inner product of two polynomial vectors
   --  **Input**: V1, V2 - vectors in R̂_q^k (NTT domain)
   --  **Output**: Result = V1 · V2 = Σᵢ V1[i] × V2[i] (NTT domain)
   --  **Usage**: v = t^T·r (encryption), m' = s^T·u (decryption)

   --  ========================================================================
   --  Matrix_Vector_Mul: Matrix-Vector Multiplication
   --  ========================================================================
   --
   --  **Mathematical Definition**:
   --    (A·v)[i] = Σⱼ₌₀^{k-1} A[i,j] × v[j]
   --
   --  **Algorithm Pseudocode**:
   --    Input: A ∈ R̂_q^{k×k} (matrix in NTT domain)
   --           v ∈ R̂_q^k (vector in NTT domain)
   --    Output: result ∈ R̂_q^k where result = A·v
   --
   --    for i = 0 to k-1:
   --      result[i] = 0
   --      for j = 0 to k-1:
   --        product = Poly_Multiply(A[i,j], v[j])
   --        result[i] = Poly_Add(result[i], product)
   --    return result
   --
   --  **Example** (k=4):
   --    A = [[a₀₀, a₀₁, a₀₂, a₀₃],
   --         [a₁₀, a₁₁, a₁₂, a₁₃],
   --         [a₂₀, a₂₁, a₂₂, a₂₃],
   --         [a₃₀, a₃₁, a₃₂, a₃₃]]
   --
   --    v = [v₀, v₁, v₂, v₃]
   --
   --    result[0] = a₀₀×v₀ + a₀₁×v₁ + a₀₂×v₂ + a₀₃×v₃
   --    result[1] = a₁₀×v₀ + a₁₁×v₁ + a₁₂×v₂ + a₁₃×v₃
   --    result[2] = a₂₀×v₀ + a₂₁×v₁ + a₂₂×v₂ + a₂₃×v₃
   --    result[3] = a₃₀×v₀ + a₃₁×v₁ + a₃₂×v₂ + a₃₃×v₃
   --
   --  **Properties**:
   --  - Associative: (AB)v = A(Bv)
   --  - Distributive: A(v₁ + v₂) = Av₁ + Av₂
   --  - Non-commutative: Av ≠ vA (dimensions don't match)
   --
   --  **Complexity**: O(k²n) = O(16·256) = 4096 modular ops (NTT domain)
   --  **Constant-Time**: Yes (fixed k² iterations)
   --
   --  ========================================================================

   procedure Matrix_Vector_Mul (
      Matrix : in Polynomial_Matrix;
      Vector : in Polynomial_Vector;
      Result : out Polynomial_Vector
   ) with
      Global => null,
      Post   => (for all I in Polynomial_Vector'Range =>
                   (for all J in Polynomial'Range =>
                      Result(I)(J) in 0 .. Q - 1));
   --  **Purpose**: Multiply matrix by vector
   --  **Input**: Matrix - k×k matrix in R̂_q (NTT domain)
   --             Vector - k-dimensional vector in R̂_q (NTT domain)
   --  **Output**: Result = Matrix · Vector (NTT domain)
   --  **Usage**: t = A·s (key generation), u = A^T·r (encryption)

   --  ========================================================================
   --  Matrix_Transpose_Vector_Mul: A^T · v
   --  ========================================================================
   --
   --  **Mathematical Definition**:
   --    (A^T·v)[i] = Σⱼ₌₀^{k-1} A[j,i] × v[j]
   --
   --  **Algorithm Pseudocode**:
   --    Input: A ∈ R̂_q^{k×k} (matrix in NTT domain)
   --           v ∈ R̂_q^k (vector in NTT domain)
   --    Output: result ∈ R̂_q^k where result = A^T·v
   --
   --    for i = 0 to k-1:
   --      result[i] = 0
   --      for j = 0 to k-1:
   --        product = Poly_Multiply(A[j,i], v[j])  -- Note: A[j,i] not A[i,j]
   --        result[i] = Poly_Add(result[i], product)
   --    return result
   --
   --  **Usage**: Encryption uses A^T·r instead of A·r
   --    This is more efficient than explicitly transposing A
   --
   --  **Complexity**: O(k²n) = O(4096) modular ops (same as Matrix_Vector_Mul)
   --  **Constant-Time**: Yes
   --
   --  ========================================================================

   procedure Matrix_Transpose_Vector_Mul (
      Matrix : in Polynomial_Matrix;
      Vector : in Polynomial_Vector;
      Result : out Polynomial_Vector
   ) with
      Global => null,
      Post   => (for all I in Polynomial_Vector'Range =>
                   (for all J in Polynomial'Range =>
                      Result(I)(J) in 0 .. Q - 1));
   --  **Purpose**: Multiply transpose of matrix by vector
   --  **Input**: Matrix - k×k matrix in R̂_q (NTT domain)
   --             Vector - k-dimensional vector in R̂_q (NTT domain)
   --  **Output**: Result = Matrix^T · Vector (NTT domain)
   --  **Usage**: u = A^T·r (encryption with public matrix A)

   --  ========================================================================
   --  Implementation Notes
   --  ========================================================================
   --
   --  **NTT Domain Operations**:
   --  - Addition: Same in both coefficient and NTT domains
   --  - Multiplication: Component-wise in NTT domain (via Poly_Multiply)
   --  - NO transforms needed: inputs/outputs all in NTT domain
   --
   --  **Memory Efficiency**:
   --  - All operations use pass-by-reference (in/out parameters)
   --  - No dynamic allocation (fixed-size arrays)
   --  - Temporary variables only for accumulation
   --
   --  **Verification Strategy**:
   --  1. Prove all coefficient additions stay in [0, q-1] via modular arithmetic
   --  2. Prove loop bounds are respected
   --  3. Prove algebraic identities (associativity, distributivity)
   --  4. Prove constant-time execution (no secret-dependent branches)
   --
   --  **Testing Strategy**:
   --  1. Zero vectors/matrices (identity elements)
   --  2. Unit vectors (single non-zero component)
   --  3. Random vectors/matrices
   --  4. Algebraic properties (commutativity, associativity)
   --  5. Integration with key generation algorithms
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Matrix;
