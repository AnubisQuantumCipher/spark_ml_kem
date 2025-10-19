pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

--  ========================================================================
--  ML-KEM-1024 Number-Theoretic Transform (NIST FIPS 203)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4.3 (NTT Operations)
--              Algorithm 9 (NTT forward transform)
--              Algorithm 10 (NTT⁻¹ inverse transform)
--              Algorithm 11 (MultiplyNTTs pointwise multiplication)
--              Algorithm 12 (BaseCaseMultiply helper)
--
--  **Purpose**: Fast polynomial multiplication in O(n log n) time
--
--  **Mathematical Foundation**:
--  - Ring: R_q = Z_q[X]/(X^256 + 1)
--  - Modulus: q = 3329 (prime, q ≡ 1 mod 512)
--  - Primitive root: ζ = 17 (512-th root of unity mod q)
--  - NTT transform: Maps coefficient form to NTT domain
--  - Multiplication: O(n²) in coefficient form, O(n) in NTT domain
--
--  **Algorithm Complexity**:
--  - NTT:        O(n log n) = 256 × 8 = 2048 operations
--  - INTT:       O(n log n) = 256 × 8 = 2048 operations
--  - Multiply:   O(n) = 128 basemul operations = 256 operations
--
--  **Security Properties**:
--  - Constant-time execution (no secret-dependent branches)
--  - Overflow-free arithmetic (proven via SPARK)
--  - Bit-reversal permutation for cache-friendly access
--
--  **SPARK Verification Levels**:
--  - Bronze: Memory safety (no overflow, array bounds)
--  - Silver: Functional correctness (NTT properties hold)
--  - Platinum: FIPS 203 compliance (exact algorithm match)
--
--  **Design Philosophy**:
--  - In-place transforms to minimize memory allocation
--  - Explicit loop invariants for SPARK verification
--  - Twiddle factors precomputed in NTT_Constants package
--  - Barrett reduction for all modular operations
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.NTT is
   

   --  ========================================================================
   --  NTT Forward Transform (FIPS 203 Algorithm 9)
   --  ========================================================================
   --
   --  **Algorithm**: Cooley-Tukey decimation-in-time
   --  **Structure**: 7 layers, 128 butterfly operations per layer
   --  **Twiddle factors**: Powers of ζ in bit-reversed order
   --
   --  **Mathematical Definition**:
   --    Let f(X) = Σ fᵢXⁱ (coefficient form)
   --    NTT(f) = [f(ζ⁰), f(ζ²), f(ζ⁴), ..., f(ζ⁵¹⁰)] (evaluation form)
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 9):
   --    Input: f̂ ∈ R_q (coefficient form, bit-reversed order)
   --    Output: f̂ ∈ R_q (NTT form, natural order)
   --
   --    k ← 1
   --    for (len = 128; len ≥ 2; len = len / 2) do
   --      for (start = 0; start < 256; start = start + 2×len) do
   --        zeta ← ζ^BitRev₇(k)
   --        k ← k + 1
   --        for (j = start; j < start + len; j++) do
   --          t ← zeta × f̂[j + len]
   --          f̂[j + len] ← f̂[j] - t
   --          f̂[j] ← f̂[j] + t
   --        end for
   --      end for
   --    end for
   --
   --  **Butterfly Operation**:
   --    Given (a, b) and twiddle factor ζ:
   --      t = ζ × b
   --      output_high = a - t
   --      output_low = a + t
   --
   --  **Loop Structure**:
   --    Layer 1: len=128, 2 blocks,  128 butterflies/block
   --    Layer 2: len=64,  4 blocks,  64 butterflies/block
   --    Layer 3: len=32,  8 blocks,  32 butterflies/block
   --    Layer 4: len=16,  16 blocks, 16 butterflies/block
   --    Layer 5: len=8,   32 blocks, 8 butterflies/block
   --    Layer 6: len=4,   64 blocks, 4 butterflies/block
   --    Layer 7: len=2,   128 blocks, 2 butterflies/block
   --
   --  **Complexity**: 7 layers × 128 butterflies = 896 butterflies
   --                  Each butterfly: 1 mult + 2 add = 3 ops
   --                  Total: 896 × 3 = 2688 modular operations
   --
   --  ========================================================================

   procedure NTT (Poly : in out Polynomial) with
      Global => null,
      Pre    => True,
      Post   => (for all I in Polynomial'Range => Poly(I) in 0 .. Q - 1);
   --  **Purpose**: Transform polynomial from coefficient to NTT domain
   --  **Input**: Poly - polynomial in coefficient form (bit-reversed)
   --  **Output**: Poly - polynomial in NTT form (natural order)
   --  **Modifies**: Poly in place
   --  **SPARK Contract**:
   --    - Pre: Always valid (accepts any coefficient array)
   --    - Post: All coefficients remain in valid range [0, q-1]
   --  **Usage**: Call before polynomial multiplication in NTT domain
   --  **Note**: Input must be in bit-reversed order for Cooley-Tukey
   --            Use BitRev procedure if needed

   --  ========================================================================
   --  INTT Inverse Transform (FIPS 203 Algorithm 10)
   --  ========================================================================
   --
   --  **Algorithm**: Gentleman-Sande decimation-in-frequency
   --  **Structure**: 7 layers + normalization step
   --  **Twiddle factors**: Inverses of forward transform twiddles
   --
   --  **Mathematical Definition**:
   --    Let f̂ = [f̂₀, f̂₁, ..., f̂₂₅₅] (NTT form)
   --    INTT(f̂) = (1/n) × Σ f̂ᵢ × ζ^(-i×j) (coefficient form)
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 10):
   --    Input: f̂ ∈ R_q (NTT form, natural order)
   --    Output: f ∈ R_q (coefficient form, bit-reversed order)
   --
   --    k ← 127
   --    for (len = 2; len ≤ 128; len = len × 2) do
   --      for (start = 0; start < 256; start = start + 2×len) do
   --        zeta ← ζ^BitRev₇(k)
   --        k ← k - 1
   --        for (j = start; j < start + len; j++) do
   --          t ← f̂[j]
   --          f̂[j] ← t + f̂[j + len]
   --          f̂[j + len] ← zeta × (f̂[j + len] - t)
   --        end for
   --      end for
   --    end for
   --
   --    // Normalization step (multiply by n⁻¹ = 3303 mod 3329)
   --    for (j = 0; j < 256; j++) do
   --      f̂[j] ← f̂[j] × 3303
   --    end for
   --
   --  **Inverse Butterfly Operation**:
   --    Given (a, b) and twiddle factor ζ:
   --      output_low = a + b
   --      output_high = ζ × (b - a)
   --
   --  **Normalization**:
   --    NTT domain multiplication includes implicit n factor
   --    Must multiply by n⁻¹ mod q = 3303 to recover coefficient form
   --    Computed: 256 × 3303 ≡ 1 (mod 3329)
   --
   --  **Complexity**: 7 layers × 128 butterflies + 256 normalizations
   --                  = 2688 + 256 = 2944 modular operations
   --
   --  ========================================================================

   procedure INTT (Poly : in out Polynomial) with
      Global => null,
      Pre    => True,
      Post   => (for all I in Polynomial'Range => Poly(I) in 0 .. Q - 1);
   --  **Purpose**: Transform polynomial from NTT to coefficient domain
   --  **Input**: Poly - polynomial in NTT form (natural order)
   --  **Output**: Poly - polynomial in coefficient form (bit-reversed)
   --  **Modifies**: Poly in place
   --  **SPARK Contract**:
   --    - Pre: Always valid (accepts any NTT-domain array)
   --    - Post: All coefficients normalized to [0, q-1]
   --  **Usage**: Call after polynomial operations in NTT domain
   --  **Note**: Output is in bit-reversed order (Gentleman-Sande property)
   --            Use BitRev procedure if natural order needed

   --  ========================================================================
   --  Pointwise Multiplication in NTT Domain (FIPS 203 Algorithm 11)
   --  ========================================================================
   --
   --  **Purpose**: Multiply two polynomials in NTT representation
   --  **Efficiency**: O(n) vs O(n²) in coefficient domain
   --
   --  **Mathematical Definition**:
   --    Let f̂, ĝ be polynomials in NTT form
   --    (f̂ ⊙ ĝ)[i] = BaseMul(f̂[2i], f̂[2i+1], ĝ[2i], ĝ[2i+1], γ^BitRev₇(i))
   --
   --  **Algorithm Pseudocode** (FIPS 203, Algorithm 11):
   --    Input: f̂, ĝ ∈ R_q (NTT domain)
   --    Output: ĥ ∈ R_q (NTT domain) where h = f × g
   --
   --    for (i = 0; i < 128; i++) do
   --      (ĥ[2i], ĥ[2i+1]) ← BaseMul(f̂[2i], f̂[2i+1], ĝ[2i], ĝ[2i+1], γ^BitRev₇(i))
   --    end for
   --
   --  **BaseMul Operation** (FIPS 203, Algorithm 12):
   --    Multiply two binomials modulo (X² - γ)
   --    Input: a₀, a₁, b₀, b₁ ∈ Z_q and γ ∈ Z_q
   --    Output: c₀, c₁ where (a₀ + a₁X)(b₀ + b₁X) ≡ c₀ + c₁X (mod X² - γ)
   --
   --    c₀ ← a₀ × b₀ + a₁ × b₁ × γ
   --    c₁ ← a₀ × b₁ + a₁ × b₀
   --
   --  **Why BaseMul?**:
   --    The ring R_q = Z_q[X]/(X^256 + 1) is isomorphic to
   --    Z_q[X]/(X² - ζ^(2i+1)) for each pair of coefficients
   --    This allows pairwise multiplication in O(1) time
   --
   --  **Complexity**: 128 basemul operations
   --                  Each basemul: 4 multiplications + 2 additions
   --                  Total: 128 × 6 = 768 modular operations
   --
   --  ========================================================================

   procedure Multiply_NTT (
      A : in Polynomial;
      B : in Polynomial;
      C : out Polynomial
   ) with
      Global => null,
      Pre    => True,
      Post   => (for all I in Polynomial'Range => C(I) in 0 .. Q - 1);
   --  **Purpose**: Multiply two polynomials in NTT domain
   --  **Inputs**: A, B - polynomials in NTT form
   --  **Output**: C - polynomial product A × B in NTT form
   --  **SPARK Contract**:
   --    - Pre: Always valid (accepts any NTT-domain arrays)
   --    - Post: Result coefficients in valid range [0, q-1]
   --  **Usage**: After NTT(A), NTT(B), compute Multiply_NTT(A, B, C)
   --  **Note**: All inputs/outputs in NTT domain (not coefficient form)

   --  ========================================================================
   --  Helper Procedures (Utility Functions)
   --  ========================================================================

   procedure BitRev_Permute (Poly : in out Polynomial) with
      Global => null,
      Pre    => True,
      Post   => (for all I in Polynomial'Range => Poly(I) in 0 .. Q - 1);
   --  **Purpose**: Apply bit-reversal permutation to polynomial coefficients
   --  **Input**: Poly - polynomial in natural order
   --  **Output**: Poly - polynomial in bit-reversed order
   --  **Algorithm**: Swap Poly[i] ↔ Poly[BitRev₇(i)] for i < BitRev₇(i)
   --  **Complexity**: O(n) = 128 swaps (pairs only swapped once)
   --  **Usage**: Convert between Cooley-Tukey and Gentleman-Sande orders
   --  **Note**: Self-inverse operation (BitRev(BitRev(x)) = x)

   --  ========================================================================
   --  SPARK Ghost Functions (For Verification Only)
   --  ========================================================================
   --
   --  **Purpose**: Ghost functions define mathematical properties for SPARK
   --              They are used in contracts but erased during compilation
   --
   --  **Usage**: Reference in loop invariants and postconditions
   --
   --  ========================================================================

   function Is_NTT_Form (Poly : Polynomial) return Boolean is
      (for all I in Polynomial'Range => Poly(I)'Valid) with
      Ghost,
      Global => null;
   --  **Purpose**: Verify polynomial is in valid NTT domain representation
   --  **Current Implementation**: Checks all coefficients are in [0, q-1]
   --  **Limitation**: Does not verify NTT-specific properties (evaluation form)
   --  **Rationale**: Full NTT verification requires checking evaluations at
   --                 roots of unity, which is computationally expensive and
   --                 not necessary for SPARK proof obligations. The range check
   --                 ensures data integrity for NTT operations.
   --  **Future Work**: Could add inverse NTT round-trip property check

   function Is_Coefficient_Form (Poly : Polynomial) return Boolean is
      (for all I in Polynomial'Range => Poly(I)'Valid) with
      Ghost,
      Global => null;
   --  **Purpose**: Verify polynomial is in valid coefficient representation
   --  **Current Implementation**: Checks all coefficients are in [0, q-1]
   --  **Limitation**: Does not distinguish coefficient vs NTT form structurally
   --  **Rationale**: Both forms use same coefficient range [0, q-1]. The
   --                 semantic difference (coefficient vs evaluation) cannot be
   --                 determined from values alone - it's a property of how the
   --                 data was produced (via NTT or INTT operations).
   --  **Future Work**: Could track form using type system or ghost state

   --  ========================================================================
   --  Implementation Notes
   --  ========================================================================
   --
   --  **Memory Layout**:
   --    All operations are in-place to avoid allocations
   --    Twiddle factors stored in NTT_Constants package (read-only)
   --
   --  **Constant-Time Guarantees**:
   --    - No secret-dependent branches in butterfly operations
   --    - No secret-dependent memory access patterns
   --    - Loop bounds are compile-time constants
   --    - Barrett reduction uses bitwise masking (no conditional branches)
   --    - All modular arithmetic (Add/Sub/Mul) is constant-time
   --
   --  **SPARK Verification Strategy**:
   --    Bronze Level:
   --      - Prove no array index out of bounds
   --      - Prove no integer overflow in arithmetic
   --      - Prove all coefficients remain in [0, q-1]
   --
   --    Silver Level:
   --      - Prove NTT(INTT(x)) = x (round-trip identity)
   --      - Prove Multiply_NTT(NTT(a), NTT(b)) = NTT(a×b) (correctness)
   --      - Prove bit-reversal is self-inverse
   --
   --    Platinum Level:
   --      - Prove exact match with FIPS 203 algorithms
   --      - Prove twiddle factors match specified values
   --      - Prove NTT output matches evaluation at roots of unity
   --
   --  **Performance Benchmarks** (Expected on modern CPUs):
   --    - NTT:           ~2,000 cycles (~1 μs at 2 GHz)
   --    - INTT:          ~2,200 cycles (~1.1 μs at 2 GHz)
   --    - Multiply_NTT:  ~800 cycles (~0.4 μs at 2 GHz)
   --    - Total polynomial multiply: ~5,000 cycles (~2.5 μs at 2 GHz)
   --
   --  **Comparison to Schoolbook Multiplication**:
   --    - Schoolbook: O(n²) = 65,536 multiplications
   --    - NTT-based: O(n log n) = ~3,500 multiplications
   --    - Speedup: ~18× faster for n=256
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.NTT;
