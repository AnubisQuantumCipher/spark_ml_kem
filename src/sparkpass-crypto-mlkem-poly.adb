pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Arithmetic; use SparkPass.Crypto.MLKEM.Arithmetic;

--  ========================================================================
--  ML-KEM-1024 Polynomial Operations Implementation
--  ========================================================================
--
--  **Implementation Strategy**:
--  1. Use explicit loops for coefficient-wise operations
--  2. Add loop invariants for SPARK verification
--  3. Delegate modular arithmetic to Arithmetic package
--  4. Optimize later (Phase 3) - correctness first
--
--  **Verification Approach**:
--  - Loop invariants maintain coefficient range [0, q-1]
--  - Quantified postconditions verified via invariant induction
--  - No aliasing issues (A, B are 'in', C is 'out')
--
--  ========================================================================

package body SparkPass.Crypto.MLKEM.Poly is

   --  ========================================================================
   --  Zero Polynomial
   --  ========================================================================

   function Zero_Poly return Polynomial is
   begin
      --  Return the zero polynomial (all coefficients = 0)
      --  SPARK proves: All coefficients = 0 via aggregate definition
      return (others => 0);
   end Zero_Poly;

   --  ========================================================================
   --  Polynomial Addition Implementation
   --  ========================================================================
   --
   --  **Loop Invariant**:
   --  At iteration I, all coefficients C(0..I-1) are correctly computed
   --  and in range [0, q-1]
   --
   --  **Proof Strategy**:
   --  1. Base case (I = 0): No coefficients set, invariant vacuously true
   --  2. Inductive step: Assume C(0..I-1) correct, prove C(I) correct
   --  3. Termination: After loop, I = 256, so C(0..255) all correct
   --
   --  ========================================================================

   procedure Add (
      A : in Polynomial;
      B : in Polynomial;
      C : out Polynomial
   ) is
   begin
      --  Coefficient-wise addition: C[i] = (A[i] + B[i]) mod q
      for I in Polynomial'Range loop
         C(I) := Mod_Add(A(I), B(I));

         pragma Loop_Invariant
            (for all J in 0 .. I =>
               C(J) = ((A(J) + B(J)) mod Q));
         --  **Invariant Explanation**:
         --  After processing coefficient I, all coefficients 0..I are
         --  correctly computed as (A[J] + B[J]) mod Q and in range [0, q-1].
         --  SPARK verifies this inductively using Mod_Add postcondition.

      end loop;

      --  Postcondition proven: Loop terminates with I = N-1,
      --  so invariant establishes C(0..N-1) all correct
   end Add;

   --  ========================================================================
   --  Polynomial Subtraction Implementation
   --  ========================================================================
   --
   --  **Loop Invariant**:
   --  At iteration I, all coefficients C(0..I-1) are correctly computed
   --  and in range [0, q-1]
   --
   --  **Note**: Mod_Sub handles negative intermediate values correctly
   --            by adding q when (A[i] - B[i]) < 0
   --
   --  ========================================================================

   procedure Sub (
      A : in Polynomial;
      B : in Polynomial;
      C : out Polynomial
   ) is
   begin
      --  Coefficient-wise subtraction: C[i] = (A[i] - B[i]) mod q
      for I in Polynomial'Range loop
         C(I) := Mod_Sub(A(I), B(I));

         pragma Loop_Invariant
            (for all J in 0 .. I =>
               C(J) = ((A(J) - B(J) + Q) mod Q));
         --  **Invariant Explanation**:
         --  After processing coefficient I, all coefficients 0..I are
         --  correctly computed as (A[J] - B[J] + Q) mod Q.
         --  The +Q ensures non-negative result for Ada's mod semantics.
         --  SPARK verifies this using Mod_Sub postcondition.

      end loop;

      --  Postcondition proven: Loop terminates with I = N-1,
      --  so invariant establishes C(0..N-1) all correct
   end Sub;

   --  ========================================================================
   --  Future Implementations (Phase 2.2+)
   --  ========================================================================
   --
   --  **Polynomial Multiplication via NTT**:
   --
   --  procedure Mul (A, B : in Polynomial; C : out Polynomial) is
   --     A_NTT, B_NTT, C_NTT : Polynomial;
   --  begin
   --     --  Transform to NTT domain
   --     NTT(A, A_NTT);
   --     NTT(B, B_NTT);
   --
   --     --  Pointwise multiplication in NTT domain
   --     for I in Polynomial'Range loop
   --        C_NTT(I) := Mod_Mul(A_NTT(I), B_NTT(I));
   --     end loop;
   --
   --     --  Transform back to coefficient domain
   --     INTT(C_NTT, C);
   --  end Mul;
   --
   --  **Complexity Analysis**:
   --  - NTT: O(n log n) = O(256 × 8) = 2048 operations
   --  - Pointwise multiply: O(n) = 256 operations
   --  - INTT: O(n log n) = 2048 operations
   --  - Total: O(n log n) vs naive O(n²) = 65536 operations
   --  - Speedup: ~16x for ML-KEM polynomial multiplication
   --
   --  ========================================================================

   --  ========================================================================
   --  SPARK Verification Notes
   --  ========================================================================
   --
   --  **Proof Obligations**:
   --  1. Range checks: All array accesses within bounds
   --  2. Loop invariants: Proven by induction
   --  3. Postconditions: Derived from final loop invariant
   --  4. No aliasing: A, B are 'in', C is 'out' (disjoint)
   --
   --  **Expected GNATprove Results**:
   --  - Flow analysis: All outputs initialized (C fully assigned)
   --  - Proof (Bronze): All VCs proven (no runtime errors)
   --  - Proof (Silver): Postconditions proven (functional correctness)
   --
   --  **Potential Prover Issues**:
   --  - Quantified expressions in loop invariants may timeout
   --  - Modular arithmetic may require SMT solver hints
   --  - Large loop bounds (256) may slow verification
   --
   --  **Resolution Strategies**:
   --  1. Split invariants into multiple pragmas (range + correctness)
   --  2. Add intermediate assertions inside loops
   --  3. Use --prover=cvc5 or --prover=z3 if alt-ergo fails
   --  4. Increase timeout with --timeout=60
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Poly;
