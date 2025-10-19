pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Poly; use SparkPass.Crypto.MLKEM.Poly;
with SparkPass.Crypto.MLKEM.NTT; use SparkPass.Crypto.MLKEM.NTT;

--  ========================================================================
--  ML-KEM-1024 Matrix Operations Implementation
--  ========================================================================
--
--  **Implementation Strategy**:
--  1. All operations assume NTT domain for efficiency
--  2. Use existing Poly_Add for coefficient-wise addition
--  3. Use Poly_Multiply for NTT-domain multiplication
--  4. No explicit NTT/INTT transforms needed (stay in NTT domain)
--
--  **Key Insight**: NTT domain properties
--  - Addition: Same as coefficient domain (component-wise mod q)
--  - Multiplication: Component-wise in NTT domain (O(n) instead of O(n²))
--  - This is why all intermediate operations stay in NTT domain
--
--  ========================================================================

package body SparkPass.Crypto.MLKEM.Matrix is

   --  ========================================================================
   --  Vector_Add Implementation
   --  ========================================================================
   --
   --  **Algorithm**:
   --    for i = 0 to k-1:
   --      Result[i] = Poly_Add(V1[i], V2[i])
   --
   --  **Complexity**: O(kn) = O(4 × 256) = 1024 modular additions
   --
   --  ========================================================================

   procedure Vector_Add (
      V1 : in Polynomial_Vector;
      V2 : in Polynomial_Vector;
      Result : out Polynomial_Vector
   ) is
   begin
      --  Add each polynomial component-wise
      for I in Polynomial_Vector'Range loop
         Add(V1(I), V2(I), Result(I));
      end loop;
   end Vector_Add;

   --  ========================================================================
   --  Dot_Product Implementation
   --  ========================================================================
   --
   --  **Algorithm**:
   --    Result = 0 (zero polynomial)
   --    for i = 0 to k-1:
   --      Product = Poly_Multiply(V1[i], V2[i])
   --      Result = Poly_Add(Result, Product)
   --
   --  **Example** (k=4):
   --    Result = (V1[0] × V2[0]) + (V1[1] × V2[1]) +
   --             (V1[2] × V2[2]) + (V1[3] × V2[3])
   --
   --  **Complexity**: O(kn) = O(1024) operations (NTT domain)
   --
   --  ========================================================================

   procedure Dot_Product (
      V1 : in Polynomial_Vector;
      V2 : in Polynomial_Vector;
      Result : out Polynomial
   ) is
      Product : Polynomial;
   begin
      --  Initialize result to zero polynomial
      Result := (others => 0);

      --  Accumulate V1[i] × V2[i] for each i
      for I in Polynomial_Vector'Range loop
         --  Multiply V1[i] and V2[i] in NTT domain
         Multiply_NTT(V1(I), V2(I), Product);

         --  Add to accumulator
         Add(Result, Product, Result);
      end loop;
   end Dot_Product;

   --  ========================================================================
   --  Matrix_Vector_Mul Implementation
   --  ========================================================================
   --
   --  **Algorithm**:
   --    for i = 0 to k-1:
   --      Result[i] = 0
   --      for j = 0 to k-1:
   --        Product = Poly_Multiply(Matrix[i,j], Vector[j])
   --        Result[i] = Poly_Add(Result[i], Product)
   --
   --  **Example** (k=4, showing result[0] computation):
   --    Result[0] = (Matrix[0,0] × Vector[0]) + (Matrix[0,1] × Vector[1]) +
   --                (Matrix[0,2] × Vector[2]) + (Matrix[0,3] × Vector[3])
   --
   --  **Complexity**: O(k²n) = O(16 × 256) = 4096 operations
   --
   --  ========================================================================

   procedure Matrix_Vector_Mul (
      Matrix : in Polynomial_Matrix;
      Vector : in Polynomial_Vector;
      Result : out Polynomial_Vector
   ) is
      Product : Polynomial;
   begin
      --  Compute each component of result vector
      for I in Polynomial_Vector'Range loop
         --  Initialize Result[i] to zero
         Result(I) := (others => 0);

         --  Accumulate Matrix[i,j] × Vector[j] for all j
         for J in Polynomial_Vector'Range loop
            --  Multiply Matrix[i,j] and Vector[j] in NTT domain
            Multiply_NTT(Matrix(I, J), Vector(J), Product);

            --  Add to Result[i]
            Add(Result(I), Product, Result(I));
         end loop;
      end loop;
   end Matrix_Vector_Mul;

   --  ========================================================================
   --  Matrix_Transpose_Vector_Mul Implementation
   --  ========================================================================
   --
   --  **Algorithm**:
   --    for i = 0 to k-1:
   --      Result[i] = 0
   --      for j = 0 to k-1:
   --        Product = Poly_Multiply(Matrix[j,i], Vector[j])  -- Note: [j,i]
   --        Result[i] = Poly_Add(Result[i], Product)
   --
   --  **Key Difference**: Use Matrix[j,i] instead of Matrix[i,j]
   --    This effectively computes A^T · v without explicit transposition
   --
   --  **Example** (k=4, showing result[0] computation):
   --    Result[0] = (Matrix[0,0] × Vector[0]) + (Matrix[1,0] × Vector[1]) +
   --                (Matrix[2,0] × Vector[2]) + (Matrix[3,0] × Vector[3])
   --
   --  **Usage in ML-KEM Encryption**:
   --    u = A^T·r where A is public matrix, r is random vector
   --
   --  **Complexity**: O(k²n) = O(4096) operations (same as Matrix_Vector_Mul)
   --
   --  ========================================================================

   procedure Matrix_Transpose_Vector_Mul (
      Matrix : in Polynomial_Matrix;
      Vector : in Polynomial_Vector;
      Result : out Polynomial_Vector
   ) is
      Product : Polynomial;
   begin
      --  Compute each component of result vector
      for I in Polynomial_Vector'Range loop
         --  Initialize Result[i] to zero
         Result(I) := (others => 0);

         --  Accumulate Matrix[j,i] × Vector[j] for all j (transposed indexing)
         for J in Polynomial_Vector'Range loop
            --  Multiply Matrix[j,i] and Vector[j] in NTT domain
            --  Note: Matrix[J, I] not Matrix[I, J] - this is the transpose
            Multiply_NTT(Matrix(J, I), Vector(J), Product);

            --  Add to Result[i]
            Add(Result(I), Product, Result(I));
         end loop;
      end loop;
   end Matrix_Transpose_Vector_Mul;

   --  ========================================================================
   --  SPARK Verification Notes
   --  ========================================================================
   --
   --  **Proof Obligations**:
   --  1. Vector_Add:
   --     - All coefficients in Result[i] in [0, q-1]
   --     - Proven via Poly_Add postcondition
   --
   --  2. Dot_Product:
   --     - Accumulator Result stays in [0, q-1] after each addition
   --     - Product from Poly_Multiply in [0, q-1]
   --     - Final Result in [0, q-1]
   --
   --  3. Matrix_Vector_Mul:
   --     - Each Result[i] initialized to zero
   --     - All accumulated products in [0, q-1]
   --     - Final Result[i][j] in [0, q-1]
   --
   --  4. Matrix_Transpose_Vector_Mul:
   --     - Same as Matrix_Vector_Mul
   --     - Index swap (J, I) proven to be in bounds
   --
   --  **Expected GNATprove Results**:
   --  - Flow analysis: All variables initialized before use
   --  - Proof (Bronze): All range checks proven
   --  - Proof (Silver): Postconditions proven
   --
   --  **Potential Issues**:
   --  - Loop invariants may be needed for accumulator bounds
   --  - Matrix indexing bounds may need explicit assertions
   --
   --  **Resolution Strategy**:
   --  - Add loop invariants if prover fails on accumulator
   --  - Use pragma Assert for complex index calculations
   --
   --  ========================================================================

end SparkPass.Crypto.MLKEM.Matrix;
