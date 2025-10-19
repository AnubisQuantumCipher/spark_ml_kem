--  ========================================================================
--  SparkPass ML-KEM XOF (Extendable Output Function) - Pure SPARK
--  ========================================================================
--
--  **Purpose**: XOF for ML-KEM matrix generation via rejection sampling
--               Wrapper around Keccak SHAKE-128
--
--  **Specification**: NIST FIPS 203 (ML-KEM), Section 4.2
--
--  **Function**:
--    - XOF(ρ, i, j): SHAKE-128 for uniform sampling matrix element Â[i,j]
--                    Output: ~672 bytes for rejection sampling
--
--  **Source**: NIST FIPS 203, Algorithm 6 (SampleNTT)
--              NIST FIPS 203, Algorithm 12 (K-PKE.KeyGen)
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.Keccak;

package SparkPass.Crypto.MLKEM.XOF is
   

   --  =====================================================================
   --  XOF Output Size
   --  =====================================================================

   --  Rejection sampling requires ~672 bytes to generate 256 coefficients
   --  Each coefficient is 12 bits from uniform distribution over Z_q (q=3329)
   --  Rejection rate ≈ (3329/4096) ≈ 81%, so need ~315 samples
   --  Safety margin: 672 bytes allows up to 448 samples (3 bytes per 2 coeffs)
   XOF_Output_Length : constant := 672;

   subtype XOF_Output is Byte_Array(1 .. XOF_Output_Length);

   --  =====================================================================
   --  XOF Function: SHAKE-128 for Matrix Generation
   --  =====================================================================
   --
   --  **Purpose**: Generate pseudorandom bytes for rejection sampling
   --
   --  **Algorithm** (NIST FIPS 203, Algorithm 6 - SampleNTT):
   --    Input: ρ ∈ {0,1}^256 (32 bytes), i,j ∈ {0,1,2,3} (matrix indices)
   --    Output: XOF(ρ || i || j) = SHAKE-128(ρ || i || j, 672×8)
   --
   --  **Usage in ML-KEM-1024 Matrix Generation**:
   --    For i, j ∈ [0, 3]:  (k=4 for ML-KEM-1024)
   --      Stream ← XOF(ρ, i, j)
   --      Â[i,j] ← SampleNTT(Stream)  -- Rejection sampling
   --
   --  **Rejection Sampling Process**:
   --    1. Read 3 bytes from stream → Extract two 12-bit values
   --    2. If value < q (3329): Accept as coefficient
   --    3. If value ≥ q: Reject and try next value
   --    4. Continue until 256 coefficients sampled
   --
   --  **Example**:
   --    ρ = [0x5a, 0x3b, ...] (32 bytes from G(d||k))
   --    i = 0, j = 1
   --    Input = ρ || [0x00] || [0x01] (34 bytes)
   --    Output = SHAKE-128(Input, 672 bytes)
   --           = [bytes for SampleNTT rejection sampling]
   --
   --  **Source**: NIST FIPS 203, Section 4.2, Algorithm 6
   --  =====================================================================

   procedure XOF_Uniform (
      Rho    : in Byte_Array;
      I      : in U8;
      J      : in U8;
      Output : out XOF_Output
   ) with
      Global => null,
      Pre    => Rho'Length = 32 and
                Rho'First = 1 and
                I <= 3 and  -- Matrix indices [0,3] for ML-KEM-1024
                J <= 3,
      Post   => Output'Length = XOF_Output_Length and
                Output'First = 1;
   --  **Purpose**: Generate 672 bytes for uniform sampling using SHAKE-128
   --  **Input**:
   --    - Rho: 32-byte public seed ρ from G(d || k)
   --    - I: Row index [0..3]
   --    - J: Column index [0..3]
   --  **Output**:
   --    - Output: 672 bytes for SampleNTT(output)
   --  **Usage**:
   --      XOF_Uniform(Rho, I => 0, J => 1, Output);
   --      A_Hat(0, 1) := SampleNTT(Output);
   --
   --  **Matrix Layout** (k=4):
   --      Â = | Â[0,0]  Â[0,1]  Â[0,2]  Â[0,3] |
   --          | Â[1,0]  Â[1,1]  Â[1,2]  Â[1,3] |
   --          | Â[2,0]  Â[2,1]  Â[2,2]  Â[2,3] |
   --          | Â[3,0]  Â[3,1]  Â[3,2]  Â[3,3] |

   --  =====================================================================
   --  Generic SHAKE-128 (for arbitrary-length output)
   --  =====================================================================
   --
   --  **Purpose**: General SHAKE-128 extendable output function
   --  **Use Case**: Protocol extensions, testing, or custom output lengths
   --  =====================================================================

   procedure SHAKE_128 (
      Input        : in Byte_Array;
      Output_Bytes : in Positive;
      Output       : out Byte_Array
   ) with
      Global => null,
      Pre    => Input'Length > 0 and
                Input'Length <= 65536 and
                Output_Bytes <= 65536 and
                Output'Length = Output_Bytes,
      Post   => Output'Length = Output_Bytes;
   --  **Purpose**: General-purpose SHAKE-128 XOF
   --  **Input**:
   --    - Input: Message to hash
   --    - Output_Bytes: Desired output length
   --    - Output: Buffer for output (must have Output_Bytes length)
   --  **Usage**:
   --      Buffer : Byte_Array(1 .. 1024);
   --      SHAKE_128(Seed, 1024, Buffer);

end SparkPass.Crypto.MLKEM.XOF;
