--  ========================================================================
--  SparkPass ML-KEM PRF (Pseudorandom Function) - Pure SPARK
--  ========================================================================
--
--  **Purpose**: PRF for ML-KEM secret/error vector sampling
--               Wrapper around Keccak SHAKE-256
--
--  **Specification**: NIST FIPS 203 (ML-KEM), Section 4.2
--
--  **Function**:
--    - PRF(σ, N): SHAKE-256 for Centered Binomial Distribution sampling
--                 Output: 64η bytes where η=2 for ML-KEM-1024
--
--  **Source**: NIST FIPS 203, Algorithm 12 (K-PKE.KeyGen)
--              NIST FIPS 203, Section 4.2 (PRF Function)
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.Keccak;

package SparkPass.Crypto.MLKEM.PRF is
   

   --  =====================================================================
   --  PRF Output Size
   --  =====================================================================

   --  For ML-KEM-1024: η₁ = η₂ = 2
   --  PRF output: 64 × η = 64 × 2 = 128 bytes
   --  Used for SamplePolyCBD(PRF(σ, N), η=2)
   Eta_1 : constant := 2;  -- Secret vector noise parameter
   Eta_2 : constant := 2;  -- Error vector noise parameter
   PRF_Output_Length : constant := 64 * Eta_1;  -- 128 bytes

   subtype PRF_Output is Byte_Array(1 .. PRF_Output_Length);

   --  =====================================================================
   --  PRF Function: SHAKE-256 for CBD Sampling
   --  =====================================================================
   --
   --  **Purpose**: Generate pseudorandom bytes for Centered Binomial Dist.
   --
   --  **Algorithm** (NIST FIPS 203, Section 4.2):
   --    Input: σ ∈ {0,1}^256 (32 bytes), N ∈ {0..255} (1 byte)
   --    Output: PRF(σ, N) = SHAKE-256(σ || N, 64η×8) ∈ {0,1}^{64η×8}
   --    For η=2: Output 128 bytes
   --
   --  **Usage in ML-KEM-1024 Key Generation**:
   --    1. Generate secret vector s:
   --       For i ∈ [0, 3]:  (k=4 for ML-KEM-1024)
   --         s[i] ← SamplePolyCBD(PRF(σ, N), η=2)
   --         N ← N + 1
   --
   --    2. Generate error vector e:
   --       For i ∈ [0, 3]:
   --         e[i] ← SamplePolyCBD(PRF(σ, N), η=2)
   --         N ← N + 1
   --
   --  **Security Properties**:
   --    - Deterministic: Same (σ, N) → same output
   --    - Pseudorandom: Output indistinguishable from random
   --    - Based on Keccak-f[1600] permutation security
   --
   --  **Example**:
   --    σ = [0xa1, 0xb2, ...] (32 bytes)
   --    N = 0
   --    Output = SHAKE-256(σ || [0x00], 128 bytes)
   --           = [random-looking bytes for CBD sampling]
   --
   --  **Source**: NIST FIPS 203, Section 4.2
   --  =====================================================================

   procedure PRF_CBD (
      Sigma  : in Byte_Array;
      N      : in U8;
      Output : out PRF_Output
   ) with
      Global => null,
      Pre    => Sigma'Length = 32 and Sigma'First = 1,
      Post   => Output'Length = PRF_Output_Length and
                Output'First = 1;
   --  **Purpose**: Generate 128 bytes for CBD sampling using SHAKE-256
   --  **Input**:
   --    - Sigma: 32-byte private seed σ from G(d || k)
   --    - N: Counter byte (0..7 for ML-KEM-1024, 8 polynomials total)
   --  **Output**:
   --    - Output: 128 bytes for SamplePolyCBD(output, η=2)
   --  **Usage**:
   --      PRF_CBD(Sigma, N => 0, Output);  -- For s[0]
   --      s[0] := SamplePolyCBD(Output, Eta => 2);
   --
   --      PRF_CBD(Sigma, N => 1, Output);  -- For s[1]
   --      s[1] := SamplePolyCBD(Output, Eta => 2);
   --
   --      ... (continue for s[2], s[3], e[0], e[1], e[2], e[3])

   --  =====================================================================
   --  Generic SHAKE-256 (for arbitrary-length output)
   --  =====================================================================
   --
   --  **Purpose**: General SHAKE-256 extendable output function
   --  **Use Case**: Protocol extensions, testing, or custom output lengths
   --  =====================================================================

   procedure SHAKE_256 (
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
   --  **Purpose**: General-purpose SHAKE-256 XOF
   --  **Input**:
   --    - Input: Message to hash
   --    - Output_Bytes: Desired output length
   --    - Output: Buffer for output (must have Output_Bytes length)
   --  **Usage**:
   --      Buffer : Byte_Array(1 .. 256);
   --      SHAKE_256(Message, 256, Buffer);

end SparkPass.Crypto.MLKEM.PRF;
