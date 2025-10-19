--  ========================================================================
--  SparkPass ML-KEM PRF Implementation
--  ========================================================================

pragma SPARK_Mode (On);

package body SparkPass.Crypto.MLKEM.PRF is

   --  =====================================================================
   --  PRF_CBD: SHAKE-256 for Centered Binomial Distribution
   --  =====================================================================

   procedure PRF_CBD (
      Sigma  : in Byte_Array;
      N      : in U8;
      Output : out PRF_Output
   ) is
      --  Concatenate Sigma || N for SHAKE-256 input
      Input : Byte_Array(1 .. 33);
   begin
      --  Copy sigma (32 bytes)
      Input(1 .. 32) := Sigma;

      --  Append N counter (1 byte)
      Input(33) := N;

      --  Call Keccak SHAKE-256 (output length determined by Output'Length)
      SparkPass.Crypto.Keccak.SHAKE_256(Input, Output);
   end PRF_CBD;

   --  =====================================================================
   --  SHAKE_256: General-Purpose Extendable Output Function
   --  =====================================================================

   procedure SHAKE_256 (
      Input        : in Byte_Array;
      Output_Bytes : in Positive;
      Output       : out Byte_Array
   ) is
      pragma Unreferenced (Output_Bytes);
      --  Output_Bytes is provided for API compatibility but not needed
      --  since SHAKE_256 determines output length from Output'Length
   begin
      SparkPass.Crypto.Keccak.SHAKE_256(Input, Output);
   end SHAKE_256;

end SparkPass.Crypto.MLKEM.PRF;
