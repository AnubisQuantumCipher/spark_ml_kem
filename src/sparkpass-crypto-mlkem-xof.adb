--  ========================================================================
--  SparkPass ML-KEM XOF Implementation
--  ========================================================================

pragma SPARK_Mode (On);

package body SparkPass.Crypto.MLKEM.XOF is

   --  =====================================================================
   --  XOF_Uniform: SHAKE-128 for Matrix Generation
   --  =====================================================================

   procedure XOF_Uniform (
      Rho    : in Byte_Array;
      I      : in U8;
      J      : in U8;
      Output : out XOF_Output
   ) is
      --  Concatenate Rho || I || J for SHAKE-128 input
      Input : Byte_Array(1 .. 34);
   begin
      --  Copy rho (32 bytes)
      Input(1 .. 32) := Rho;

      --  Append i index (1 byte)
      Input(33) := I;

      --  Append j index (1 byte)
      Input(34) := J;

      --  Call Keccak SHAKE-128 (output length determined by Output'Length)
      SparkPass.Crypto.Keccak.SHAKE_128(Input, Output);
   end XOF_Uniform;

   --  =====================================================================
   --  SHAKE_128: General-Purpose Extendable Output Function
   --  =====================================================================

   procedure SHAKE_128 (
      Input        : in Byte_Array;
      Output_Bytes : in Positive;
      Output       : out Byte_Array
   ) is
      pragma Unreferenced (Output_Bytes);
      --  Output_Bytes is provided for API compatibility but not needed
      --  since SHAKE_128 determines output length from Output'Length
   begin
      SparkPass.Crypto.Keccak.SHAKE_128(Input, Output);
   end SHAKE_128;

end SparkPass.Crypto.MLKEM.XOF;
