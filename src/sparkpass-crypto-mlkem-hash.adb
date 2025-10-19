--  ========================================================================
--  SparkPass ML-KEM Hash Functions Implementation
--  ========================================================================

pragma SPARK_Mode (On);

package body SparkPass.Crypto.MLKEM.Hash is

   --  =====================================================================
   --  G_Expand_Seed: SHA3-512 Seed Expansion
   --  =====================================================================

   procedure G_Expand_Seed (
      Seed   : in Byte_Array;
      K      : in U8;
      Output : out SHA3_512_Digest
   ) is
      --  Concatenate Seed || K for SHA3-512 input
      Input : Byte_Array(1 .. 33);
   begin
      --  Copy seed
      Input(1 .. 32) := Seed;

      --  Append k value
      Input(33) := K;

      --  Call Keccak SHA3-512
      SparkPass.Crypto.Keccak.SHA3_512_Hash(Input, Output);
   end G_Expand_Seed;

   --  =====================================================================
   --  H_Hash_Public_Key: SHA3-256 of Public Key
   --  =====================================================================

   procedure H_Hash_Public_Key (
      Public_Key : in Byte_Array;
      Output     : out SHA3_256_Digest
   ) is
   begin
      --  Direct call to Keccak SHA3-256
      SparkPass.Crypto.Keccak.SHA3_256_Hash(Public_Key, Output);
   end H_Hash_Public_Key;

   --  =====================================================================
   --  SHA3_256_Hash: General-Purpose SHA3-256
   --  =====================================================================

   procedure SHA3_256_Hash (
      Input  : in Byte_Array;
      Output : out SHA3_256_Digest
   ) is
   begin
      SparkPass.Crypto.Keccak.SHA3_256_Hash(Input, Output);
   end SHA3_256_Hash;

   --  =====================================================================
   --  SHA3_512_Hash: General-Purpose SHA3-512
   --  =====================================================================

   procedure SHA3_512_Hash (
      Input  : in Byte_Array;
      Output : out SHA3_512_Digest
   ) is
   begin
      SparkPass.Crypto.Keccak.SHA3_512_Hash(Input, Output);
   end SHA3_512_Hash;

end SparkPass.Crypto.MLKEM.Hash;
