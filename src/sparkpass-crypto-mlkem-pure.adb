--  ========================================================================
--  SparkPass Pure SPARK ML-KEM-1024 Implementation Body
--  ========================================================================
--
--  **Purpose**: Complete pure SPARK ML-KEM-1024 implementation
--               Drop-in replacement for liboqs FFI
--
--  **Implementation**: Wires together KeyGen, Encaps, and Decaps modules
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.KeyGen;
with SparkPass.Crypto.MLKEM.Encaps;
with SparkPass.Crypto.MLKEM.Decaps;
with SparkPass.Crypto.Random;

package body SparkPass.Crypto.MLKEM.Pure is

   --  =====================================================================
   --  Keypair: Generate ML-KEM-1024 Key Pair
   --  =====================================================================

   procedure Keypair (
      Public : out Public_Key;
      Secret : out Secret_Key
   ) is
      Seed : Seed_Array;
   begin
      --  Generate random seed for KeyGen
      SparkPass.Crypto.Random.Fill(Seed);

      --  Generate key pair using simple KeyGen interface
      SparkPass.Crypto.MLKEM.KeyGen.KeyGen(
         Random_Seed => Seed,
         PK => Public,
         SK => Secret
      );
   end Keypair;

   --  =====================================================================
   --  Encapsulate: Generate Shared Secret
   --  =====================================================================

   procedure Encapsulate (
      Public  : in Public_Key;
      Cipher  : out Ciphertext;
      Shared  : out Shared_Key;
      Success : out Boolean
   ) is
   begin
      --  Encapsulate shared secret
      SparkPass.Crypto.MLKEM.Encaps.Encapsulate(
         Public, Cipher, Shared
      );

      --  ML-KEM encapsulation always succeeds
      Success := True;

   exception
      when others =>
         --  On any error, zero the shared secret
         Shared := (others => 0);
         Success := False;
   end Encapsulate;

   --  =====================================================================
   --  Decapsulate: Recover Shared Secret
   --  =====================================================================

   procedure Decapsulate (
      Secret  : in Secret_Key;
      Cipher  : in Ciphertext;
      Shared  : out Shared_Key;
      Success : out Boolean
   ) is
   begin
      --  Decapsulate shared secret
      --  Note: Always succeeds due to implicit rejection
      --  (invalid ciphertexts return pseudorandom key)
      SparkPass.Crypto.MLKEM.Decaps.Decapsulate(
         Secret, Cipher, Shared
      );

      --  ML-KEM decapsulation always succeeds (implicit rejection)
      Success := True;

   exception
      when others =>
         --  On any error, zero the shared secret
         Shared := (others => 0);
         Success := False;
   end Decapsulate;

end SparkPass.Crypto.MLKEM.Pure;
