--  ========================================================================
--  SparkPass Pure SPARK ML-KEM-1024 Implementation
--  ========================================================================
--
--  **Purpose**: Complete pure SPARK ML-KEM-1024 implementation
--               Replaced liboqs FFI with pure SPARK verified code
--
--  **Implementation**: NIST FIPS 203 validated (see ML_KEM_FIPS_203_VALIDATION.md)
--
--  **Status**: ✅ VALIDATED against NIST KAT vectors
--
--  **Security**: IND-CCA2 secure under Module-LWE assumption
--
--  **Date**: 2025-10-19 (Switched from liboqs to pure SPARK)
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;
with SparkPass.Crypto.MLKEM.KeyGen;
with SparkPass.Crypto.MLKEM.Encaps;
with SparkPass.Crypto.MLKEM.Decaps;
with SparkPass.Crypto.Random;

package body SparkPass.Crypto.MLKEM is

   --  =====================================================================
   --  Keypair: Generate ML-KEM-1024 Key Pair
   --  =====================================================================
   --
   --  Uses NIST FIPS 203 Algorithm 15 (ML-KEM.KeyGen)
   --
   --  =====================================================================

   procedure Keypair (
      Public : out Public_Key;
      Secret : out Secret_Key
   ) is
      Seed : Seed_Array;
   begin
      --  Generate random seed for KeyGen (32 bytes)
      SparkPass.Crypto.Random.Fill(Seed);

      --  Generate key pair using SPARK-verified KeyGen
      SparkPass.Crypto.MLKEM.KeyGen.KeyGen(
         Random_Seed => Seed,
         PK => Public,
         SK => Secret
      );
   end Keypair;

   --  =====================================================================
   --  Encapsulate: Generate Shared Secret
   --  =====================================================================
   --
   --  Uses NIST FIPS 203 Algorithm 16 (ML-KEM.Encaps)
   --  Validated against NIST KAT Vector 0
   --
   --  =====================================================================

   procedure Encapsulate (
      Public  : in Public_Key;
      Cipher  : out Ciphertext;
      Shared  : out Shared_Key;
      Success : out Boolean
   ) is
   begin
      --  Encapsulate shared secret using SPARK-verified Encaps
      --  Returns K̄ directly per FIPS 203 (no additional hashing)
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
   --
   --  Uses NIST FIPS 203 Algorithm 18 (ML-KEM.Decaps)
   --  Validated against NIST KAT Vector 0
   --
   --  Implements implicit rejection:
   --    - Valid ciphertext: Returns K̄ (from G)
   --    - Invalid ciphertext: Returns SHAKE256(z || c) (pseudorandom)
   --
   --  =====================================================================

   procedure Decapsulate (
      Secret  : in Secret_Key;
      Cipher  : in Ciphertext;
      Shared  : out Shared_Key;
      Success : out Boolean
   ) is
   begin
      --  Decapsulate shared secret using SPARK-verified Decaps
      --  Includes implicit rejection (SHAKE256(z||c) on invalid ciphertext)
      --  Note: Always succeeds due to implicit rejection mechanism
      --  (invalid ciphertexts return pseudorandom key, indistinguishable from valid)
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

end SparkPass.Crypto.MLKEM;
