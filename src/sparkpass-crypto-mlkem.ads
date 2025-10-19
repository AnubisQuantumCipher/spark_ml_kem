pragma SPARK_Mode (On);
with SparkPass.Config;
with SparkPass.Types; use SparkPass.Types; use type SparkPass.Types.U8;

package SparkPass.Crypto.MLKEM is
   subtype Public_Key  is MLKem_Public_Key_Array;
   subtype Secret_Key  is MLKem_Secret_Key_Array;
   subtype Ciphertext  is MLKem_Ciphertext_Array;
   subtype Shared_Key  is MLKem_Shared_Key_Array;

   procedure Keypair (Public : out Public_Key; Secret : out Secret_Key)
     with
       Global  => null,
       Depends => (Public => null, Secret => null);

   procedure Encapsulate
     (Public     : Public_Key;
      Cipher     : out Ciphertext;
      Shared     : out Shared_Key;
      Success    : out Boolean)
     with
       Global  => null,
       Depends => (Cipher => Public, Shared => Public, Success => Public),
       Post    => (if not Success then
                     (for all I in Shared'Range => Shared (I) = 0));

   procedure Decapsulate
     (Secret     : Secret_Key;
      Cipher     : Ciphertext;
      Shared     : out Shared_Key;
      Success    : out Boolean)
     with
       Global  => null,
       Depends => (Shared => (Secret, Cipher), Success => (Secret, Cipher)),
       Post    => (if not Success then
                     (for all I in Shared'Range => Shared (I) = 0));

end SparkPass.Crypto.MLKEM;
