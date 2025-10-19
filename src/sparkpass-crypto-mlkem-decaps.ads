--  ========================================================================
--  SparkPass ML-KEM Decapsulate (Pure SPARK)
--  ========================================================================
--
--  **Purpose**: ML-KEM-1024 decapsulation (recover shared secret)
--               Implements NIST FIPS 203 Algorithm 18 (ML-KEM.Decaps)
--
--  **Specification**: NIST FIPS 203, Section 7.3
--
--  **Algorithm**:
--    Input: Secret key dk (3168 bytes), Ciphertext c (1568 bytes)
--    Output: Shared secret K (32 bytes)
--
--    1. Decode secret key: (dk_pke, ek, h, z) ← dk
--    2. m' ← K-PKE.Decrypt(dk_pke, c)
--    3. (K̄, c') ← K-PKE.Encrypt(ek, m', H(m'))
--    4. If c = c': K ← H(K̄ || H(c))      [success]
--       Else:     K ← H(z || H(c))        [implicit rejection]
--    5. return K
--
--  **Source**: NIST FIPS 203, Algorithm 18
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

package SparkPass.Crypto.MLKEM.Decaps is
   pragma Elaborate_Body;

   --  =====================================================================
   --  Decapsulate: ML-KEM.Decaps (NIST FIPS 203, Algorithm 18)
   --  =====================================================================
   --
   --  **Purpose**: Recover shared secret from ciphertext using secret key
   --
   --  **Algorithm**:
   --    Input: dk (secret key, 3168 bytes), c (ciphertext, 1568 bytes)
   --    Output: K (shared secret, 32 bytes)
   --
   --  **Security**: IND-CCA2 secure via Fujisaki-Okamoto transform
   --    - If decryption succeeds: K = H(K̄ || H(c))
   --    - If decryption fails: K = H(z || H(c)) [implicit rejection]
   --
   --  **Implicit Rejection**:
   --    Returns pseudorandom key on failure (indistinguishable from success)
   --    Prevents chosen-ciphertext attacks
   --
   --  **Source**: NIST FIPS 203, Algorithm 18
   --  =====================================================================

   procedure Decapsulate (
      Secret_Key    : in Secret_Key_Array;
      Ciphertext    : in Ciphertext_Array;
      Shared_Secret : out Shared_Secret_Array
   ) with
      Global => null,
      Pre    => True,
      Post   => True;
   --  **Purpose**: Decapsulate shared secret from ciphertext
   --  **Input**:
   --    - Secret_Key: ML-KEM-1024 secret key (3168 bytes)
   --    - Ciphertext: ML-KEM-1024 ciphertext (1568 bytes)
   --  **Output**:
   --    - Shared_Secret: 32-byte shared secret
   --  **Usage**:
   --      SK : Secret_Key_Array;
   --      CT : Ciphertext_Array;
   --      SS : Shared_Secret_Array;
   --      Decapsulate(SK, CT, SS);

   --  =====================================================================
   --  Decapsulate_Expanded: Decapsulate with Component Access
   --  =====================================================================
   --
   --  **Purpose**: Same as Decapsulate, but exposes internal components
   --               Useful for testing and debugging
   --  =====================================================================

   procedure Decapsulate_Expanded (
      Secret_Key       : in Secret_Key_Array;
      Ciphertext       : in Ciphertext_Array;
      Shared_Secret    : out Shared_Secret_Array;
      Recovered_Msg    : out Seed_Array;  -- Decrypted message m'
      Valid            : out Boolean      -- True if c = c' (authentic)
   ) with
      Global => null,
      Pre    => True,
      Post   => True;
   --  **Purpose**: Decapsulate with validation check (for testing)
   --  **Output**:
   --    - Recovered_Msg: Decrypted message from ciphertext
   --    - Valid: True if ciphertext is authentic, False if rejected

end SparkPass.Crypto.MLKEM.Decaps;
