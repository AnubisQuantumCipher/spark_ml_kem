--  ========================================================================
--  SparkPass ML-KEM Encapsulate (Pure SPARK)
--  ========================================================================
--
--  **Purpose**: ML-KEM-1024 key encapsulation (generate shared secret)
--               Implements NIST FIPS 203 Algorithm 16 (ML-KEM.Encaps)
--
--  **Specification**: NIST FIPS 203, Section 7.2
--
--  **Algorithm**:
--    Input: Public key ek (1568 bytes)
--    Output: (K, c) where K is 32-byte shared secret, c is ciphertext
--
--    1. m ← {0,1}^256  (32 random bytes)
--    2. (K̄, c) ← K-PKE.Encrypt(ek, m, H(m))
--    3. K ← H(K̄ || H(c))  (implicit rejection protection)
--    4. return (K, c)
--
--  **Source**: NIST FIPS 203, Algorithm 16
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

package SparkPass.Crypto.MLKEM.Encaps is
   pragma Elaborate_Body;

   --  =====================================================================
   --  Encapsulate: ML-KEM.Encaps (NIST FIPS 203, Algorithm 16)
   --  =====================================================================
   --
   --  **Purpose**: Generate shared secret and ciphertext from public key
   --
   --  **Algorithm**:
   --    Input: ek (public key, 1568 bytes)
   --    Output: (K, c) where:
   --      - K: 32-byte shared secret
   --      - c: Ciphertext (1568 bytes for ML-KEM-1024)
   --
   --  **Security**: IND-CCA2 secure (proven in EasyCrypt)
   --
   --  **Ciphertext Structure** (ML-KEM-1024):
   --    c = c₁ || c₂
   --    c₁ = Encode₁₀(Compress₁₀(u))  -- 1280 bytes (k=4 compressed vectors)
   --    c₂ = Encode₄(Compress₄(v))     -- 128 bytes (single compressed poly)
   --    Total: 1408 bytes
   --
   --  **Source**: NIST FIPS 203, Algorithm 16
   --  =====================================================================

   procedure Encapsulate (
      Public_Key    : in Public_Key_Array;
      Ciphertext    : out Ciphertext_Array;
      Shared_Secret : out Shared_Secret_Array
   ) with
      Global => null,
      Pre    => True,
      Post   => True;
   --  **Purpose**: Encapsulate shared secret using public key
   --  **Input**:
   --    - Public_Key: ML-KEM-1024 public key (1568 bytes)
   --  **Output**:
   --    - Ciphertext: ML-KEM-1024 ciphertext (1408 bytes)
   --    - Shared_Secret: 32-byte shared secret
   --  **Usage**:
   --      PK : Public_Key;
   --      CT : Ciphertext;
   --      SS : Shared_Secret;
   --      Encapsulate(PK, CT, SS);

   --  =====================================================================
   --  Encapsulate_Expanded: Encapsulate with Component Access
   --  =====================================================================
   --
   --  **Purpose**: Same as Encapsulate, but exposes internal components
   --               Useful for testing and debugging
   --  =====================================================================

   procedure Encapsulate_Expanded (
      Public_Key       : in Public_Key_Array;
      Random_Message   : in Seed_Array;  -- For deterministic testing
      Ciphertext       : out Ciphertext_Array;
      Shared_Secret    : out Shared_Secret_Array;
      U_Vector         : out Polynomial_Vector;  -- Intermediate u
      V_Polynomial     : out Polynomial          -- Intermediate v
   ) with
      Global => null,
      Pre    => True,
      Post   => True;
   --  **Purpose**: Encapsulate with deterministic message (for testing)
   --  **Usage**: Primarily for NIST test vector validation

end SparkPass.Crypto.MLKEM.Encaps;
