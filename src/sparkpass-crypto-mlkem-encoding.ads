--  ========================================================================
--  SparkPass ML-KEM Encoding/Decoding (Pure SPARK)
--  ========================================================================
--
--  **Purpose**: Encode and decode polynomials/vectors for ML-KEM-1024
--               Implements FIPS 203 bit-packing algorithms
--
--  **Specification**: NIST FIPS 203, Section 4.2.1
--
--  **Functions**:
--    - ByteEncode_d / ByteDecode_d: Bit-packed encoding with d bits/coeff
--    - Compress_d / Decompress_d: Lossy compression for ciphertexts
--    - Encode_Vector / Decode_Vector: Encode k-vectors of polynomials
--
--  **Bit Widths for ML-KEM-1024**:
--    - Secret key s: 12 bits/coeff (no compression)
--    - Public key t: 12 bits/coeff (no compression)
--    - Ciphertext u: 10 bits/coeff (compressed from 12)
--    - Ciphertext v: 4 bits/coeff (compressed from 12)
--
--  **Source**: NIST FIPS 203, Algorithm 4 (ByteEncode), Algorithm 5 (ByteDecode)
--
--  ========================================================================

pragma SPARK_Mode (On);

with SparkPass.Types; use SparkPass.Types;
with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

package SparkPass.Crypto.MLKEM.Encoding is
   

   --  =====================================================================
   --  Encoding Size Constants
   --  =====================================================================

   --  ByteEncode₁₂: 256 coeffs × 12 bits = 3072 bits = 384 bytes
   Bytes_Per_Poly_12 : constant := 384;

   --  ByteEncode₁₁: 256 coeffs × 11 bits = 2816 bits = 352 bytes (ML-KEM-1024)
   Bytes_Per_Poly_11 : constant := 352;

   --  ByteEncode₁₀: 256 coeffs × 10 bits = 2560 bits = 320 bytes (ML-KEM-768)
   Bytes_Per_Poly_10 : constant := 320;

   --  ByteEncode₅: 256 coeffs × 5 bits = 1280 bits = 160 bytes (ML-KEM-1024)
   Bytes_Per_Poly_5 : constant := 160;

   --  ByteEncode₄: 256 coeffs × 4 bits = 1024 bits = 128 bytes (ML-KEM-768)
   Bytes_Per_Poly_4 : constant := 128;

   --  Vector encoding sizes for ML-KEM-1024 (k=4)
   Bytes_Per_Vector_12 : constant := 4 * Bytes_Per_Poly_12;  -- 1536 bytes
   Bytes_Per_Vector_11 : constant := 4 * Bytes_Per_Poly_11;  -- 1408 bytes
   Bytes_Per_Vector_10 : constant := 4 * Bytes_Per_Poly_10;  -- 1280 bytes

   --  =====================================================================
   --  ByteEncode₁₂: Encode polynomial with 12 bits per coefficient
   --  =====================================================================
   --
   --  **Purpose**: Encode polynomial for secret/public keys (no compression)
   --
   --  **Algorithm** (NIST FIPS 203, Algorithm 4):
   --    Input: Polynomial F with 256 coefficients in Z_q (q=3329)
   --    Output: Byte array B of length 384 bytes (256 × 12 / 8)
   --
   --  **Encoding**:
   --    Each coefficient is encoded as 12-bit little-endian integer
   --    Coefficients are packed sequentially into bytes
   --
   --  **Example**:
   --    F[0] = 0x5A3 (1443), F[1] = 0x1F2 (498)
   --    B[0] = 0xA3 (low 8 bits of F[0])
   --    B[1] = 0xF5 (high 4 bits of F[0] || low 4 bits of F[1])
   --    B[2] = 0x1F (high 8 bits of F[1])
   --
   --  **Bit Layout** (first 3 bytes for F[0], F[1]):
   --    B[0]: [F[0]₇ F[0]₆ F[0]₅ F[0]₄ F[0]₃ F[0]₂ F[0]₁ F[0]₀]
   --    B[1]: [F[1]₃ F[1]₂ F[1]₁ F[1]₀ F[0]₁₁ F[0]₁₀ F[0]₉ F[0]₈]
   --    B[2]: [F[1]₁₁ F[1]₁₀ F[1]₉ F[1]₈ F[1]₇ F[1]₆ F[1]₅ F[1]₄]
   --
   --  **Source**: NIST FIPS 203, Algorithm 4
   --  =====================================================================

   procedure ByteEncode_12 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Poly_12 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Poly_12;
   --  **Purpose**: Encode polynomial to 384-byte array (12 bits/coeff)
   --  **Input**: Polynomial with 256 coefficients
   --  **Output**: 384-byte encoded array
   --  **Usage**:
   --      Secret_Bytes : Byte_Array(1 .. 384);
   --      ByteEncode_12(Secret_Poly, Secret_Bytes);

   --  =====================================================================
   --  ByteDecode₁₂: Decode polynomial from 12-bit encoding
   --  =====================================================================
   --
   --  **Purpose**: Decode byte array to polynomial (inverse of ByteEncode₁₂)
   --
   --  **Algorithm** (NIST FIPS 203, Algorithm 5):
   --    Input: Byte array B of length 384 bytes
   --    Output: Polynomial F with 256 coefficients in Z_q
   --
   --  **Decoding**:
   --    Extract 12-bit little-endian values from byte array
   --    Each 3 bytes encodes 2 coefficients
   --
   --  **Example**:
   --    B[0] = 0xA3, B[1] = 0xF5, B[2] = 0x1F
   --    F[0] = (B[1] & 0x0F) << 8 | B[0] = 0x5A3 (1443)
   --    F[1] = B[2] << 4 | (B[1] >> 4) = 0x1F2 (498)
   --
   --  **Source**: NIST FIPS 203, Algorithm 5
   --  =====================================================================

   procedure ByteDecode_12 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Poly_12 and Input'First = 1,
      Post   => True;
   --  **Purpose**: Decode 384-byte array to polynomial (12 bits/coeff)
   --  **Input**: 384-byte encoded array
   --  **Output**: Polynomial with 256 coefficients
   --  **Usage**:
   --      Secret_Poly : Polynomial;
   --      ByteDecode_12(Secret_Bytes, Secret_Poly);

   --  =====================================================================
   --  ByteEncode₁₀: Encode polynomial with 10 bits per coefficient
   --  =====================================================================
   --
   --  **Purpose**: Encode compressed ciphertext u vector
   --
   --  **Algorithm**: Same as ByteEncode₁₂ but with 10 bits per coefficient
   --    256 coeffs × 10 bits = 2560 bits = 320 bytes
   --    Each 5 bytes encodes 4 coefficients
   --
   --  **Source**: NIST FIPS 203, Algorithm 4 (with d=10)
   --  =====================================================================

   procedure ByteEncode_10 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Poly_10 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Poly_10;
   --  **Purpose**: Encode polynomial to 320-byte array (10 bits/coeff)
   --  **Usage**: After Compress₁₀ for ciphertext u

   --  =====================================================================
   --  ByteDecode₁₀: Decode polynomial from 10-bit encoding
   --  =====================================================================

   procedure ByteDecode_10 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Poly_10 and Input'First = 1,
      Post   => True;
   --  **Purpose**: Decode 320-byte array to polynomial (10 bits/coeff)
   --  **Usage**: Before Decompress₁₀ for ciphertext u

   --  =====================================================================
   --  ByteEncode₄: Encode polynomial with 4 bits per coefficient
   --  =====================================================================
   --
   --  **Purpose**: Encode compressed ciphertext v (single polynomial)
   --
   --  **Algorithm**: 256 coeffs × 4 bits = 1024 bits = 128 bytes
   --    Each byte encodes 2 coefficients
   --
   --  **Source**: NIST FIPS 203, Algorithm 4 (with d=4)
   --  =====================================================================

   procedure ByteEncode_4 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Poly_4 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Poly_4;
   --  **Purpose**: Encode polynomial to 128-byte array (4 bits/coeff)
   --  **Usage**: After Compress₄ for ciphertext v

   --  =====================================================================
   --  ByteDecode₄: Decode polynomial from 4-bit encoding
   --  =====================================================================

   procedure ByteDecode_4 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Poly_4 and Input'First = 1,
      Post   => True;
   --  **Purpose**: Decode 128-byte array to polynomial (4 bits/coeff)
   --  **Usage**: Before Decompress₄ for ciphertext v

   --  =====================================================================
   --  Compress_d: Compress coefficient to d bits
   --  =====================================================================
   --
   --  **Purpose**: Lossy compression for ciphertext components
   --
   --  **Algorithm** (NIST FIPS 203, Section 4.2.1):
   --    Compress_d(x) = ⌈(2^d / q) × x⌋ mod 2^d
   --    where q = 3329, x ∈ [0, q)
   --
   --  **For d=10** (ciphertext u):
   --    Compress₁₀(x) = ⌈(1024 / 3329) × x⌋ mod 1024
   --
   --  **For d=4** (ciphertext v):
   --    Compress₄(x) = ⌈(16 / 3329) × x⌋ mod 16
   --
   --  **Security**: Information-theoretically lossy (intentional)
   --  **Purpose**: Reduce ciphertext size while preserving correctness
   --
   --  **Source**: NIST FIPS 203, Algorithm 3
   --  =====================================================================

   function Compress_10 (X : Coefficient) return Coefficient
   with
      Global => null,
      Post   => Compress_10'Result < 1024;  -- Result in [0, 2^10)
   --  **Purpose**: Compress coefficient to 10 bits
   --  **Input**: x ∈ [0, 3329)
   --  **Output**: y ∈ [0, 1024)

   function Compress_4 (X : Coefficient) return Coefficient
   with
      Global => null,
      Post   => Compress_4'Result < 16;  -- Result in [0, 2^4)
   --  **Purpose**: Compress coefficient to 4 bits
   --  **Input**: x ∈ [0, 3329)
   --  **Output**: y ∈ [0, 16)

   --  =====================================================================
   --  Decompress_d: Decompress coefficient from d bits
   --  =====================================================================
   --
   --  **Purpose**: Reverse compression (with information loss)
   --
   --  **Algorithm** (NIST FIPS 203, Section 4.2.1):
   --    Decompress_d(y) = ⌈(q / 2^d) × y⌋
   --    where q = 3329, y ∈ [0, 2^d)
   --
   --  **Property**: Decompress_d(Compress_d(x)) ≈ x (with rounding error)
   --
   --  **Source**: NIST FIPS 203, Algorithm 3
   --  =====================================================================

   function Decompress_10 (Y : Coefficient) return Coefficient
   with
      Global => null,
      Pre    => Y < 1024,
      Post   => Decompress_10'Result < Q;
   --  **Purpose**: Decompress coefficient from 10 bits
   --  **Input**: y ∈ [0, 1024)
   --  **Output**: x ∈ [0, 3329)

   function Decompress_4 (Y : Coefficient) return Coefficient
   with
      Global => null,
      Pre    => Y < 16,
      Post   => Decompress_4'Result < Q;
   --  **Purpose**: Decompress coefficient from 4 bits
   --  **Input**: y ∈ [0, 16)
   --  **Output**: x ∈ [0, 3329)

   --  =====================================================================
   --  Vector Encoding Functions
   --  =====================================================================
   --
   --  **Purpose**: Encode/decode k-vectors of polynomials
   --  **For ML-KEM-1024**: k = 4
   --  =====================================================================

   procedure Encode_Vector_12 (
      Vec    : in Polynomial_Vector;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Vector_12 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Vector_12;
   --  **Purpose**: Encode 4-vector to 1536 bytes (4 × 384)
   --  **Usage**: Encode secret key s or public key t

   procedure Decode_Vector_12 (
      Input : in Byte_Array;
      Vec   : out Polynomial_Vector
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Vector_12 and Input'First = 1,
      Post   => True;
   --  **Purpose**: Decode 1536 bytes to 4-vector
   --  **Usage**: Decode secret key s or public key t

   procedure Encode_Vector_10 (
      Vec    : in Polynomial_Vector;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Vector_10 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Vector_10;
   --  **Purpose**: Encode compressed 4-vector to 1280 bytes (4 × 320)
   --  **Usage**: Encode ciphertext u after compression

   procedure Decode_Vector_10 (
      Input : in Byte_Array;
      Vec   : out Polynomial_Vector
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Vector_10 and Input'First = 1,
      Post   => True;
   --  **Purpose**: Decode 1280 bytes to compressed 4-vector
   --  **Usage**: Decode ciphertext u before decompression

   --  =====================================================================
   --  ML-KEM-1024 Specific Encoding (11/5-bit)
   --  =====================================================================

   procedure ByteEncode_11 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Poly_11 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Poly_11;

   procedure ByteDecode_11 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Poly_11 and Input'First = 1,
      Post   => True;

   procedure ByteEncode_5 (
      Poly   : in Polynomial;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Poly_5 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Poly_5;

   procedure ByteDecode_5 (
      Input : in Byte_Array;
      Poly  : out Polynomial
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Poly_5 and Input'First = 1,
      Post   => True;

   function Compress_11 (X : Coefficient) return Coefficient
      with Inline;

   function Decompress_11 (Y : Coefficient) return Coefficient
      with Inline;

   function Compress_5 (X : Coefficient) return Coefficient
      with Inline;

   function Decompress_5 (Y : Coefficient) return Coefficient
      with Inline;

   procedure Encode_Vector_11 (
      Vec    : in Polynomial_Vector;
      Output : out Byte_Array
   ) with
      Global => null,
      Pre    => Output'Length = Bytes_Per_Vector_11 and Output'First = 1,
      Post   => Output'Length = Bytes_Per_Vector_11;

   procedure Decode_Vector_11 (
      Input : in Byte_Array;
      Vec   : out Polynomial_Vector
   ) with
      Global => null,
      Pre    => Input'Length = Bytes_Per_Vector_11 and Input'First = 1,
      Post   => True;

end SparkPass.Crypto.MLKEM.Encoding;
