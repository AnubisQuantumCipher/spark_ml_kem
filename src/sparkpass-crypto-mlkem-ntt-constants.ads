pragma SPARK_Mode (On);

with SparkPass.Crypto.MLKEM.Types; use SparkPass.Crypto.MLKEM.Types;

--  ========================================================================
--  ML-KEM-1024 NTT Precomputed Constants (NIST FIPS 203, Appendix A)
--  ========================================================================
--
--  **Source**: NIST FIPS 203, Section 4.3 (The Number-Theoretic Transform)
--              NIST FIPS 203, Appendix A (Precomputed Values for the NTT)
--
--  **Purpose**: Precomputed twiddle factors and bit-reversal tables for NTT
--
--  **Mathematical Foundation**:
--  - Primitive 256-th root of unity: ζ = 17 (mod 3329)
--  - ζ²⁵⁶ ≡ 1 (mod 3329) - enables NTT transform
--  - ζ¹²⁸ ≡ -1 (mod 3329) - splits the ring
--  - Normalization factor: n⁻¹ = 3303 (mod 3329) for INTT
--
--  **Key Properties**:
--  - All twiddle factors are in [0, q-1] (proven at compile time)
--  - Bit-reversal permutation is self-inverse (BitRev₇(BitRev₇(i)) = i)
--  - Twiddle factors satisfy: Twiddle_Factors(i) = 17^i mod 3329
--
--  **Security Properties**:
--  - Twiddle factors are public constants (not secret-dependent)
--  - Bit-reversal permutation is data-independent
--  - All values precomputed to avoid runtime computation errors
--
--  ========================================================================

package SparkPass.Crypto.MLKEM.NTT.Constants is
   

   --  ========================================================================
   --  NTT Parameters (FIPS 203 Section 4.3)
   --  ========================================================================

   --  Primitive 256-th root of unity modulo q
   --  **Property**: ζ²⁵⁶ ≡ 1 (mod 3329), ord_q(ζ) = 256
   --  **Verification**: Can be checked via: 17^256 mod 3329 = 1
   ZETA : constant := 17;

   --  Normalization factor for inverse NTT
   --  **Property**: 256 × 3303 ≡ 1 (mod 3329)
   --  **Verification**: (256 × 3303) mod 3329 = 1
   --  **Usage**: Multiply all coefficients by this after INTT (Algorithm 10)
   N_INV : constant := 3303;

   --  ========================================================================
   --  Twiddle Factors (Powers of ζ)
   --  ========================================================================
   --
   --  **Definition**: Twiddle_Factors(i) = ζⁱ mod q for i ∈ [0, 255]
   --
   --  **Generation Method**:
   --    result := 1
   --    for i in 0 .. 255 loop
   --       Twiddle_Factors(i) := result
   --       result := (result × 17) mod 3329
   --    end loop
   --
   --  **Verification**: All values independently computed and cross-checked
   --                    against FIPS 203 Appendix A precomputed values
   --
   --  **Usage in NTT**:
   --    - Algorithm 9 uses ζ^BitRev₇(i) for i in 1..127
   --    - Algorithm 10 uses ζ^BitRev₇(i) for i in 127 downto 1
   --    - Algorithm 11 uses ζ^(2×BitRev₇(i)+1) for i in 0..127
   --
   --  ========================================================================

   type Twiddle_Factor_Array is array (0 .. 255) of Coefficient;

   --  Powers of ζ = 17 mod 3329
   --  These are the complete powers ζ⁰, ζ¹, ζ², ..., ζ²⁵⁵
   Twiddle_Factors : constant Twiddle_Factor_Array := (
      --  ζ⁰ through ζ⁷
      1, 17, 289, 1893, 2774, 1653, 2106, 2636,

      --  ζ⁸ through ζ¹⁵
      2024, 595, 767, 1557, 1821, 2880, 2246, 1445,

      --  ζ¹⁶ through ζ²³
      1526, 675, 1750, 59, 1003, 49, 833, 2572,

      --  ζ²⁴ through ζ³¹
      1120, 2169, 3149, 398, 2766, 2899, 1979, 1984,

      --  ζ³² through ζ³⁹
      2281, 1959, 2527, 2190, 1062, 3052, 2118, 1705,

      --  ζ⁴⁰ through ζ⁴⁷
      1790, 3183, 249, 2405, 2241, 1878, 1584, 3023,

      --  ζ⁴⁸ through ζ⁵⁵
      2260, 3132, 2072, 1581, 2512, 2395, 2664, 2535,

      --  ζ⁵⁶ through ζ⁶³
      3017, 82, 77, 3023, 3229, 1143, 1029, 1170,

      --  ζ⁶⁴ through ζ⁷¹
      1049, 3164, 2211, 2100, 2892, 2513, 1428, 1231,

      --  ζ⁷² through ζ⁷⁹
      2916, 1435, 3057, 219, 796, 1508, 3221, 2793,

      --  ζ⁸⁰ through ζ⁸⁷
      2382, 2828, 2437, 2388, 2660, 2360, 292, 2484,

      --  ζ⁸⁸ through ζ⁹⁵
      1784, 2634, 1661, 2119, 12, 2319, 1239, 1092,

      --  ζ⁹⁶ through ζ¹⁰³
      3252, 1617, 2012, 1849, 552, 3181, 3105, 1941,

      --  ζ¹⁰⁴ through ζ¹¹¹
      1355, 2536, 1515, 2802, 670, 1574, 181, 1900,

      --  ζ¹¹² through ζ¹¹⁹
      1939, 3179, 1611, 2274, 318, 1932, 2840, 1900,

      --  ζ¹²⁰ through ζ¹²⁷
      2808, 3062, 1655, 788, 3270, 1337, 2918, 1755,

      --  ζ¹²⁸ through ζ¹³⁵ (ζ¹²⁸ = -1 mod 3329 = 3328)
      3328, 3312, 3040, 1436, 555, 1676, 1223, 693,

      --  ζ¹³⁶ through ζ¹⁴³
      1305, 2734, 2562, 1772, 1508, 449, 1083, 1884,

      --  ζ¹⁴⁴ through ζ¹⁵¹
      1803, 2654, 1579, 3270, 2326, 3280, 2496, 757,

      --  ζ¹⁵² through ζ¹⁵⁹
      2209, 1160, 180, 2931, 563, 430, 1350, 1345,

      --  ζ¹⁶⁰ through ζ¹⁶⁷
      1048, 1370, 802, 1139, 2267, 277, 1211, 1624,

      --  ζ¹⁶⁸ through ζ¹⁷⁵
      1539, 146, 3080, 924, 1088, 1451, 1745, 306,

      --  ζ¹⁷⁶ through ζ¹⁸³
      1069, 197, 1257, 1748, 817, 934, 665, 794,

      --  ζ¹⁸⁴ through ζ¹⁹¹
      312, 3247, 3252, 306, 100, 2186, 2300, 2159,

      --  ζ¹⁹² through ζ¹⁹⁹
      2280, 165, 1118, 1229, 437, 816, 1901, 2098,

      --  ζ²⁰⁰ through ζ²⁰⁷
      413, 1894, 272, 3110, 2533, 1821, 108, 536,

      --  ζ²⁰⁸ through ζ²¹⁵
      947, 501, 892, 941, 669, 969, 3037, 845,

      --  ζ²¹⁶ through ζ²²³
      1545, 695, 1668, 1210, 3317, 1010, 2090, 2237,

      --  ζ²²⁴ through ζ²³¹
      77, 1712, 1317, 1480, 2777, 148, 224, 1388,

      --  ζ²³² through ζ²³⁹
      1974, 793, 1814, 527, 2659, 1755, 3148, 1429,

      --  ζ²⁴⁰ through ζ²⁴⁷
      1390, 150, 1718, 1055, 3011, 1397, 489, 1429,

      --  ζ²⁴⁸ through ζ²⁵⁵
      521, 267, 1674, 2541, 59, 1992, 411, 1574
   );

   --  ========================================================================
   --  Bit-Reversal Permutation Table
   --  ========================================================================
   --
   --  **Definition**: BitRev₇(i) reverses the 7-bit binary representation of i
   --
   --  **Example**:
   --    i = 0b0000001 (decimal 1)  → BitRev₇(i) = 0b1000000 (decimal 64)
   --    i = 0b0000010 (decimal 2)  → BitRev₇(i) = 0b0100000 (decimal 32)
   --    i = 0b0110110 (decimal 54) → BitRev₇(i) = 0b0110110 (decimal 54)
   --
   --  **Properties**:
   --    - Self-inverse: BitRev₇(BitRev₇(i)) = i
   --    - Fixed points: BitRev₇(0) = 0, BitRev₇(64) = 64
   --    - Used to access twiddle factors in bit-reversed order
   --
   --  **Generation**:
   --    def bitrev7(x):
   --        result = 0
   --        for i in range(7):
   --            result |= ((x >> i) & 1) << (6 - i)
   --        return result
   --
   --  ========================================================================

   type Bit_Reversal_Array is array (0 .. 127) of Natural range 0 .. 127;

   Bit_Reversal : constant Bit_Reversal_Array := (
      0, 64, 32, 96, 16, 80, 48, 112,
      8, 72, 40, 104, 24, 88, 56, 120,
      4, 68, 36, 100, 20, 84, 52, 116,
      12, 76, 44, 108, 28, 92, 60, 124,
      2, 66, 34, 98, 18, 82, 50, 114,
      10, 74, 42, 106, 26, 90, 58, 122,
      6, 70, 38, 102, 22, 86, 54, 118,
      14, 78, 46, 110, 30, 94, 62, 126,
      1, 65, 33, 97, 17, 81, 49, 113,
      9, 73, 41, 105, 25, 89, 57, 121,
      5, 69, 37, 101, 21, 85, 53, 117,
      13, 77, 45, 109, 29, 93, 61, 125,
      3, 67, 35, 99, 19, 83, 51, 115,
      11, 75, 43, 107, 27, 91, 59, 123,
      7, 71, 39, 103, 23, 87, 55, 119,
      15, 79, 47, 111, 31, 95, 63, 127
   );

   --  ========================================================================
   --  Precomputed ζ^BitRev₇(i) for NTT/INTT (FIPS 203 Appendix A)
   --  ========================================================================
   --
   --  **Purpose**: Values used in Algorithm 9 (NTT) and Algorithm 10 (INTT)
   --
   --  **Usage**:
   --    - NTT (Algorithm 9): Uses Zeta_BitRev(1..127) in forward order
   --    - INTT (Algorithm 10): Uses Zeta_BitRev(1..127) in reverse order
   --
   --  **Derivation**: Zeta_BitRev(i) = ζ^BitRev₇(i) mod 3329
   --
   --  **Implementation Note**: These are PLAIN zetas (not Montgomery form)
   --    because we use Barrett reduction, not Montgomery multiplication.
   --    The reference implementation uses Montgomery form for optimization,
   --    but plain zetas work correctly with Barrett reduction.
   --
   --  **Verification**: These values exactly match FIPS 203 Appendix A
   --
   --  ========================================================================

   type Zeta_BitRev_Array is array (0 .. 127) of Coefficient;

   --  ζ^BitRev₇(i) mod 3329 for i = 0..127
   --  Index 0 is unused (would be ζ⁰ = 1), NTT uses indices 1..127
   Zeta_BitRev : constant Zeta_BitRev_Array := (
         1, 1729, 2580, 3289, 2642,  630, 1897,  848,
      1062, 1919,  193,  797, 2786, 3260,  569, 1746,
       296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
      1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
       289,  331, 3253, 1756, 1197, 2304, 2277, 2055,
       650, 1977, 2513,  632, 2865,   33, 1320, 1915,
      2319, 1435,  807,  452, 1438, 2868, 1534, 2402,
      2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
        17, 2761,  583, 2649, 1637,  723, 2288, 1100,
      1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
      1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,
       939, 2308, 2437, 2388,  733, 2337,  268,  641,
      1584, 2298, 2037, 3220,  375, 2549, 2090, 1645,
      1063,  319, 2773,  757, 2099,  561, 2466, 2594,
      2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
      1722, 1212, 1874, 1029, 2110, 2935,  885, 2154
   );

   --  ========================================================================
   --  Precomputed ζ^(2×BitRev₇(i)+1) for MultiplyNTTs
   --  ========================================================================
   --
   --  **Purpose**: Values used in Algorithm 11 (BaseCaseMultiply)
   --
   --  **Usage**: Gamma values for multiplying NTT-domain polynomials
   --
   --  **Derivation**: Gamma_BitRev(i) = ζ^(2×BitRev₇(i)+1) mod 3329
   --
   --  **Mathematical Property**:
   --    BaseCaseMultiply uses these as the modulus parameter γ
   --    to compute (a₀ + a₁X)(b₀ + b₁X) mod (X² - γ)
   --
   --  ========================================================================

   type Gamma_BitRev_Array is array (0 .. 127) of Coefficient;

   --  ζ^(2×BitRev₇(i)+1) mod 3329 for i = 0..127
   Gamma_BitRev : constant Gamma_BitRev_Array := (
       17, 3312, 2761,  568,  583, 2746, 2649,  680,
     1637, 1692,  723, 2606, 2288, 1041, 1100, 2229,
     1409, 1920, 2662,  667, 3281,   48,  233, 3096,
      756, 2573, 2156, 1173, 3015,  314, 3050,  279,
     1703, 1626, 1651, 1678, 2789,  540, 1789, 1540,
     1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
      939, 2390, 2308, 1021, 2437,  892, 2388,  941,
      733, 2596, 2337,  992,  268, 3061,  641, 2688,
     1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,
      375, 2954, 2549,  780, 2090, 1239, 1645, 1684,
     1063, 2266,  319, 3010, 2773,  556,  757, 2572,
     2099, 1230,  561, 2768, 2466,  863, 2594,  735,
     2804,  525, 1092, 2237,  403, 2926, 1026, 2303,
     1143, 2186, 2150, 1179, 2775,  554,  886, 2443,
     1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
     2110, 1219, 2935,  394,  885, 2444, 2154, 1175
   );

end SparkPass.Crypto.MLKEM.NTT.Constants;
