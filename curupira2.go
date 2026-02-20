package curupira2

import (
	"crypto/cipher"
	"fmt"

	"github.com/pedroalbanese/curupira2/internal/subtle"
)

const BlockSize = 12

type KeySizeError int

func (k KeySizeError) Error() string {
	return fmt.Sprintf("curupira2: invalid key size %d", int(k))
}

type BlockCipher interface {
	cipher.Block
	Sct(dst, src []byte)
}

type curupira2Cipher struct {
	keyBits             int
	R                   int
	t                   int
	encryptionRoundKeys [][]byte
	decryptionRoundKeys [][]byte
}

// NewCipher creates and returns a new BlockCipher.
func NewCipher(key []byte) (BlockCipher, error) {
	l := len(key)
	switch l {
	case 12, 18, 24:
		break
	default:
		return nil, KeySizeError(l)
	}

	c := new(curupira2Cipher)
	c.expandKey(key)

	return c, nil
}

func (c *curupira2Cipher) BlockSize() int {
	return BlockSize
}

func (c *curupira2Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("curupira2: input not full block")
	}
	if len(dst) < BlockSize {
		panic("curupira2: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("curupira2: invalid buffer overlap")
	}
	c.processBlock(dst, src, c.encryptionRoundKeys)
}

func (c *curupira2Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("curupira2: input not full block")
	}
	if len(dst) < BlockSize {
		panic("curupira2: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("curupira2: invalid buffer overlap")
	}
	c.processBlock(dst, src, c.decryptionRoundKeys)
}

// Sct applies a square-complete transform to exactly one block
func (c *curupira2Cipher) Sct(dst, src []byte) {
	tmp := make([]byte, 12)
	tmp = performUnkeyedRound(src)
	for r := 0; r < 3; r++ {
		tmp = performUnkeyedRound(tmp)
	}
	copy(dst, tmp)
}

func (c *curupira2Cipher) processBlock(dst []byte, src []byte, roundKeys [][]byte) {
	var tmp []byte

	tmp = performWhiteningRound(src, roundKeys[0])
	for r := 1; r <= c.R-1; r++ {
		tmp = performRound(tmp, roundKeys[r])
	}
	tmp = performLastRound(tmp, roundKeys[c.R])
	copy(dst, tmp)
}

// expandKey implements the Curupira-2 key schedule
func (c *curupira2Cipher) expandKey(key []byte) {
	keyBits := len(key) * 8

	switch keyBits {
	case 96:
		c.R = 10
		c.t = 2
	case 144:
		c.R = 14
		c.t = 3
	case 192:
		c.R = 18
		c.t = 4
	}

	c.keyBits = keyBits
	c.keySchedule(key)
}

// keySchedule implements the Curupira-2 key expansion
func (c *curupira2Cipher) keySchedule(key []byte) {
	c.encryptionRoundKeys = make([][]byte, c.R+1)
	c.decryptionRoundKeys = make([][]byte, c.R+1)

	// K(0) = K (user key)
	K := make([]byte, len(key))
	copy(K, key)

	// Generate round keys using the key evolution function Ψr
	for r := 0; r <= c.R; r++ {
		// Select round key (φ*r) - only 12 least significant bytes
		kr := selectRoundKeyCurupira2(K)
		c.encryptionRoundKeys[r] = kr

		// Prepare decryption keys
		if r > 0 {
			c.decryptionRoundKeys[c.R-r] = applyLinearDiffusionLayer(kr)
		}

		// Calculate next subkey: K(r+1) = Ψr(K(r)) = ξ ∘ @(K(r) ⊕ q(r))
		if r < c.R {
			K = nextSubkeyCurupira2(K, r+1, c.keyBits)
		}
	}

	c.decryptionRoundKeys[0] = c.encryptionRoundKeys[c.R]
	c.decryptionRoundKeys[c.R] = c.encryptionRoundKeys[0]
}

// calculateScheduleConstant - q(s) = (S[s-1], 0, ..., 0)
func calculateScheduleConstant(s int) []byte {
	// q(s) is a byte vector of size 6t (12, 18, or 24 bytes)
	// with only the most significant byte set to S[s-1]
	if s == 0 {
		return make([]byte, 0) // q(0) = 0
	}
	
	// The actual size will be determined by the key size in the calling function
	// Here we return just the constant part
	constant := make([]byte, 1)
	constant[0] = sBox(byte(s-1))
	return constant
}

// nextSubkeyCurupira2 - implements Ψr(u) = ξ ∘ @(u ⊕ q(r))
func nextSubkeyCurupira2(K []byte, round int, keyBits int) []byte {
	// Step 1: Add constant (XOR with q(r))
	// q(r) is (S[r-1], 0, ..., 0) - only affects the most significant byte
	q := calculateScheduleConstant(round)
	
	// Create a copy and add constant to most significant byte
	KplusQ := make([]byte, len(K))
	copy(KplusQ, K)
	if len(q) > 0 {
		// XOR with the most significant byte (last byte in little-endian representation)
		KplusQ[len(K)-1] ^= q[0]
	}
	
	// Step 2: Apply @ transform (multiply by x⁸)
	afterAt := multiplyByX8(KplusQ, keyBits)
	
	// Step 3: Apply ξ transform (involutive transform)
	return xiTransform(afterAt, keyBits)
}

// multiplyByX8 - implements @(u) = u · x⁸ mod p(x)
func multiplyByX8(K []byte, keyBits int) []byte {
	n := len(K)
	result := make([]byte, n)
	
	// According to Theorem 1 and the specific equations in section 4.3
	switch keyBits {
	case 96: // 12 bytes
		// @ : (U11, ..., U0) · x⁸ = (U10, ..., U1 ⊕ T1[U11], U0 ⊕ T0[U11], U11)
		U11 := K[11] // most significant byte
		T0val := T0(U11)
		T1val := T1(U11)
		
		// Copy U10...U2
		for i := 0; i < 9; i++ {
			result[i] = K[i+1]
		}
		// U1 ⊕ T1[U11]
		result[9] = K[10] ^ T1val
		// U0 ⊕ T0[U11]
		result[10] = K[0] ^ T0val
		// U11
		result[11] = U11
		
	case 144: // 18 bytes
		// @ : (U17,...,U0)·x⁸ = (U16,...,U6⊕T1[U17],U5⊕T0[U17],...,U0,U17)
		U17 := K[17]
		T0val := T0(U17)
		T1val := T1(U17)
		
		// Copy U16...U7
		for i := 0; i < 10; i++ {
			result[i] = K[i+1]
		}
		// U6 ⊕ T1[U17]
		result[10] = K[11] ^ T1val
		// U5 ⊕ T0[U17]
		result[11] = K[10] ^ T0val
		// Copy U4...U0
		for i := 12; i < 17; i++ {
			result[i] = K[i-12]
		}
		// U17
		result[17] = U17
		
	case 192: // 24 bytes
		// @ : (U23,...,U0)·x⁸ = (U22,...,U5⊕T1[U23],U4⊕T0[U23],...,U0,U23)
		U23 := K[23]
		T0val := T0(U23)
		T1val := T1(U23)
		
		// Copy U22...U6
		for i := 0; i < 17; i++ {
			result[i] = K[i+1]
		}
		// U5 ⊕ T1[U23]
		result[17] = K[18] ^ T1val
		// U4 ⊕ T0[U23]
		result[18] = K[17] ^ T0val
		// Copy U3...U0
		for i := 19; i < 23; i++ {
			result[i] = K[i-19]
		}
		// U23
		result[23] = U23
	}
	
	return result
}

// xiTransform - implements the involutive transform ξ
func xiTransform(K []byte, keyBits int) []byte {
	n := len(K)
	result := make([]byte, n)
	
	// ξ is defined as:
	// v = ξ(u) ⇔ { Vi = U_{11-i} ⊕ U_{12+i} if 0 ≤ i < 6t-12
	//            { Vi = Ui otherwise
	
	switch keyBits {
	case 96: // 12 bytes, 6t-12 = 0, so it's identity
		copy(result, K)
		
	case 144: // 18 bytes, 6t-12 = 6
		// For i = 0 to 5: Vi = U_{11-i} ⊕ U_{12+i}
		for i := 0; i < 6; i++ {
			result[i] = K[11-i] ^ K[12+i]
		}
		// For i = 6 to 17: Vi = Ui
		for i := 6; i < 18; i++ {
			result[i] = K[i]
		}
		
	case 192: // 24 bytes, 6t-12 = 12
		// For i = 0 to 11: Vi = U_{11-i} ⊕ U_{12+i}
		for i := 0; i < 12; i++ {
			result[i] = K[11-i] ^ K[12+i]
		}
		// For i = 12 to 23: Vi = Ui
		for i := 12; i < 24; i++ {
			result[i] = K[i]
		}
	}
	
	return result
}

// T0 and T1 as defined in the paper
func T0(u byte) byte {
	// T0 = U ⊕ (U >> 5) ⊕ (U >> 3)
	return u ^ (u >> 5) ^ (u >> 3)
}

func T1(u byte) byte {
	// T1 = (U << 3) ⊕ (U << 5)
	return (u << 3) ^ (u << 5)
}

// selectRoundKeyCurupira2 - φ*r: takes 12 least significant bytes
func selectRoundKeyCurupira2(Kr []byte) []byte {
	kr := make([]byte, 12)
	
	// Take the 12 least significant bytes (U0...U11)
	for i := 0; i < 12 && i < len(Kr); i++ {
		kr[i] = Kr[i]
	}
	
	// Apply S-box to bytes that will go to first row (i=0)
	// In the 3x4 matrix representation, first row bytes are at positions 0,3,6,9
	for j := 0; j < 4; j++ {
		if 3*j < 12 {
			kr[3*j] = sBox(kr[3*j])
		}
	}
	
	return kr
}

// All the following functions are IDENTICAL to Curupira-1
// (copied from the original implementation)

func applyNonLinearLayer(a []byte) []byte {
	b := make([]byte, 12)
	for i := 0; i < 12; i++ {
		b[i] = sBox(a[i])
	}
	return b
}

func applyPermutationLayer(a []byte) []byte {
	b := make([]byte, 12)
	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			b[i+3*j] = a[i+3*(i^j)]
		}
	}
	return b
}

func applyLinearDiffusionLayer(a []byte) []byte {
	b := make([]byte, 12)
	for j := 0; j < 4; j++ {
		dTimesa(a, j, b)
	}
	return b
}

func applyKeyAddition(a, kr []byte) []byte {
	b := make([]byte, 12)
	for i := 0; i < 12; i++ {
		b[i] = a[i] ^ kr[i]
	}
	return b
}

func performWhiteningRound(a, k0 []byte) []byte {
	return applyKeyAddition(a, k0)
}

func performLastRound(a, kR []byte) []byte {
	return applyKeyAddition(
		applyPermutationLayer(
			applyNonLinearLayer(a),
		),
		kR,
	)
}

func performRound(a, kr []byte) []byte {
	return applyKeyAddition(
		applyLinearDiffusionLayer(
			applyPermutationLayer(
				applyNonLinearLayer(a),
			),
		),
		kr,
	)
}

func performUnkeyedRound(a []byte) []byte {
	return applyLinearDiffusionLayer(
		applyPermutationLayer(
			applyNonLinearLayer(a),
		),
	)
}

func dTimesa(a []byte, j int, b []byte) {
	d := 3 * j
	v := xTimes(a[0+d] ^ a[1+d] ^ a[2+d])
	w := xTimes(v)

	b[0+d] = a[0+d] ^ v
	b[1+d] = a[1+d] ^ w
	b[2+d] = a[2+d] ^ v ^ w
}

func xTimes(u byte) byte {
	return xTimesTable[u]
}

func xor(a, b []byte) {
	subtle.XORBytes(a, a, b)
}

// Tables from Curupira-1
var xTimesTable = [256]byte{0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E, 0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE, 0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE, 0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE, 0x4D, 0x4F, 0x49, 0x4B, 0x45, 0x47, 0x41, 0x43, 0x5D, 0x5F, 0x59, 0x5B, 0x55, 0x57, 0x51, 0x53, 0x6D, 0x6F, 0x69, 0x6B, 0x65, 0x67, 0x61, 0x63, 0x7D, 0x7F, 0x79, 0x7B, 0x75, 0x77, 0x71, 0x73, 0x0D, 0x0F, 0x09, 0x0B, 0x05, 0x07, 0x01, 0x03, 0x1D, 0x1F, 0x19, 0x1B, 0x15, 0x17, 0x11, 0x13, 0x2D, 0x2F, 0x29, 0x2B, 0x25, 0x27, 0x21, 0x23, 0x3D, 0x3F, 0x39, 0x3B, 0x35, 0x37, 0x31, 0x33, 0xCD, 0xCF, 0xC9, 0xCB, 0xC5, 0xC7, 0xC1, 0xC3, 0xDD, 0xDF, 0xD9, 0xDB, 0xD5, 0xD7, 0xD1, 0xD3, 0xED, 0xEF, 0xE9, 0xEB, 0xE5, 0xE7, 0xE1, 0xE3, 0xFD, 0xFF, 0xF9, 0xFB, 0xF5, 0xF7, 0xF1, 0xF3, 0x8D, 0x8F, 0x89, 0x8B, 0x85, 0x87, 0x81, 0x83, 0x9D, 0x9F, 0x99, 0x9B, 0x95, 0x97, 0x91, 0x93, 0xAD, 0xAF, 0xA9, 0xAB, 0xA5, 0xA7, 0xA1, 0xA3, 0xBD, 0xBF, 0xB9, 0xBB, 0xB5, 0xB7, 0xB1, 0xB3}

var sBoxTable = [256]byte{0xBA, 0x54, 0x2F, 0x74, 0x53, 0xD3, 0xD2, 0x4D, 0x50, 0xAC, 0x8D, 0xBF, 0x70, 0x52, 0x9A, 0x4C, 0xEA, 0xD5, 0x97, 0xD1, 0x33, 0x51, 0x5B, 0xA6, 0xDE, 0x48, 0xA8, 0x99, 0xDB, 0x32, 0xB7, 0xFC, 0xE3, 0x9E, 0x91, 0x9B, 0xE2, 0xBB, 0x41, 0x6E, 0xA5, 0xCB, 0x6B, 0x95, 0xA1, 0xF3, 0xB1, 0x02, 0xCC, 0xC4, 0x1D, 0x14, 0xC3, 0x63, 0xDA, 0x5D, 0x5F, 0xDC, 0x7D, 0xCD, 0x7F, 0x5A, 0x6C, 0x5C, 0xF7, 0x26, 0xFF, 0xED, 0xE8, 0x9D, 0x6F, 0x8E, 0x19, 0xA0, 0xF0, 0x89, 0x0F, 0x07, 0xAF, 0xFB, 0x08, 0x15, 0x0D, 0x04, 0x01, 0x64, 0xDF, 0x76, 0x79, 0xDD, 0x3D, 0x16, 0x3F, 0x37, 0x6D, 0x38, 0xB9, 0x73, 0xE9, 0x35, 0x55, 0x71, 0x7B, 0x8C, 0x72, 0x88, 0xF6, 0x2A, 0x3E, 0x5E, 0x27, 0x46, 0x0C, 0x65, 0x68, 0x61, 0x03, 0xC1, 0x57, 0xD6, 0xD9, 0x58, 0xD8, 0x66, 0xD7, 0x3A, 0xC8, 0x3C, 0xFA, 0x96, 0xA7, 0x98, 0xEC, 0xB8, 0xC7, 0xAE, 0x69, 0x4B, 0xAB, 0xA9, 0x67, 0x0A, 0x47, 0xF2, 0xB5, 0x22, 0xE5, 0xEE, 0xBE, 0x2B, 0x81, 0x12, 0x83, 0x1B, 0x0E, 0x23, 0xF5, 0x45, 0x21, 0xCE, 0x49, 0x2C, 0xF9, 0xE6, 0xB6, 0x28, 0x17, 0x82, 0x1A, 0x8B, 0xFE, 0x8A, 0x09, 0xC9, 0x87, 0x4E, 0xE1, 0x2E, 0xE4, 0xE0, 0xEB, 0x90, 0xA4, 0x1E, 0x85, 0x60, 0x00, 0x25, 0xF4, 0xF1, 0x94, 0x0B, 0xE7, 0x75, 0xEF, 0x34, 0x31, 0xD4, 0xD0, 0x86, 0x7E, 0xAD, 0xFD, 0x29, 0x30, 0x3B, 0x9F, 0xF8, 0xC6, 0x13, 0x06, 0x05, 0xC5, 0x11, 0x77, 0x7C, 0x7A, 0x78, 0x36, 0x1C, 0x39, 0x59, 0x18, 0x56, 0xB3, 0xB0, 0x24, 0x20, 0xB2, 0x92, 0xA3, 0xC0, 0x44, 0x62, 0x10, 0xB4, 0x84, 0x43, 0x93, 0xC2, 0x4A, 0xBD, 0x8F, 0x2D, 0xBC, 0x9C, 0x6A, 0x40, 0xCF, 0xA2, 0x80, 0x4F, 0x1F, 0xCA, 0xAA, 0x42}

func sBox(u byte) byte {
	return sBoxTable[u]
}
