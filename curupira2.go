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
	if s == 0 {
		return make([]byte, 0)
	}
	constant := make([]byte, 1)
	constant[0] = sBox(byte(s - 1))
	return constant
}

// nextSubkeyCurupira2 - implements Ψr(u) = ξ ∘ @(u ⊕ q(r))
func nextSubkeyCurupira2(K []byte, round int, keyBits int) []byte {
	// Step 1: Add constant (XOR with q(r))
	q := calculateScheduleConstant(round)

	// Create a copy and add constant to most significant byte
	KplusQ := make([]byte, len(K))
	copy(KplusQ, K)
	if len(q) > 0 {
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

	switch keyBits {
	case 96: // 12 bytes
		U11 := K[11]
		T0val := T0(U11)
		T1val := T1(U11)

		for i := 0; i < 9; i++ {
			result[i] = K[i+1]
		}
		result[9] = K[10] ^ T1val
		result[10] = K[0] ^ T0val
		result[11] = U11

	case 144: // 18 bytes
		U17 := K[17]
		T0val := T0(U17)
		T1val := T1(U17)

		for i := 0; i < 10; i++ {
			result[i] = K[i+1]
		}
		result[10] = K[11] ^ T1val
		result[11] = K[10] ^ T0val
		for i := 12; i < 17; i++ {
			result[i] = K[i-12]
		}
		result[17] = U17

	case 192: // 24 bytes
		U23 := K[23]
		T0val := T0(U23)
		T1val := T1(U23)

		for i := 0; i < 17; i++ {
			result[i] = K[i+1]
		}
		result[17] = K[18] ^ T1val
		result[18] = K[17] ^ T0val
		for i := 19; i < 23; i++ {
			result[i] = K[i-19]
		}
		result[23] = U23
	}

	return result
}

// xiTransform - implements the involutive transform ξ
func xiTransform(K []byte, keyBits int) []byte {
	n := len(K)
	result := make([]byte, n)

	switch keyBits {
	case 96: // 12 bytes, identity
		copy(result, K)

	case 144: // 18 bytes
		for i := 0; i < 6; i++ {
			result[i] = K[11-i] ^ K[12+i]
		}
		for i := 6; i < 18; i++ {
			result[i] = K[i]
		}

	case 192: // 24 bytes
		for i := 0; i < 12; i++ {
			result[i] = K[11-i] ^ K[12+i]
		}
		for i := 12; i < 24; i++ {
			result[i] = K[i]
		}
	}

	return result
}

// T0 and T1 as defined in the paper
func T0(u byte) byte {
	return u ^ (u >> 5) ^ (u >> 3)
}

func T1(u byte) byte {
	return (u << 3) ^ (u << 5)
}

// selectRoundKeyCurupira2 - φ*r: takes 12 least significant bytes
func selectRoundKeyCurupira2(Kr []byte) []byte {
	kr := make([]byte, 12)

	for i := 0; i < 12 && i < len(Kr); i++ {
		kr[i] = Kr[i]
	}

	// Apply S-box to bytes that will go to first row (positions 0,3,6,9)
	for j := 0; j < 4; j++ {
		if 3*j < 12 {
			kr[3*j] = sBox(kr[3*j])
		}
	}

	return kr
}

// ============== AEAD LetterSoup Implementation ==============

type AEAD interface {
	SetIV(iv []byte)
	Update(aData []byte)
	Encrypt(mData, cData []byte)
	Decrypt(cData, mData []byte)
	GetTag(tag []byte, tagBits int) []byte
}

type LetterSoup struct {
	mac        MAC
	cipher     BlockCipher
	blockBytes int
	mLength    int
	hLength    int
	iv         []byte
	A          []byte
	D          []byte
	R          []byte
	L          []byte
}

func NewLetterSoup(cipher BlockCipher) AEAD {
	mac := NewMarvin(cipher, nil, true)
	return NewLetterSoupWithMAC(cipher, mac)
}

func NewLetterSoupWithMAC(cipher BlockCipher, mac MAC) AEAD {
	l := new(LetterSoup)
	l.cipher = cipher
	l.blockBytes = cipher.BlockSize()
	l.mac = mac

	return l
}

func (ls *LetterSoup) SetIV(iv []byte) {
	ivLength := len(iv)
	blockBytes := ls.blockBytes

	ls.iv = make([]byte, ivLength)
	copy(ls.iv, iv[:ivLength])

	ls.L = []byte{}

	// Step 2 of Algorithm 2 - Page 6
	ls.R = make([]byte, blockBytes)
	leftPaddedN := make([]byte, blockBytes)

	copy(leftPaddedN[blockBytes-ivLength:], iv[:blockBytes])
	ls.cipher.Encrypt(ls.R, leftPaddedN)
	xor(ls.R, leftPaddedN)
}

func (ls *LetterSoup) Update(aData []byte) {
	aLength := len(aData)
	blockBytes := ls.blockBytes

	// Step 4 of Algorithm 2 - Page 6 (L and part of D)
	ls.L = make([]byte, blockBytes)
	ls.D = make([]byte, blockBytes)

	empty := make([]byte, blockBytes)

	ls.hLength = aLength
	ls.cipher.Encrypt(ls.L, empty)

	ls.mac.InitWithR(ls.L)
	ls.mac.Update(aData)
	ls.mac.GetTag(ls.D, ls.cipher.BlockSize()*8)
}

func (ls *LetterSoup) Encrypt(dst, src []byte) {
	mLength := len(src)
	blockBytes := ls.blockBytes

	// Step 3 of Algorithm 2 - Page 6 (C and part of A)
	ls.A = make([]byte, blockBytes)
	ls.mLength = mLength

	if dst == nil {
		dst = make([]byte, blockBytes)
	}

	ls.LFSRC(src, dst)

	ls.mac.InitWithR(ls.R)
	ls.mac.Update(dst)
	ls.mac.GetTag(ls.A, ls.cipher.BlockSize()*8)
}

func (ls *LetterSoup) Decrypt(dst, src []byte) {
	ls.LFSRC(src, dst)
}

func (ls *LetterSoup) GetTag(tag []byte, tagBits int) []byte {
	if tag == nil {
		tag = make([]byte, tagBits/8)
	}

	blockBytes := ls.blockBytes

	// Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
	Atemp := make([]byte, blockBytes)
	copy(Atemp[0:], ls.A[0:blockBytes])
	auxValue1 := make([]byte, blockBytes)
	auxValue2 := make([]byte, blockBytes)

	// auxValue1 = rpad(bin(n-tagBits)||1)
	diff := int8(ls.cipher.BlockSize()*8 - tagBits)
	if diff == 0 {
		auxValue1[0] = byte(0x80)
		auxValue1[1] = byte(0x00)
	} else if diff < 0 {
		auxValue1[0] = byte(diff)
		auxValue1[1] = byte(0x80)
	} else {
		diff = int8(diff<<1) | int8(0x01)
		for diff > 0 {
			diff = int8(diff << 1)
		}

		auxValue1[0] = byte(diff)
		auxValue1[1] = byte(0x00)
	}

	// auxValue2 = lpad(bin(|M|))
	for i := 0; i < 4; i++ {
		auxValue2[blockBytes-i-1] = byte((ls.mLength * 8) >> (8 * i))
	}

	copy(ls.A[0:], Atemp[0:blockBytes])
	xor(Atemp, auxValue1)
	xor(Atemp, auxValue2)

	// Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
	if len(ls.L) != 0 {
		// auxValue2 = lpad(bin(|H|))
		auxValue2 := make([]byte, blockBytes)

		for i := 0; i < 4; i++ {
			auxValue2[blockBytes-i-1] = byte((ls.hLength * 8) >> (8 * i))
		}

		Dtemp := make([]byte, blockBytes)
		copy(Dtemp[0:], ls.D[0:blockBytes])

		xor(Dtemp, auxValue1)
		xor(Dtemp, auxValue2)
		ls.cipher.Sct(auxValue1, Dtemp)
		xor(Atemp, auxValue1)
	}

	// Step 7 of Algorithm 2 - Page 6
	ls.cipher.Encrypt(auxValue1, Atemp)

	for i := 0; i < tagBits/8; i++ {
		tag[i] = auxValue1[i]
	}

	return tag
}

func (ls *LetterSoup) LFSRC(mData, cData []byte) {
	mLength := len(mData)
	blockBytes := ls.blockBytes

	// Algorithm 8 - Page 20
	M := make([]byte, blockBytes)
	C := make([]byte, blockBytes)
	O := make([]byte, blockBytes)
	copy(O[0:], ls.R[0:blockBytes])

	q := mLength / blockBytes
	r := mLength % blockBytes

	for i := 0; i < q; i++ {
		copy(M[0:], mData[i*blockBytes:])
		ls.updateOffset(O)
		ls.cipher.Encrypt(C, O)
		xor(C, M)
		copy(cData[i*blockBytes:], C[0:])
	}

	if r != 0 {
		copy(M[0:r], mData[q*blockBytes:])
		ls.updateOffset(O)
		ls.cipher.Encrypt(C, O)
		xor(C, M)
		copy(cData[q*blockBytes:], C[0:r])
	}
}

func (ls *LetterSoup) updateOffset(O []byte) {
	// Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
	var O0 byte = O[0]

	copy(O[0:], O[1:12])

	O[9] = byte(O[9] ^ O0 ^ ((O0 & 0xFF) >> 3) ^ ((O0 & 0xFF) >> 5))
	O[10] = byte(O[10] ^ (O0 << 5) ^ (O0 << 3))
	O[11] = O0
}

// ============== MAC Marvin Implementation ==============

type MAC interface {
	Init()
	InitWithR(R []byte)
	Update(aData []byte)
	GetTag(tag []byte, tagBits int) []byte
}

const c byte = 0x2A

type Marvin struct {
	cipher         BlockCipher
	blockBytes     int
	mLength        int
	R              []byte
	O              []byte
	buffer         []byte
	letterSoupMode bool
}

func NewMarvin(cipher BlockCipher, R []byte, letterSoupMode bool) MAC {
	m := new(Marvin)
	m.letterSoupMode = letterSoupMode
	m.cipher = cipher
	m.blockBytes = cipher.BlockSize()

	if R != nil {
		m.InitWithR(R)
	} else {
		m.Init()
	}

	return m
}

func (m *Marvin) Init() {
	blockBytes := m.blockBytes

	m.buffer = make([]byte, blockBytes)
	m.R = make([]byte, blockBytes)
	m.O = make([]byte, blockBytes)

	// Step 2 of Algorithm 1 - Page 4
	leftPaddedC := make([]byte, blockBytes)

	leftPaddedC[blockBytes-1] = c
	m.cipher.Encrypt(m.R, leftPaddedC)

	xor(m.R, leftPaddedC)
	copy(m.O, m.R[0:blockBytes])
}

func (m *Marvin) InitWithR(R []byte) {
	blockBytes := m.blockBytes

	m.buffer = make([]byte, blockBytes)
	m.R = make([]byte, blockBytes)
	m.O = make([]byte, blockBytes)

	copy(m.R, R[0:blockBytes])
	copy(m.O, R[0:blockBytes])
}

func (m *Marvin) Update(aData []byte) {
	aLength := len(aData)
	blockBytes := m.blockBytes

	M := make([]byte, blockBytes)
	A := make([]byte, blockBytes)

	q := aLength / blockBytes
	r := aLength % blockBytes

	// Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
	xor(m.buffer, m.R)

	for i := 0; i < q; i++ {
		copy(M[0:], aData[i*blockBytes:])
		m.updateOffset()
		xor(M, m.O)
		m.cipher.Sct(A, M)
		xor(m.buffer, A)
	}

	if r != 0 {
		copy(M[0:], aData[q*blockBytes:q*blockBytes+r])

		for i := r; i < blockBytes; i++ {
			M[i] = 0
		}

		m.updateOffset()
		xor(M, m.O)
		m.cipher.Sct(A, M)
		xor(m.buffer, A)
	}

	m.mLength = aLength
}

func (m *Marvin) GetTag(tag []byte, tagBits int) []byte {
	if tag == nil {
		tag = make([]byte, tagBits/8)
	}

	blockBytes := m.blockBytes

	if m.letterSoupMode {
		copy(tag[0:], m.buffer[0:blockBytes])
		return tag
	}

	// Steps 6-9 of Algorithm 1 - Page 4
	A := make([]byte, blockBytes)
	encryptedA := make([]byte, blockBytes)
	auxValue1 := make([]byte, blockBytes)
	auxValue2 := make([]byte, blockBytes)

	// auxValue1 = rpad(bin(n-tagBits)||1)
	diff := int8(m.cipher.BlockSize()*8 - tagBits)
	if diff == 0 {
		auxValue1[0] = byte(0x80)
		auxValue1[1] = byte(0x00)
	} else if diff < 0 {
		auxValue1[0] = byte(diff)
		auxValue1[1] = byte(0x80)
	} else {
		diff = int8(diff<<1) | int8(0x01)
		for diff > 0 {
			diff = int8(diff << 1)
		}

		auxValue1[0] = byte(diff)
		auxValue1[1] = byte(0x00)
	}

	// auxValue2 = lpad(bin(|M|))
	processedBits := 8 * m.mLength
	for i := 0; i < 4; i++ {
		auxValue2[blockBytes-i-1] = byte(processedBits >> (8 * i))
	}

	copy(A[0:], m.buffer[0:blockBytes])

	xor(A, auxValue1)
	xor(A, auxValue2)
	m.cipher.Encrypt(encryptedA, A)

	for i := 0; i < tagBits/8; i++ {
		tag[i] = encryptedA[i]
	}

	return tag
}

func (m *Marvin) updateOffset() {
	// Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
	var O0 byte = m.O[0]

	copy(m.O[0:], m.O[1:12])

	m.O[9] = byte(m.O[9] ^ O0 ^ ((O0 & 0xFF) >> 3) ^ ((O0 & 0xFF) >> 5))
	m.O[10] = byte(m.O[10] ^ (O0 << 5) ^ (O0 << 3))
	m.O[11] = O0
}

// ============== Core Cipher Functions ==============

// XOR the contents of b into a in-place
func xor(a, b []byte) {
	subtle.XORBytes(a, a, b)
}

// Tables from Curupira-1
var xTimesTable = [256]byte{
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E,
	0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E,
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E,
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E,
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
	0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE,
	0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
	0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE,
	0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
	0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
	0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
	0x4D, 0x4F, 0x49, 0x4B, 0x45, 0x47, 0x41, 0x43,
	0x5D, 0x5F, 0x59, 0x5B, 0x55, 0x57, 0x51, 0x53,
	0x6D, 0x6F, 0x69, 0x6B, 0x65, 0x67, 0x61, 0x63,
	0x7D, 0x7F, 0x79, 0x7B, 0x75, 0x77, 0x71, 0x73,
	0x0D, 0x0F, 0x09, 0x0B, 0x05, 0x07, 0x01, 0x03,
	0x1D, 0x1F, 0x19, 0x1B, 0x15, 0x17, 0x11, 0x13,
	0x2D, 0x2F, 0x29, 0x2B, 0x25, 0x27, 0x21, 0x23,
	0x3D, 0x3F, 0x39, 0x3B, 0x35, 0x37, 0x31, 0x33,
	0xCD, 0xCF, 0xC9, 0xCB, 0xC5, 0xC7, 0xC1, 0xC3,
	0xDD, 0xDF, 0xD9, 0xDB, 0xD5, 0xD7, 0xD1, 0xD3,
	0xED, 0xEF, 0xE9, 0xEB, 0xE5, 0xE7, 0xE1, 0xE3,
	0xFD, 0xFF, 0xF9, 0xFB, 0xF5, 0xF7, 0xF1, 0xF3,
	0x8D, 0x8F, 0x89, 0x8B, 0x85, 0x87, 0x81, 0x83,
	0x9D, 0x9F, 0x99, 0x9B, 0x95, 0x97, 0x91, 0x93,
	0xAD, 0xAF, 0xA9, 0xAB, 0xA5, 0xA7, 0xA1, 0xA3,
	0xBD, 0xBF, 0xB9, 0xBB, 0xB5, 0xB7, 0xB1, 0xB3,
}

var sBoxTable = [256]byte{
	0xBA, 0x54, 0x2F, 0x74, 0x53, 0xD3, 0xD2, 0x4D,
	0x50, 0xAC, 0x8D, 0xBF, 0x70, 0x52, 0x9A, 0x4C,
	0xEA, 0xD5, 0x97, 0xD1, 0x33, 0x51, 0x5B, 0xA6,
	0xDE, 0x48, 0xA8, 0x99, 0xDB, 0x32, 0xB7, 0xFC,
	0xE3, 0x9E, 0x91, 0x9B, 0xE2, 0xBB, 0x41, 0x6E,
	0xA5, 0xCB, 0x6B, 0x95, 0xA1, 0xF3, 0xB1, 0x02,
	0xCC, 0xC4, 0x1D, 0x14, 0xC3, 0x63, 0xDA, 0x5D,
	0x5F, 0xDC, 0x7D, 0xCD, 0x7F, 0x5A, 0x6C, 0x5C,
	0xF7, 0x26, 0xFF, 0xED, 0xE8, 0x9D, 0x6F, 0x8E,
	0x19, 0xA0, 0xF0, 0x89, 0x0F, 0x07, 0xAF, 0xFB,
	0x08, 0x15, 0x0D, 0x04, 0x01, 0x64, 0xDF, 0x76,
	0x79, 0xDD, 0x3D, 0x16, 0x3F, 0x37, 0x6D, 0x38,
	0xB9, 0x73, 0xE9, 0x35, 0x55, 0x71, 0x7B, 0x8C,
	0x72, 0x88, 0xF6, 0x2A, 0x3E, 0x5E, 0x27, 0x46,
	0x0C, 0x65, 0x68, 0x61, 0x03, 0xC1, 0x57, 0xD6,
	0xD9, 0x58, 0xD8, 0x66, 0xD7, 0x3A, 0xC8, 0x3C,
	0xFA, 0x96, 0xA7, 0x98, 0xEC, 0xB8, 0xC7, 0xAE,
	0x69, 0x4B, 0xAB, 0xA9, 0x67, 0x0A, 0x47, 0xF2,
	0xB5, 0x22, 0xE5, 0xEE, 0xBE, 0x2B, 0x81, 0x12,
	0x83, 0x1B, 0x0E, 0x23, 0xF5, 0x45, 0x21, 0xCE,
	0x49, 0x2C, 0xF9, 0xE6, 0xB6, 0x28, 0x17, 0x82,
	0x1A, 0x8B, 0xFE, 0x8A, 0x09, 0xC9, 0x87, 0x4E,
	0xE1, 0x2E, 0xE4, 0xE0, 0xEB, 0x90, 0xA4, 0x1E,
	0x85, 0x60, 0x00, 0x25, 0xF4, 0xF1, 0x94, 0x0B,
	0xE7, 0x75, 0xEF, 0x34, 0x31, 0xD4, 0xD0, 0x86,
	0x7E, 0xAD, 0xFD, 0x29, 0x30, 0x3B, 0x9F, 0xF8,
	0xC6, 0x13, 0x06, 0x05, 0xC5, 0x11, 0x77, 0x7C,
	0x7A, 0x78, 0x36, 0x1C, 0x39, 0x59, 0x18, 0x56,
	0xB3, 0xB0, 0x24, 0x20, 0xB2, 0x92, 0xA3, 0xC0,
	0x44, 0x62, 0x10, 0xB4, 0x84, 0x43, 0x93, 0xC2,
	0x4A, 0xBD, 0x8F, 0x2D, 0xBC, 0x9C, 0x6A, 0x40,
	0xCF, 0xA2, 0x80, 0x4F, 0x1F, 0xCA, 0xAA, 0x42,
}

func sBox(u byte) byte {
	return sBoxTable[u]
}

func xTimes(u byte) byte {
	return xTimesTable[u]
}

func dTimesa(a []byte, j int, b []byte) {
	d := 3 * j
	v := xTimes(a[0+d] ^ a[1+d] ^ a[2+d])
	w := xTimes(v)

	b[0+d] = a[0+d] ^ v
	b[1+d] = a[1+d] ^ w
	b[2+d] = a[2+d] ^ v ^ w
}

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

// cTimes is kept for compatibility but not used in Curupira-2
func cTimes(u byte) byte {
	return xTimes(
		xTimes(
			xTimes(
				xTimes(u)^u,
			)^u,
		),
	)
}
