package curupira2

import (
	"crypto/cipher"
	"fmt"
	"crypto/subtle"
)

// BlockSize constante do tamanho do bloco (12 bytes)
const BlockSize = 12

// S-Box table
var sBoxTable = [256]byte{
	0xba, 0x54, 0x2f, 0x74, 0x53, 0xd3, 0xd2, 0x4d,
	0x50, 0xac, 0x8d, 0xbf, 0x70, 0x52, 0x9a, 0x4c,
	0xea, 0xd5, 0x97, 0xd1, 0x33, 0x51, 0x5b, 0xa6,
	0xde, 0x48, 0xa8, 0x99, 0xdb, 0x32, 0xb7, 0xfc,
	0xe3, 0x9e, 0x91, 0x9b, 0xe2, 0xbb, 0x41, 0x6e,
	0xa5, 0xcb, 0x6b, 0x95, 0xa1, 0xf3, 0xb1, 0x02,
	0xcc, 0xc4, 0x1d, 0x14, 0xc3, 0x63, 0xda, 0x5d,
	0x5f, 0xdc, 0x7d, 0xcd, 0x7f, 0x5a, 0x6c, 0x5c,
	0xf7, 0x26, 0xff, 0xed, 0xe8, 0x9d, 0x6f, 0x8e,
	0x19, 0xa0, 0xf0, 0x89, 0x0f, 0x07, 0xaf, 0xfb,
	0x08, 0x15, 0x0d, 0x04, 0x01, 0x64, 0xdf, 0x76,
	0x79, 0xdd, 0x3d, 0x16, 0x3f, 0x37, 0x6d, 0x38,
	0xb9, 0x73, 0xe9, 0x35, 0x55, 0x71, 0x7b, 0x8c,
	0x72, 0x88, 0xf6, 0x2a, 0x3e, 0x5e, 0x27, 0x46,
	0x0c, 0x65, 0x68, 0x61, 0x03, 0xc1, 0x57, 0xd6,
	0xd9, 0x58, 0xd8, 0x66, 0xd7, 0x3a, 0xc8, 0x3c,
	0xfa, 0x96, 0xa7, 0x98, 0xec, 0xb8, 0xc7, 0xae,
	0x69, 0x4b, 0xab, 0xa9, 0x67, 0x0a, 0x47, 0xf2,
	0xb5, 0x22, 0xe5, 0xee, 0xbe, 0x2b, 0x81, 0x12,
	0x83, 0x1b, 0x0e, 0x23, 0xf5, 0x45, 0x21, 0xce,
	0x49, 0x2c, 0xf9, 0xe6, 0xb6, 0x28, 0x17, 0x82,
	0x1a, 0x8b, 0xfe, 0x8a, 0x09, 0xc9, 0x87, 0x4e,
	0xe1, 0x2e, 0xe4, 0xe0, 0xeb, 0x90, 0xa4, 0x1e,
	0x85, 0x60, 0x00, 0x25, 0xf4, 0xf1, 0x94, 0x0b,
	0xe7, 0x75, 0xef, 0x34, 0x31, 0xd4, 0xd0, 0x86,
	0x7e, 0xad, 0xfd, 0x29, 0x30, 0x3b, 0x9f, 0xf8,
	0xc6, 0x13, 0x06, 0x05, 0xc5, 0x11, 0x77, 0x7c,
	0x7a, 0x78, 0x36, 0x1c, 0x39, 0x59, 0x18, 0x56,
	0xb3, 0xb0, 0x24, 0x20, 0xb2, 0x92, 0xa3, 0xc0,
	0x44, 0x62, 0x10, 0xb4, 0x84, 0x43, 0x93, 0xc2,
	0x4a, 0xbd, 0x8f, 0x2d, 0xbc, 0x9c, 0x6a, 0x40,
	0xcf, 0xa2, 0x80, 0x4f, 0x1f, 0xca, 0xaa, 0x42,
}

// X-times table
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

func sBox(v byte) byte   { return sBoxTable[v] }
func xTimes(v byte) byte { return xTimesTable[v] }
func T0(v byte) byte     { return (v << 5) ^ (v << 3) }
func T1(v byte) byte     { return v ^ (v >> 3) ^ (v >> 5) }

// Cipher representa a estrutura do Curupira2
type Cipher struct {
	keyEnc         []byte
	keyDec         []byte
	keyLength      byte
	numberOfRounds byte
}

// BlockCipher interface para compatibilidade
type BlockCipher interface {
	cipher.Block
	Sct(dst, src []byte)
}

var _ BlockCipher = (*Cipher)(nil)

func getRoundsFromKeyLength(keyLen int) (byte, error) {
	switch keyLen {
	case 12:
		return 10, nil
	case 18:
		return 12, nil
	case 24:
		return 14, nil
	default:
		return 0, ErrInvalidKeyLength
	}
}

// NewCipher cria uma nova instância do Curupira2
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 12 && len(key) != 18 && len(key) != 24 {
		return nil, ErrInvalidKeyLength
	}

	rounds, err := getRoundsFromKeyLength(len(key))
	if err != nil {
		return nil, err
	}

	c := &Cipher{
		keyEnc:         make([]byte, len(key)),
		keyDec:         make([]byte, len(key)),
		keyLength:      byte(len(key) - 1),
		numberOfRounds: rounds,
	}

	copy(c.keyEnc, key)
	copy(c.keyDec, key)

	// Gera as subchaves de decriptação
	msb := byte(0)
	for i := byte(0); i < rounds; i++ {
		c.createNextKey(c.keyDec, &msb, 0)
	}

	return c, nil
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

func (c *Cipher) createNextKey(key []byte, msb *byte, isDecryption byte) {
	var aux1, aux2 byte

	if isDecryption != 0 {
		if *msb == 0 {
			*msb = c.keyLength
		} else {
			*msb--
		}
		aux2 = key[*msb]
		key[*msb] ^= sBox(*msb)
	} else {
		key[*msb] ^= sBox(*msb)
		aux2 = key[*msb]
	}

	if *msb != 0 {
		aux1 = *msb - 1
	} else {
		aux1 = c.keyLength
	}
	key[aux1] ^= T0(aux2)

	if aux1 != 0 {
		aux1--
	} else {
		aux1 = c.keyLength
	}
	key[aux1] ^= T1(aux2)

	if isDecryption == 0 {
		*msb++
		if *msb > c.keyLength {
			*msb = 0
		}
	}
}

func (c *Cipher) swapCT(ptr1, ptr2 int, block []byte) {
	aux := sBox(block[ptr1])
	block[ptr1] = sBox(block[ptr2])
	block[ptr2] = aux
}

func (c *Cipher) sOnRow1(ptr1, ptr2 int, block []byte) {
	block[ptr1] = sBox(block[ptr1])
	block[ptr2] = sBox(block[ptr2])
	c.swapCT(ptr1+1, ptr2+1, block)
}

func (c *Cipher) updatePosMsb(posMsb *byte) {
	*posMsb++
	if *posMsb > c.keyLength {
		*posMsb = 0
	}
}

func (c *Cipher) applyKey(block []byte, key []byte, msb byte) byte {
	posMsb := msb

	for i := 0; i < 12; {
		block[i] ^= sBox(key[posMsb])
		i++
		posMsb++
		if posMsb > c.keyLength {
			posMsb = 0
		}
		if i >= 12 {
			break
		}

		block[i] ^= key[posMsb]
		i++
		posMsb++
		if posMsb > c.keyLength {
			posMsb = 0
		}
		if i >= 12 {
			break
		}

		block[i] ^= key[posMsb]
		i++
		posMsb++
		if posMsb > c.keyLength {
			posMsb = 0
		}
	}
	return posMsb
}

// Crypt - implementação do Curupira2
func (c *Cipher) Crypt(dst, src []byte, dirDecryption byte) {
	block := make([]byte, BlockSize)
	copy(block, src)

	// Cria cópias locais das chaves
	keyEnc := make([]byte, len(c.keyEnc))
	keyDec := make([]byte, len(c.keyDec))
	copy(keyEnc, c.keyEnc)
	copy(keyDec, c.keyDec)

	var key []byte
	msb := byte(0)
	originalMsb := byte(0)

	if dirDecryption != 0 {
		key = keyDec
		msb = c.numberOfRounds
		originalMsb = c.numberOfRounds
	} else {
		key = keyEnc
		msb = 0
		originalMsb = 0
	}

	// Whitening - NÃO modifica o msb original
	c.applyKey(block, key, msb)

	// Rounds - usa o msb original
	msb = originalMsb

	for r := byte(1); r <= c.numberOfRounds; r++ {
		// Permutation layer
		c.sOnRow1(0, 3, block)
		c.swapCT(2, 8, block)
		c.sOnRow1(6, 9, block)
		c.swapCT(5, 11, block)

		// Cria chave da próxima rodada
		c.createNextKey(key, &msb, dirDecryption)

		if r == c.numberOfRounds {
			c.applyKey(block, key, msb)
			break
		}

		// Theta layer
		posMsb := msb
		for i := 0; i < 4; i++ {
			aux3 := key[posMsb]
			c.updatePosMsb(&posMsb)
			aux3 = sBox(aux3)

			ptr := i * 3
			aux1 := block[ptr] ^ block[ptr+1] ^ block[ptr+2]

			if dirDecryption != 0 {
				aux2 := posMsb + 1
				if aux2 > c.keyLength {
					aux2 = 0
				}
				aux1 ^= aux3 ^ key[posMsb] ^ key[aux2]
			}

			aux1 = xTimes(aux1)
			aux2v := xTimes(aux1)

			block[ptr] ^= aux1 ^ aux3
			block[ptr+1] ^= aux2v ^ key[posMsb]
			c.updatePosMsb(&posMsb)

			block[ptr+2] ^= aux1 ^ aux2v ^ key[posMsb]
			c.updatePosMsb(&posMsb)
		}
	}

	copy(dst, block)
}

// Encrypt encripta um bloco
func (c *Cipher) Encrypt(dst, src []byte) {
	temp := make([]byte, BlockSize)
	c.Crypt(temp, src, 0)

	// Reorganiza para formato row-major (C style)
	dst[0] = temp[0]   // (0,0)
	dst[1] = temp[3]   // (0,1)
	dst[2] = temp[6]   // (0,2)
	dst[3] = temp[9]   // (0,3)
	dst[4] = temp[1]   // (1,0)
	dst[5] = temp[4]   // (1,1)
	dst[6] = temp[7]   // (1,2)
	dst[7] = temp[10]  // (1,3)
	dst[8] = temp[2]   // (2,0)
	dst[9] = temp[5]   // (2,1)
	dst[10] = temp[8]  // (2,2)
	dst[11] = temp[11] // (2,3)
}

// Decrypt decripta um bloco
func (c *Cipher) Decrypt(dst, src []byte) {
	temp := make([]byte, BlockSize)

	// Reorganiza do formato row-major para column-major
	temp[0] = src[0]   // (0,0)
	temp[1] = src[4]   // (1,0)
	temp[2] = src[8]   // (2,0)
	temp[3] = src[1]   // (0,1)
	temp[4] = src[5]   // (1,1)
	temp[5] = src[9]   // (2,1)
	temp[6] = src[2]   // (0,2)
	temp[7] = src[6]   // (1,2)
	temp[8] = src[10]  // (2,2)
	temp[9] = src[3]   // (0,3)
	temp[10] = src[7]  // (1,3)
	temp[11] = src[11] // (2,3)

	c.Crypt(dst, temp, 1)
}

// Sct aplica a transformação Square Complete Transform (4 rounds não chaveados)
func (c *Cipher) Sct(dst, src []byte) {
	tmp := make([]byte, BlockSize)
	copy(tmp, src)

	for r := 0; r < 4; r++ {
		c.sOnRow1(0, 3, tmp)
		c.swapCT(2, 8, tmp)
		c.sOnRow1(6, 9, tmp)
		c.swapCT(5, 11, tmp)

		for i := 0; i < 4; i++ {
			ptr := i * 3
			aux1 := tmp[ptr] ^ tmp[ptr+1] ^ tmp[ptr+2]
			aux1 = xTimes(aux1)
			aux2 := xTimes(aux1)

			tmp[ptr] ^= aux1
			tmp[ptr+1] ^= aux2
			tmp[ptr+2] ^= aux1 ^ aux2
		}
	}

	copy(dst, tmp)
}

// Erros
var ErrInvalidKeyLength = &errInvalidKeyLength{}

type errInvalidKeyLength struct{}

func (e *errInvalidKeyLength) Error() string {
	return "curupira2: invalid key length (must be 12, 18, or 24 bytes)"
}

// printMatrix imprime matriz no formato C (row-major)
func printMatrix(matrix []byte, label string) {
	if label != "" {
		fmt.Printf("\n%s:\n", label)
	}
	for row := 0; row < 3; row++ {
		fmt.Print("| ")
		for col := 0; col < 4; col++ {
			idx := row*4 + col
			fmt.Printf(" %02x ", matrix[idx])
		}
		fmt.Println(" |")
	}
}

// =============== IMPLEMENTAÇÃO AEAD LETTERSOUP ===============

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

func (this *LetterSoup) SetIV(iv []byte) {
	ivLength := len(iv)
	blockBytes := this.blockBytes

	this.iv = make([]byte, ivLength)
	copy(this.iv, iv[:ivLength])

	this.L = []byte{}

	// Step 2 of Algorithm 2 - Page 6
	this.R = make([]byte, blockBytes)
	leftPaddedN := make([]byte, blockBytes)

	copy(leftPaddedN[blockBytes-ivLength:], iv[:blockBytes])
	this.cipher.Encrypt(this.R, leftPaddedN)
	xor(this.R, leftPaddedN)
}

func (this *LetterSoup) Update(aData []byte) {
	aLength := len(aData)
	blockBytes := this.blockBytes

	// Step 4 of Algorithm 2 - Page 6 (L and part of D)
	this.L = make([]byte, blockBytes)
	this.D = make([]byte, blockBytes)

	empty := make([]byte, blockBytes)

	this.hLength = aLength
	this.cipher.Encrypt(this.L, empty)

	this.mac.InitWithR(this.L)
	this.mac.Update(aData)
	this.mac.GetTag(this.D, this.cipher.BlockSize()*8)
}

func (this *LetterSoup) Encrypt(dst, src []byte) {
	mLength := len(src)
	blockBytes := this.blockBytes

	// Step 3 of Algorithm 2 - Page 6 (C and part of A)
	this.A = make([]byte, blockBytes)
	this.mLength = mLength

	if dst == nil {
		dst = make([]byte, blockBytes)
	}

	this.LFSRC(src, dst)

	this.mac.InitWithR(this.R)
	this.mac.Update(dst)
	this.mac.GetTag(this.A, this.cipher.BlockSize()*8)
}

func (this *LetterSoup) Decrypt(dst, src []byte) {
	this.LFSRC(src, dst)
}

func (this *LetterSoup) GetTag(tag []byte, tagBits int) []byte {
	if tag == nil {
		tag = make([]byte, tagBits/8)
	}

	blockBytes := this.blockBytes

	// Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
	Atemp := make([]byte, blockBytes)
	copy(Atemp[0:], this.A[0:blockBytes])
	auxValue1 := make([]byte, blockBytes)
	auxValue2 := make([]byte, blockBytes)

	// auxValue1 = rpad(bin(n-tagBits)||1)
	diff := int8(this.cipher.BlockSize()*8 - tagBits)
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
		auxValue2[blockBytes-i-1] = byte((this.mLength * 8) >> (8 * i))
	}

	copy(this.A[0:], Atemp[0:blockBytes])
	xor(Atemp, auxValue1)
	xor(Atemp, auxValue2)

	// Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
	if len(this.L) != 0 {
		// auxValue2 = lpad(bin(|H|))
		auxValue2 := make([]byte, blockBytes)

		for i := 0; i < 4; i++ {
			auxValue2[blockBytes-i-1] = byte((this.hLength * 8) >> (8 * i))
		}

		Dtemp := make([]byte, blockBytes)
		copy(Dtemp[0:], this.D[0:blockBytes])

		xor(Dtemp, auxValue1)
		xor(Dtemp, auxValue2)
		this.cipher.Sct(auxValue1, Dtemp)
		xor(Atemp, auxValue1)
	}

	// Step 7 of Algorithm 2 - Page 6
	this.cipher.Encrypt(auxValue1, Atemp)

	for i := 0; i < tagBits/8; i++ {
		tag[i] = auxValue1[i]
	}

	return tag
}

func (this *LetterSoup) LFSRC(mData, cData []byte) {
	mLength := len(mData)
	blockBytes := this.blockBytes

	// Algorithm 8 - Page 20
	M := make([]byte, blockBytes)
	C := make([]byte, blockBytes)
	O := make([]byte, blockBytes)
	copy(O[0:], this.R[0:blockBytes])

	q := mLength / blockBytes
	r := mLength % blockBytes

	for i := 0; i < q; i++ {
		copy(M[0:], mData[i*blockBytes:])
		this.updateOffset(O)
		this.cipher.Encrypt(C, O)
		xor(C, M)
		copy(cData[i*blockBytes:], C[0:])
	}

	if r != 0 {
		copy(M[0:r], mData[q*blockBytes:])
		this.updateOffset(O)
		this.cipher.Encrypt(C, O)
		xor(C, M)
		copy(cData[q*blockBytes:], C[0:r])
	}
}

func (this *LetterSoup) updateOffset(O []byte) {
	// Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
	var O0 byte = O[0]

	copy(O[0:], O[1:12])

	O[9] = byte(O[9] ^ O0 ^ ((O0 & 0xFF) >> 3) ^ ((O0 & 0xFF) >> 5))
	O[10] = byte(O[10] ^ (O0 << 5) ^ (O0 << 3))
	O[11] = O0
}

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

func (this *Marvin) Init() {
	blockBytes := this.blockBytes

	this.buffer = make([]byte, blockBytes)
	this.R = make([]byte, blockBytes)
	this.O = make([]byte, blockBytes)

	// Step 2 of Algorithm 1 - Page 4
	leftPaddedC := make([]byte, blockBytes)

	leftPaddedC[blockBytes-1] = c
	this.cipher.Encrypt(this.R, leftPaddedC)

	xor(this.R, leftPaddedC)
	copy(this.O, this.R[0:blockBytes])
}

func (this *Marvin) InitWithR(R []byte) {
	blockBytes := this.blockBytes

	this.buffer = make([]byte, blockBytes)
	this.R = make([]byte, blockBytes)
	this.O = make([]byte, blockBytes)

	copy(this.R, R[0:blockBytes])
	copy(this.O, R[0:blockBytes])
}

func (this *Marvin) Update(aData []byte) {
	aLength := len(aData)
	blockBytes := this.blockBytes

	M := make([]byte, blockBytes)
	A := make([]byte, blockBytes)

	q := aLength / blockBytes
	r := aLength % blockBytes

	// Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
	xor(this.buffer, this.R)

	for i := 0; i < q; i++ {
		copy(M[0:], aData[i*blockBytes:])
		this.updateOffset()
		xor(M, this.O)
		this.cipher.Sct(A, M)
		xor(this.buffer, A)
	}

	if r != 0 {
		copy(M[0:], aData[q*blockBytes:q*blockBytes+r])

		for i := r; i < blockBytes; i++ {
			M[i] = 0
		}

		this.updateOffset()
		xor(M, this.O)
		this.cipher.Sct(A, M)
		xor(this.buffer, A)
	}

	this.mLength = aLength
}

func (this *Marvin) GetTag(tag []byte, tagBits int) []byte {
	if tag == nil {
		tag = make([]byte, tagBits/8)
	}

	blockBytes := this.blockBytes

	if this.letterSoupMode {
		copy(tag[0:], this.buffer[0:blockBytes])
		return tag
	}

	// Steps 6-9 of Algorithm 1 - Page 4
	A := make([]byte, blockBytes)
	encryptedA := make([]byte, blockBytes)
	auxValue1 := make([]byte, blockBytes)
	auxValue2 := make([]byte, blockBytes)

	// auxValue1 = rpad(bin(n-tagBits)||1)
	diff := int8(this.cipher.BlockSize()*8 - tagBits)
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
	processedBits := 8 * this.mLength
	for i := 0; i < 4; i++ {
		auxValue2[blockBytes-i-1] = byte(processedBits >> (8 * i))
	}

	copy(A[0:], this.buffer[0:blockBytes])

	xor(A, auxValue1)
	xor(A, auxValue2)
	this.cipher.Encrypt(encryptedA, A)

	for i := 0; i < tagBits/8; i++ {
		tag[i] = encryptedA[i]
	}

	return tag
}

func (this *Marvin) updateOffset() {
	// Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)
	var O0 byte = this.O[0]

	copy(this.O[0:], this.O[1:12])

	this.O[9] = byte(this.O[9] ^ O0 ^ ((O0 & 0xFF) >> 3) ^ ((O0 & 0xFF) >> 5))
	this.O[10] = byte(this.O[10] ^ (O0 << 5) ^ (O0 << 3))
	this.O[11] = O0
}

// XOR the contents of b into a in-place
func xor(a, b []byte) {
	subtle.XORBytes(a, a, b)
}

func initXTimesTable() {
	var u, d int

	for u = 0x00; u <= 0xFF; u++ {
		d = u << 1
		if d >= 0x100 {
			d = d ^ 0x14D
		}

		xTimesTable[u] = byte(d)
	}
}

func initSBoxTable() {
	P := []int{
		0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC, 0xD, 0xA, 0x9, 0x6,
		0x7, 0x8, 0x2, 0x1,
	}
	Q := []int{
		0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC, 0xF, 0x0, 0x4, 0xD,
		0x7, 0xB, 0x1, 0x8,
	}

	var u, uh1, uh2, ul1, ul2 int

	for u = 0x00; u <= 0xFF; u++ {
		uh1 = P[byte(u>>4)&0xF]
		ul1 = Q[byte(u&0xF)]
		uh2 = Q[byte(uh1&0xC)^byte(int(ul1>>2)&0x3)]
		ul2 = P[byte(int(uh1<<2)&0xC)^byte(ul1&0x3)]
		uh1 = P[byte(uh2&0xC)^byte(int(ul2>>2)&0x3)]
		ul1 = Q[byte(int(uh2<<2)&0xC)^byte(ul2&0x3)]

		sBoxTable[u] = byte((uh1 << 4) ^ ul1)
	}
}

func cTimes(u byte) byte {
	// see page 13, item 5.
	return xTimes(
		xTimes(
			xTimes(
				xTimes(u)^u,
			) ^ u,
		),
	)
}

func dTimesa(a []byte, j int, b []byte) {
	// see page 13.
	var d int = 3 * j // Column delta
	var v byte = xTimes(byte(a[0+d] ^ a[1+d] ^ a[2+d]))
	var w byte = xTimes(v)

	b[0+d] = byte(a[0+d] ^ v)
	b[1+d] = byte(a[1+d] ^ w)
	b[2+d] = byte(a[2+d] ^ v ^ w)
}

func eTimesa(a []byte, j int, b []byte, e bool) {
	// see page 14.
	var d int = 3 * j // Column delta.
	var v byte = byte(a[0+d] ^ a[1+d] ^ a[2+d])

	if e {
		v = cTimes(v)
	} else {
		v = byte(cTimes(v) ^ v)
	}

	b[0+d] = byte(a[0+d] ^ v)
	b[1+d] = byte(a[1+d] ^ v)
	b[2+d] = byte(a[2+d] ^ v)
}

func applyNonLinearLayer(a []byte) []byte {
	// see page 6.
	b := make([]byte, 12)

	for i := 0; i < 12; i++ {
		b[i] = sBox(a[i])
	}

	return b
}

func applyPermutationLayer(a []byte) []byte {
	// see page 7.
	b := make([]byte, 12)

	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			b[i+3*j] = a[i+3*(i^j)]
		}
	}

	return b
}

func applyLinearDiffusionLayer(a []byte) []byte {
	// see page 7.
	b := make([]byte, 12)

	for j := 0; j < 4; j++ {
		dTimesa(a, j, b)
	}

	return b
}

func applyKeyAddition(a, kr []byte) []byte {
	// see page 7.
	b := make([]byte, 12)

	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			b[i+3*j] = byte(a[i+3*j] ^ kr[i+3*j])
		}
	}

	return b
}

func performWhiteningRound(a, k0 []byte) []byte {
	// see page 9.
	return applyKeyAddition(a, k0)
}

func performLastRound(a, kR []byte) []byte {
	// see page 9.
	return applyKeyAddition(
		applyPermutationLayer(
			applyNonLinearLayer(a),
		),
		kR,
	)
}

func performRound(a, kr []byte) []byte {
	// see page 9.
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

func calculateScheduleConstant(s int, keyBits int) []byte {
	// see page 7
	var t int = keyBits / 48
	var q []byte = make([]byte, 3*2*t)

	if s == 0 {
		return q
	}

	// For i = 0
	for j := 0; j < 2*t; j++ {
		q[3*j] = sBox(byte(2*t*(s-1) + j))
		// Note: 2t(s-1) + j is at most 144 for 192 bits cipher key.
	}

	// For i > 0
	for i := 1; i < 3; i++ {
		for j := 0; j < 2*t; j++ {
			q[i+3*j] = 0
		}
	}

	return q
}

func applyConstantAddition(Kr []byte, subkeyRank int, keyBits, t int) []byte {
	// see page 8
	var b []byte = make([]byte, 3*2*t)

	// Do constant addition
	var q []byte = calculateScheduleConstant(subkeyRank, keyBits)
	for i := 0; i < 3; i++ {
		for j := 0; j < 2*t; j++ {
			b[i+3*j] = byte(Kr[i+3*j] ^ q[i+3*j])
		}
	}

	return b
}

func applyCyclicShift(a []byte, t int) []byte {
	// see page 8
	b := make([]byte, 3*2*t)

	for j := 0; j < 2*t; j++ {
		// For i = 0.
		b[3*j] = a[3*j]
		// For i = 1.
		b[1+3*j] = a[1+3*byte((j+1)%(2*t))]

		// For i = 2.
		if j > 0 {
			b[2+3*j] = a[2+3*byte((j-1)%(2*t))]
			// Note that (0 - 1) % 2t would give -1.
		} else {
			b[2] = a[2+3*byte(2*t-1)]
		}
	}

	return b
}

func applyLinearDiffusion(a []byte, t int) []byte {
	// see page 8
	b := make([]byte, 3*2*t)

	for j := 0; j < 2*t; j++ {
		eTimesa(a, j, b, true)
	}

	return b
}

func calculateNextSubkey(Kr []byte, subkeyRank int, keyBits, t int) []byte {
	// see pages 7, 8 and 9.
	return applyLinearDiffusion(
		applyCyclicShift(
			applyConstantAddition(
				Kr,
				subkeyRank,
				keyBits,
				t,
			),
			t,
		),
		t,
	)
}

func selectRoundKey(Kr []byte) []byte {
	// see page 9.
	kr := make([]byte, 12)

	// For i = 0.
	for j := 0; j < 4; j++ {
		kr[3*j] = sBox(Kr[3*j])
	}

	// For i > 0.
	for i := 1; i < 3; i++ {
		for j := 0; j < 4; j++ {
			kr[i+3*j] = Kr[i+3*j]
		}
	}

	return kr
}
