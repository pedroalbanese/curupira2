package curupira2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Vetores de teste oficiais da implementação C
var testVectors = []struct {
	name      string
	keyHex    string
	plainHex  string
	cipherHex string // Resultado esperado em formato C (row-major)
}{
	// Vetores para chave de 12 bytes (96 bits)
	{
		name:      "Chave 12 bytes zeros, plain zeros",
		keyHex:    "000000000000000000000000",
		plainHex:  "000000000000000000000000",
		cipherHex: "e89cf298824a80eaf1f9d894",
	},
	{
		name:      "Chave 12 bytes zeros, plain 1 na primeira posição",
		keyHex:    "000000000000000000000000",
		plainHex:  "010000000000000000000000",
		cipherHex: "b9f0993d580fbb2d27aed365",
	},
	{
		name:      "Chave 12 bytes não zero (0-11), plain 0x80-0x8b",
		keyHex:    "000102030405060708090a0b",
		plainHex:  "808182838485868788898a8b",
		cipherHex: "b75001e7d7380fa4c4343d1c",
	},

	// Vetores para chave de 18 bytes (144 bits)
	{
		name:      "Chave 18 bytes zeros, plain zeros",
		keyHex:    "000000000000000000000000000000000000",
		plainHex:  "000000000000000000000000",
		cipherHex: "d929b6aa7d50332a2c6cb543",
	},
	{
		name:      "Chave 18 bytes zeros, plain 1 na primeira posição",
		keyHex:    "000000000000000000000000000000000000",
		plainHex:  "010000000000000000000000",
		cipherHex: "a8dfe9e5ae518d18647ca9dc",
	},
	{
		name:      "Chave 18 bytes não zero (0-17), plain 0x80-0x8b",
		keyHex:    "000102030405060708090a0b0c0d0e0f1011",
		plainHex:  "808182838485868788898a8b",
		cipherHex: "6527e2104bbc4a5dd069d0b4",
	},

	// Vetores para chave de 24 bytes (192 bits)
	{
		name:      "Chave 24 bytes zeros, plain zeros",
		keyHex:    "000000000000000000000000000000000000000000000000",
		plainHex:  "000000000000000000000000",
		cipherHex: "9d90a47828630c0bc98b0172",
	},
	{
		name:      "Chave 24 bytes zeros, plain 1 na primeira posição",
		keyHex:    "000000000000000000000000000000000000000000000000",
		plainHex:  "010000000000000000000000",
		cipherHex: "7bfceda2093bf12498226c82",
	},
	{
		name:      "Chave 24 bytes não zero (0-23), plain 0x80-0x8b",
		keyHex:    "000102030405060708090a0b0c0d0e0f1011121314151617",
		plainHex:  "808182838485868788898a8b",
		cipherHex: "9580d187ec496587f3df0ce6",
	},
}

// TestOfficialVectors testa a implementação contra os vetores oficiais do C
func TestOfficialVectors(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Decodificar chave e plaintext
			key, err := hex.DecodeString(tv.keyHex)
			if err != nil {
				t.Fatalf("Erro ao decodificar chave: %v", err)
			}

			plain, err := hex.DecodeString(tv.plainHex)
			if err != nil {
				t.Fatalf("Erro ao decodificar plaintext: %v", err)
			}

			// Criar cipher
			c, err := NewCipher(key)
			if err != nil {
				t.Fatalf("Erro ao criar cipher: %v", err)
			}

			// Verificar número de rounds
			expectedRounds := 10
			if len(key) == 18 {
				expectedRounds = 12
			} else if len(key) == 24 {
				expectedRounds = 14
			}
			if int(c.numberOfRounds) != expectedRounds {
				t.Errorf("Número de rounds incorreto: %d, esperado %d", c.numberOfRounds, expectedRounds)
			}

			// Cifrar
			ciphertext := make([]byte, BlockSize)
			c.Encrypt(ciphertext, plain)

			// Comparar resultado
			cipherHex := hex.EncodeToString(ciphertext)
			if cipherHex != tv.cipherHex {
				t.Errorf("Ciphertext incorreto\nObtido:  %s\nEsperado: %s", cipherHex, tv.cipherHex)

				// Mostrar diferença byte a byte
				expected, _ := hex.DecodeString(tv.cipherHex)
				t.Log("Diferença byte a byte:")
				for i := 0; i < BlockSize; i++ {
					if ciphertext[i] != expected[i] {
						t.Logf("  [%d]: %02x (obtido) vs %02x (esperado)", i, ciphertext[i], expected[i])
					}
				}
			}

			// Testar decifragem
			decrypted := make([]byte, BlockSize)
			c.Decrypt(decrypted, ciphertext)

			if !bytes.Equal(decrypted, plain) {
				t.Errorf("Decifragem falhou\nObtido:  %x\nEsperado: %x", decrypted, plain)
			}
		})
	}
}

// TestKeySizes verifica se apenas tamanhos de chave válidos são aceitos
func TestKeySizes(t *testing.T) {
	// Tamanhos válidos
	validKeys := [][]byte{
		make([]byte, 12), // 96 bits
		make([]byte, 18), // 144 bits
		make([]byte, 24), // 192 bits
	}

	for _, key := range validKeys {
		c, err := NewCipher(key)
		if err != nil {
			t.Errorf("Falhou para chave de %d bytes: %v", len(key), err)
		}
		if c.BlockSize() != BlockSize {
			t.Errorf("BlockSize incorreto para chave de %d bytes", len(key))
		}
	}

	// Tamanhos inválidos
	invalidKeys := [][]byte{
		make([]byte, 8),
		make([]byte, 16),
		make([]byte, 32),
	}

	for _, key := range invalidKeys {
		_, err := NewCipher(key)
		if err == nil {
			t.Errorf("Deveria falhar para chave inválida de %d bytes", len(key))
		}
	}
}

// TestEncryptDecrypt verifica se decifrar após cifrar retorna o original
func TestEncryptDecrypt(t *testing.T) {
	keySizes := []int{12, 18, 24}

	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i)
		}

		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Falhou ao criar cifrador: %v", err)
		}

		plaintext := make([]byte, BlockSize)
		for i := range plaintext {
			plaintext[i] = byte(i + 0x80)
		}

		ciphertext := make([]byte, BlockSize)
		decrypted := make([]byte, BlockSize)

		c.Encrypt(ciphertext, plaintext)
		c.Decrypt(decrypted, ciphertext)

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Cifrar/Decifrar falhou para chave de %d bytes\nPlain: %x\nDecrypted: %x",
				keySize, plaintext, decrypted)
		}
	}
}

// TestSCT verifica propriedades da transformada square-complete
func TestSCT(t *testing.T) {
	key := make([]byte, 12)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	input := make([]byte, BlockSize)
	for i := range input {
		input[i] = byte(i)
	}

	output := make([]byte, BlockSize)
	c.Sct(output, input)

	// SCT deve ser determinístico
	output2 := make([]byte, BlockSize)
	c.Sct(output2, input)

	if !bytes.Equal(output, output2) {
		t.Error("SCT não é determinístico")
	}

	// SCT de zeros não deve ser zeros
	zeros := make([]byte, BlockSize)
	sctZeros := make([]byte, BlockSize)
	c.Sct(sctZeros, zeros)

	if bytes.Equal(zeros, sctZeros) {
		t.Error("SCT de zeros não deveria ser zeros")
	}
}

// TestAvalancheEffect testa o efeito avalanche no plaintext
func TestAvalancheEffect(t *testing.T) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = 0xAA
	}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	plaintext1 := make([]byte, BlockSize)
	for i := range plaintext1 {
		plaintext1[i] = 0x55
	}

	ciphertext1 := make([]byte, BlockSize)
	c.Encrypt(ciphertext1, plaintext1)

	// Mudar um bit no plaintext
	plaintext2 := make([]byte, BlockSize)
	copy(plaintext2, plaintext1)
	plaintext2[0] ^= 0x01

	ciphertext2 := make([]byte, BlockSize)
	c.Encrypt(ciphertext2, plaintext2)

	// Contar bits diferentes
	diffBits := 0
	for i := 0; i < BlockSize; i++ {
		diff := ciphertext1[i] ^ ciphertext2[i]
		for diff != 0 {
			diffBits++
			diff &= diff - 1
		}
	}

	if diffBits < 20 || diffBits > 76 {
		t.Errorf("Efeito avalanche fraco: apenas %d bits mudaram (esperado ~48)", diffBits)
	}
}

// TestKeyAvalanche testa o efeito avalanche na chave
func TestKeyAvalanche(t *testing.T) {
	key1 := make([]byte, 12)
	for i := range key1 {
		key1[i] = 0xAA
	}

	c1, err := NewCipher(key1)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	key2 := make([]byte, 12)
	copy(key2, key1)
	key2[0] ^= 0x01

	c2, err := NewCipher(key2)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	plaintext := make([]byte, BlockSize)
	for i := range plaintext {
		plaintext[i] = 0x55
	}

	ciphertext1 := make([]byte, BlockSize)
	ciphertext2 := make([]byte, BlockSize)

	c1.Encrypt(ciphertext1, plaintext)
	c2.Encrypt(ciphertext2, plaintext)

	diffBits := 0
	for i := 0; i < BlockSize; i++ {
		diff := ciphertext1[i] ^ ciphertext2[i]
		for diff != 0 {
			diffBits++
			diff &= diff - 1
		}
	}

	if diffBits < 20 || diffBits > 76 {
		t.Errorf("Efeito avalanche na chave fraco: apenas %d bits mudaram (esperado ~48)", diffBits)
	}
}

// TestKeySchedule verifica se o key schedule produz resultados diferentes para cada rodada
func TestKeySchedule(t *testing.T) {
	keySizes := []int{12, 18, 24}

	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i)
		}

		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Falhou ao criar cifrador: %v", err)
		}

		// Verificar se as chaves de encriptação e decriptação são diferentes
		if bytes.Equal(c.keyEnc, c.keyDec) {
			t.Errorf("Chaves de encriptação e decriptação são iguais para tamanho %d", keySize)
		}

		// Verificar se a chave de decriptação não é igual à chave original
		if bytes.Equal(key, c.keyDec) {
			t.Errorf("Chave de decriptação é igual à chave original para tamanho %d", keySize)
		}
	}
}

// TestLetterSoupBasic testa o funcionamento básico do LetterSoup
func TestLetterSoupBasic(t *testing.T) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	aead := NewLetterSoup(c)

	iv := []byte("123456789012")
	aead.SetIV(iv)

	authData := []byte("dados autenticados")
	aead.Update(authData)

	plaintext := []byte("mensagem secreta")
	ciphertext := make([]byte, len(plaintext))

	aead.Encrypt(plaintext, ciphertext)

	decrypted := make([]byte, len(plaintext))
	aead.Decrypt(ciphertext, decrypted)

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("LetterSoup: decifragem falhou\nOriginal: %x\nDecifrado: %x", plaintext, decrypted)
	}

	tag := aead.GetTag(nil, 64)
	if len(tag) != 8 {
		t.Errorf("Tag com tamanho incorreto: %d bytes", len(tag))
	}
}

// TestMarvinBasic testa o funcionamento básico do Marvin
func TestMarvinBasic(t *testing.T) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	mac := NewMarvin(c, nil, false)

	data := []byte("dados para autenticar")
	mac.Update(data)

	tag := mac.GetTag(nil, 64)
	if len(tag) != 8 {
		t.Errorf("Tag com tamanho incorreto: %d bytes", len(tag))
	}

	mac2 := NewMarvin(c, nil, false)
	mac2.Update(data)
	tag2 := mac2.GetTag(nil, 64)

	if !bytes.Equal(tag, tag2) {
		t.Errorf("MAC não é determinístico")
	}
}

// TestMarvinWithR testa o Marvin com R fornecido
func TestMarvinWithR(t *testing.T) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Falhou ao criar cifrador: %v", err)
	}

	R := make([]byte, BlockSize)
	for i := range R {
		R[i] = byte(i + 0x50)
	}

	mac := NewMarvin(c, R, false)

	data := []byte("dados para autenticar")
	mac.Update(data)

	tag := mac.GetTag(nil, 64)
	if len(tag) != 8 {
		t.Errorf("Tag com tamanho incorreto: %d bytes", len(tag))
	}
}

// TestLetterSoupWithDifferentKeys testa LetterSoup com diferentes tamanhos de chave
func TestLetterSoupWithDifferentKeys(t *testing.T) {
	keySizes := []int{12, 18, 24}

	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i)
		}

		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Falhou ao criar cifrador para chave %d: %v", keySize, err)
		}

		aead := NewLetterSoup(c)

		iv := make([]byte, 12)
		for i := range iv {
			iv[i] = byte(i + 0x20)
		}
		aead.SetIV(iv)

		authData := []byte("dados autenticados")
		aead.Update(authData)

		plaintext := []byte("mensagem secreta para teste")
		ciphertext := make([]byte, len(plaintext))

		aead.Encrypt(plaintext, ciphertext)

		decrypted := make([]byte, len(plaintext))
		aead.Decrypt(ciphertext, decrypted)

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("LetterSoup com chave %d: decifragem falhou", keySize)
		}
	}
}

// BenchmarkEncrypt mede o desempenho da cifragem
func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, _ := NewCipher(key)
	plaintext := make([]byte, BlockSize)
	ciphertext := make([]byte, BlockSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(ciphertext, plaintext)
	}
}

// BenchmarkDecrypt mede o desempenho da decifragem
func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, _ := NewCipher(key)
	plaintext := make([]byte, BlockSize)
	ciphertext := make([]byte, BlockSize)
	c.Encrypt(ciphertext, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(plaintext, ciphertext)
	}
}

// BenchmarkKeySchedule mede o desempenho da expansão de chave
func BenchmarkKeySchedule(b *testing.B) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCipher(key)
	}
}

// BenchmarkLetterSoupEncrypt mede o desempenho do LetterSoup
func BenchmarkLetterSoupEncrypt(b *testing.B) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, _ := NewCipher(key)
	aead := NewLetterSoup(c)

	iv := []byte("123456789012")
	aead.SetIV(iv)

	authData := []byte("dados autenticados")
	aead.Update(authData)

	plaintext := make([]byte, 1024) // 1KB
	ciphertext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Encrypt(plaintext, ciphertext)
	}
}

// BenchmarkMarvinUpdate mede o desempenho do Marvin
func BenchmarkMarvinUpdate(b *testing.B) {
	key := make([]byte, 12)
	for i := range key {
		key[i] = byte(i)
	}

	c, _ := NewCipher(key)
	mac := NewMarvin(c, nil, false)

	data := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac.Update(data)
	}
}
