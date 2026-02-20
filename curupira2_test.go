package curupira2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

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

// TestRoundKeys verifica propriedades das chaves de rodada
func TestRoundKeys(t *testing.T) {
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
		
		curupiraCipher, ok := c.(*curupira2Cipher)
		if !ok {
			t.Skip("Não foi possível acessar as chaves de rodada internas")
			return
		}
		
		// Verificar se todas as chaves de rodada são diferentes
		seen := make(map[string]bool)
		for r, roundKey := range curupiraCipher.encryptionRoundKeys {
			keyStr := hex.EncodeToString(roundKey)
			if seen[keyStr] {
				t.Errorf("Chave de rodada duplicada na rodada %d para chave de %d bytes", r, keySize)
			}
			seen[keyStr] = true
		}
		
		// Verificar número de rodadas
		expectedRounds := map[int]int{12: 10, 18: 14, 24: 18}[keySize]
		if len(curupiraCipher.encryptionRoundKeys) != expectedRounds+1 {
			t.Errorf("Número incorreto de chaves de rodada: %d, esperado %d", 
				len(curupiraCipher.encryptionRoundKeys), expectedRounds+1)
		}
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
	} else {
		t.Logf("Efeito avalanche: %d bits mudaram", diffBits)
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
	} else {
		t.Logf("Efeito avalanche na chave: %d bits mudaram", diffBits)
	}
}

// TestT0T1Functions testa as funções T0 e T1
func TestT0T1Functions(t *testing.T) {
	testCases := []struct {
		input    byte
		expected byte
	}{
		{0x00, 0x00},
		{0xFF, 0xFF},
		{0xAA, 0xAA},
		{0x55, 0x55},
	}
	
	// Testar T0
	for _, tc := range testCases {
		result := T0(tc.input)
		expected := tc.input ^ (tc.input >> 5) ^ (tc.input >> 3)
		if result != expected {
			t.Errorf("T0(0x%02X) = 0x%02X, esperado 0x%02X", tc.input, result, expected)
		}
	}
	
	// Testar T1
	for _, tc := range testCases {
		result := T1(tc.input)
		val := (uint16(tc.input) << 3) ^ (uint16(tc.input) << 5)
		expected := byte(val & 0xFF)
		if result != expected {
			t.Errorf("T1(0x%02X) = 0x%02X, esperado 0x%02X", tc.input, result, expected)
		}
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
		
		curupiraCipher, ok := c.(*curupira2Cipher)
		if !ok {
			t.Skip("Não foi possível acessar as chaves de rodada internas")
			return
		}
		
		// Verificar se as chaves de rodada são diferentes entre si
		for i := 0; i < len(curupiraCipher.encryptionRoundKeys)-1; i++ {
			if bytes.Equal(curupiraCipher.encryptionRoundKeys[i], curupiraCipher.encryptionRoundKeys[i+1]) {
				t.Errorf("Chaves de rodada %d e %d são iguais", i, i+1)
			}
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
	
	aead.Encrypt(ciphertext, plaintext)
	
	decrypted := make([]byte, len(plaintext))
	aead.Decrypt(decrypted, ciphertext)
	
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
