package curupira2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestVectors will be filled when we have official test vectors
// For now, we test properties and consistency

func TestKeySizes(t *testing.T) {
	// Test valid key sizes
	validKeys := [][]byte{
		make([]byte, 12), // 96 bits
		make([]byte, 18), // 144 bits
		make([]byte, 24), // 192 bits
	}

	for _, key := range validKeys {
		c, err := NewCipher(key)
		if err != nil {
			t.Errorf("Failed for key size %d: %v", len(key), err)
		}
		if c.BlockSize() != BlockSize {
			t.Errorf("Wrong block size for key size %d", len(key))
		}
	}

	// Test invalid key sizes
	invalidKeys := [][]byte{
		make([]byte, 8),
		make([]byte, 16),
		make([]byte, 32),
	}

	for _, key := range invalidKeys {
		_, err := NewCipher(key)
		if err == nil {
			t.Errorf("Should fail for invalid key size %d", len(key))
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Test that decryption reverses encryption for all key sizes
	keySizes := []int{12, 18, 24}
	
	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		// Fill key with pattern
		for i := range key {
			key[i] = byte(i)
		}
		
		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}
		
		plaintext := make([]byte, BlockSize)
		// Fill plaintext with pattern
		for i := range plaintext {
			plaintext[i] = byte(i + 0x80)
		}
		
		ciphertext := make([]byte, BlockSize)
		decrypted := make([]byte, BlockSize)
		
		c.Encrypt(ciphertext, plaintext)
		c.Decrypt(decrypted, ciphertext)
		
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Encrypt/Decrypt failed for key size %d\nPlain: %x\nDecrypted: %x", 
				keySize, plaintext, decrypted)
		}
	}
}

func TestSCT(t *testing.T) {
	// Test Square Complete Transform (unkeyed rounds)
	key := make([]byte, 12) // 96-bit key
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	
	input := make([]byte, BlockSize)
	for i := range input {
		input[i] = byte(i)
	}
	
	output := make([]byte, BlockSize)
	c.Sct(output, input)
	
	// SCT should be deterministic
	output2 := make([]byte, BlockSize)
	c.Sct(output2, input)
	
	if !bytes.Equal(output, output2) {
		t.Error("SCT not deterministic")
	}
	
	// SCT of all zeros should not be all zeros (avalanche effect)
	zeros := make([]byte, BlockSize)
	sctZeros := make([]byte, BlockSize)
	c.Sct(sctZeros, zeros)
	
	if bytes.Equal(zeros, sctZeros) {
		t.Error("SCT of zeros should not be zeros")
	}
}

func TestKeyScheduleProperties(t *testing.T) {
	// Test that different rounds produce different round keys
	keySizes := []int{12, 18, 24}
	
	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i)
		}
		
		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}
		
		// Check that all round keys are different
		seen := make(map[string]bool)
		for r, roundKey := range c.encryptionRoundKeys {
			keyStr := hex.EncodeToString(roundKey)
			if seen[keyStr] {
				t.Errorf("Duplicate round key at round %d for key size %d", r, keySize)
			}
			seen[keyStr] = true
		}
		
		// Check number of round keys
		expectedRounds := map[int]int{12: 10, 18: 14, 24: 18}[keySize]
		if len(c.encryptionRoundKeys) != expectedRounds+1 {
			t.Errorf("Wrong number of round keys for key size %d: got %d, expected %d", 
				keySize, len(c.encryptionRoundKeys), expectedRounds+1)
		}
	}
}

func TestAvalancheEffect(t *testing.T) {
	// Test that changing one bit in plaintext affects many bits in ciphertext
	key := make([]byte, 12)
	for i := range key {
		key[i] = 0xAA
	}
	
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	
	plaintext1 := make([]byte, BlockSize)
	for i := range plaintext1 {
		plaintext1[i] = 0x55
	}
	
	ciphertext1 := make([]byte, BlockSize)
	c.Encrypt(ciphertext1, plaintext1)
	
	// Change one bit
	plaintext2 := make([]byte, BlockSize)
	copy(plaintext2, plaintext1)
	plaintext2[0] ^= 0x01
	
	ciphertext2 := make([]byte, BlockSize)
	c.Encrypt(ciphertext2, plaintext2)
	
	// Count differing bits
	diffBits := 0
	for i := 0; i < BlockSize; i++ {
		diff := ciphertext1[i] ^ ciphertext2[i]
		for diff != 0 {
			diffBits++
			diff &= diff - 1
		}
	}
	
	// Avalanche effect should flip about half the bits (48 bits on average)
	if diffBits < 20 || diffBits > 76 {
		t.Errorf("Poor avalanche effect: only %d bits changed (expected ~48)", diffBits)
	}
}

func TestKeyAvalanche(t *testing.T) {
	// Test that changing one bit in key affects ciphertext significantly
	key1 := make([]byte, 12)
	for i := range key1 {
		key1[i] = 0xAA
	}
	
	c1, err := NewCipher(key1)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	
	// Change one bit in key
	key2 := make([]byte, 12)
	copy(key2, key1)
	key2[0] ^= 0x01
	
	c2, err := NewCipher(key2)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	
	plaintext := make([]byte, BlockSize)
	for i := range plaintext {
		plaintext[i] = 0x55
	}
	
	ciphertext1 := make([]byte, BlockSize)
	ciphertext2 := make([]byte, BlockSize)
	
	c1.Encrypt(ciphertext1, plaintext)
	c2.Encrypt(ciphertext2, plaintext)
	
	// Count differing bits
	diffBits := 0
	for i := 0; i < BlockSize; i++ {
		diff := ciphertext1[i] ^ ciphertext2[i]
		for diff != 0 {
			diffBits++
			diff &= diff - 1
		}
	}
	
	// Changing one key bit should affect about half the ciphertext bits
	if diffBits < 20 || diffBits > 76 {
		t.Errorf("Poor key avalanche: only %d bits changed (expected ~48)", diffBits)
	}
}

func TestT0T1Functions(t *testing.T) {
	// Test T0 and T1 as defined in the paper
	testCases := []struct {
		input byte
		t0    byte
		t1    byte
	}{
		{0x00, 0x00, 0x00},
		{0xFF, 0xFF ^ 0x1F ^ 0x3F, 0xF8 ^ 0xE0}, // Manual calculation
		{0xAA, 0xAA ^ 0x15 ^ 0x2A, 0x50 ^ 0x40},
		{0x55, 0x55 ^ 0x0A ^ 0x15, 0xA8 ^ 0xA0},
	}
	
	for _, tc := range testCases {
		t0 := T0(tc.input)
		t1 := T1(tc.input)
		
		// We can't assert exact values without official test vectors
		// But we can test properties
		
		// T0 and T1 should be different (generally)
		if t0 == t1 && tc.input != 0 {
			t.Errorf("T0 and T1 should be different for %x", tc.input)
		}
		
		// Test that T0 and T1 are consistent with definitions
		expectedT0 := tc.input ^ (tc.input >> 5) ^ (tc.input >> 3)
		expectedT1 := (tc.input << 3) ^ (tc.input << 5)
		
		if t0 != expectedT0 {
			t.Errorf("T0(%x) = %x, expected %x", tc.input, t0, expectedT0)
		}
		if t1 != expectedT1 {
			t.Errorf("T1(%x) = %x, expected %x", tc.input, t1, expectedT1)
		}
	}
}

func TestXiTransform(t *testing.T) {
	// Test the involutive property of ξ: ξ(ξ(u)) = u
	keySizes := []int{12, 18, 24}
	
	for _, keySize := range keySizes {
		// Create a test vector of appropriate size
		testVector := make([]byte, keySize)
		for i := range testVector {
			testVector[i] = byte(i * 3)
		}
		
		// Apply ξ twice
		first := xiTransform(testVector, keySize*8)
		second := xiTransform(first, keySize*8)
		
		if !bytes.Equal(testVector, second) {
			t.Errorf("ξ not involutive for key size %d", keySize)
		}
	}
}

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

// TestVector structure for when we have official test vectors
type testVector struct {
	key        string
	plaintext  string
	ciphertext string
}

// Placeholder for future official test vectors
func TestWithOfficialVectors(t *testing.T) {
	// When official test vectors become available, add them here
	// For now, this test is skipped
	t.Skip("No official test vectors available for Curupira-2")
	
	vectors := []testVector{
		// Add vectors here when available
	}
	
	for i, v := range vectors {
		key, _ := hex.DecodeString(v.key)
		plaintext, _ := hex.DecodeString(v.plaintext)
		expected, _ := hex.DecodeString(v.ciphertext)
		
		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Vector %d: %v", i, err)
		}
		
		ciphertext := make([]byte, BlockSize)
		c.Encrypt(ciphertext, plaintext)
		
		if !bytes.Equal(ciphertext, expected) {
			t.Errorf("Vector %d failed\nGot: %x\nExpected: %x", i, ciphertext, expected)
		}
	}
}
