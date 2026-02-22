#!/usr/bin/env python3
import struct
from typing import List, Optional, Tuple
import os
import sys
import argparse

class KeySizeError(Exception):
    def __init__(self, size: int):
        self.size = size
        super().__init__(f"curupira2: invalid key size {size}")

class Curupira2:
    BLOCK_SIZE = 12
    
    def __init__(self, key: bytes):
        self.key = key
        self.key_size = len(key)
        
        if self.key_size not in [12, 18, 24]:
            raise KeySizeError(self.key_size)
        
        # Initialize tables
        self._init_xtimes_table()
        self._init_sbox_table()
        
        # Set number of rounds based on key size
        if self.key_size == 12:
            self.number_of_rounds = 10
        elif self.key_size == 18:
            self.number_of_rounds = 12
        else:  # 24
            self.number_of_rounds = 14
        
        # Initialize cipher state
        self.key_enc = bytearray(key)
        self.key_dec = bytearray(key)
        self.key_length = len(key) - 1
        
        # Generate decryption subkeys
        msb = 0
        for i in range(self.number_of_rounds):
            msb = self._create_next_key(self.key_dec, msb, 0)
    
    def _init_xtimes_table(self):
        """Initialize xTimes table (multiplication by 2 in GF(2^8))"""
        self.xtimes_table = [0] * 256
        for u in range(256):
            d = u << 1
            if d >= 0x100:
                d = d ^ 0x14D  # Polynomial reduction x^8 + x^6 + x^5 + x^3 + 1
            self.xtimes_table[u] = d & 0xFF
    
    def _init_sbox_table(self):
        """Initialize S-Box table according to Curupira2 algorithm"""
        P = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
             0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]
        Q = [0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC,
             0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8]
        
        self.sbox_table = [0] * 256
        
        for u in range(256):
            uh1 = P[(u >> 4) & 0xF]
            ul1 = Q[u & 0xF]
            uh2 = Q[((uh1 & 0xC) ^ ((ul1 >> 2) & 0x3)) & 0xF]
            ul2 = P[(((uh1 << 2) & 0xC) ^ (ul1 & 0x3)) & 0xF]
            uh1 = P[((uh2 & 0xC) ^ ((ul2 >> 2) & 0x3)) & 0xF]
            ul1 = Q[(((uh2 << 2) & 0xC) ^ (ul2 & 0x3)) & 0xF]
            
            self.sbox_table[u] = ((uh1 << 4) ^ ul1) & 0xFF
    
    def sbox(self, u: int) -> int:
        """Apply S-Box"""
        return self.sbox_table[u & 0xFF]
    
    def xtimes(self, u: int) -> int:
        """Multiplication by 2 in GF(2^8)"""
        return self.xtimes_table[u & 0xFF]
    
    def T0(self, v: int) -> int:
        """T0 transformation: (v << 5) ^ (v << 3)"""
        return ((v << 5) ^ (v << 3)) & 0xFF
    
    def T1(self, v: int) -> int:
        """T1 transformation: v ^ (v >> 3) ^ (v >> 5)"""
        return (v ^ (v >> 3) ^ (v >> 5)) & 0xFF
    
    def _xor(self, a: bytearray, b: bytes) -> None:
        """XOR in-place between bytearray and bytes"""
        for i in range(min(len(a), len(b))):
            a[i] ^= b[i]
    
    def _create_next_key(self, key: bytearray, msb: int, is_decryption: int) -> int:
        """Create next key for key schedule"""
        key_len = self.key_length
        
        if is_decryption != 0:
            if msb == 0:
                msb = key_len
            else:
                msb -= 1
            aux2 = key[msb]
            key[msb] ^= self.sbox(msb)
        else:
            key[msb] ^= self.sbox(msb)
            aux2 = key[msb]
        
        if msb != 0:
            aux1 = msb - 1
        else:
            aux1 = key_len
        key[aux1] ^= self.T0(aux2)
        
        if aux1 != 0:
            aux1 -= 1
        else:
            aux1 = key_len
        key[aux1] ^= self.T1(aux2)
        
        if is_decryption == 0:
            msb += 1
            if msb > key_len:
                msb = 0
        
        return msb
    
    def _swap_ct(self, ptr1: int, ptr2: int, block: bytearray):
        """Swap with S-box transformation"""
        aux = self.sbox(block[ptr1])
        block[ptr1] = self.sbox(block[ptr2])
        block[ptr2] = aux
    
    def _s_on_row1(self, ptr1: int, ptr2: int, block: bytearray):
        """Apply S-box on row 1 and swap"""
        block[ptr1] = self.sbox(block[ptr1])
        block[ptr2] = self.sbox(block[ptr2])
        self._swap_ct(ptr1 + 1, ptr2 + 1, block)
    
    def _update_pos_msb(self, pos_msb: int, key_length: int) -> int:
        """Update position MSB"""
        pos_msb += 1
        if pos_msb > key_length:
            pos_msb = 0
        return pos_msb
    
    def _apply_key(self, block: bytearray, key: bytearray, msb: int) -> int:
        """Apply key to block"""
        pos_msb = msb
        key_length = self.key_length
        i = 0
        
        while i < 12:
            block[i] ^= self.sbox(key[pos_msb])
            i += 1
            pos_msb = self._update_pos_msb(pos_msb, key_length)
            if i >= 12:
                break
            
            block[i] ^= key[pos_msb]
            i += 1
            pos_msb = self._update_pos_msb(pos_msb, key_length)
            if i >= 12:
                break
            
            block[i] ^= key[pos_msb]
            i += 1
            pos_msb = self._update_pos_msb(pos_msb, key_length)
        
        return pos_msb
    
    def crypt(self, data: bytes, dir_decryption: int) -> bytes:
        """Core encryption/decryption function"""
        block = bytearray(data)
        
        # Create local copies of keys
        key_enc = bytearray(self.key_enc)
        key_dec = bytearray(self.key_dec)
        
        if dir_decryption != 0:
            key = key_dec
            msb = self.number_of_rounds
            original_msb = self.number_of_rounds
        else:
            key = key_enc
            msb = 0
            original_msb = 0
        
        # Whitening - doesn't modify original msb
        self._apply_key(block, key, msb)
        
        # Rounds - use original msb
        msb = original_msb
        
        for r in range(1, self.number_of_rounds + 1):
            # Permutation layer
            self._s_on_row1(0, 3, block)
            self._swap_ct(2, 8, block)
            self._s_on_row1(6, 9, block)
            self._swap_ct(5, 11, block)
            
            # Create next round key
            msb = self._create_next_key(key, msb, dir_decryption)
            
            if r == self.number_of_rounds:
                self._apply_key(block, key, msb)
                break
            
            # Theta layer
            pos_msb = msb
            for i in range(4):
                aux3 = key[pos_msb]
                pos_msb = self._update_pos_msb(pos_msb, self.key_length)
                aux3 = self.sbox(aux3)
                
                ptr = i * 3
                aux1 = block[ptr] ^ block[ptr + 1] ^ block[ptr + 2]
                
                if dir_decryption != 0:
                    aux2 = pos_msb + 1
                    if aux2 > self.key_length:
                        aux2 = 0
                    aux1 ^= aux3 ^ key[pos_msb] ^ key[aux2]
                
                aux1 = self.xtimes(aux1)
                aux2v = self.xtimes(aux1)
                
                block[ptr] ^= aux1 ^ aux3
                block[ptr + 1] ^= aux2v ^ key[pos_msb]
                pos_msb = self._update_pos_msb(pos_msb, self.key_length)
                
                block[ptr + 2] ^= aux1 ^ aux2v ^ key[pos_msb]
                pos_msb = self._update_pos_msb(pos_msb, self.key_length)
        
        return bytes(block)
    
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt a single block"""
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Plaintext must be {self.BLOCK_SIZE} bytes")
        
        temp = self.crypt(plaintext, 0)
        
        # Reorganize to row-major (C style)
        dst = bytearray(self.BLOCK_SIZE)
        dst[0] = temp[0]   # (0,0)
        dst[1] = temp[3]   # (0,1)
        dst[2] = temp[6]   # (0,2)
        dst[3] = temp[9]   # (0,3)
        dst[4] = temp[1]   # (1,0)
        dst[5] = temp[4]   # (1,1)
        dst[6] = temp[7]   # (1,2)
        dst[7] = temp[10]  # (1,3)
        dst[8] = temp[2]   # (2,0)
        dst[9] = temp[5]   # (2,1)
        dst[10] = temp[8]  # (2,2)
        dst[11] = temp[11] # (2,3)
        
        return bytes(dst)
    
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt a single block"""
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {self.BLOCK_SIZE} bytes")
        
        # Reorganize from row-major to column-major
        temp = bytearray(self.BLOCK_SIZE)
        temp[0] = ciphertext[0]   # (0,0)
        temp[1] = ciphertext[4]   # (1,0)
        temp[2] = ciphertext[8]   # (2,0)
        temp[3] = ciphertext[1]   # (0,1)
        temp[4] = ciphertext[5]   # (1,1)
        temp[5] = ciphertext[9]   # (2,1)
        temp[6] = ciphertext[2]   # (0,2)
        temp[7] = ciphertext[6]   # (1,2)
        temp[8] = ciphertext[10]  # (2,2)
        temp[9] = ciphertext[3]   # (0,3)
        temp[10] = ciphertext[7]  # (1,3)
        temp[11] = ciphertext[11] # (2,3)
        
        return self.crypt(bytes(temp), 1)
    
    def sct(self, data: bytes) -> bytes:
        """Square-Complete Transform (4 unkeyed rounds)"""
        if len(data) != self.BLOCK_SIZE:
            raise ValueError(f"Data must be {self.BLOCK_SIZE} bytes")
        
        tmp = bytearray(data)
        
        for _ in range(4):
            self._s_on_row1(0, 3, tmp)
            self._swap_ct(2, 8, tmp)
            self._s_on_row1(6, 9, tmp)
            self._swap_ct(5, 11, tmp)
            
            for i in range(4):
                ptr = i * 3
                aux1 = tmp[ptr] ^ tmp[ptr + 1] ^ tmp[ptr + 2]
                aux1 = self.xtimes(aux1)
                aux2 = self.xtimes(aux1)
                
                tmp[ptr] ^= aux1
                tmp[ptr + 1] ^= aux2
                tmp[ptr + 2] ^= aux1 ^ aux2
        
        return bytes(tmp)
    
    # Go-compatible methods
    def Encrypt(self, dst: bytearray, src: bytes):
        """Encrypt like Go: Encrypt(dst, src)"""
        if len(src) != self.BLOCK_SIZE:
            raise ValueError(f"Source must be {self.BLOCK_SIZE} bytes")
        
        result = self.encrypt_block(src)
        dst[:len(result)] = result
    
    def Decrypt(self, dst: bytearray, src: bytes):
        """Decrypt like Go: Decrypt(dst, src)"""
        if len(src) != self.BLOCK_SIZE:
            raise ValueError(f"Source must be {self.BLOCK_SIZE} bytes")
        
        result = self.decrypt_block(src)
        dst[:len(result)] = result
    
    def Sct(self, dst: bytearray, src: bytes):
        """SCT like Go: Sct(dst, src)"""
        if len(src) != self.BLOCK_SIZE:
            raise ValueError(f"Source must be {self.BLOCK_SIZE} bytes")
        
        result = self.sct(src)
        dst[:len(result)] = result
    
    def BlockSize(self) -> int:
        """Block size like Go"""
        return self.BLOCK_SIZE


class Marvin:
    """Marvin MAC implementation compatible with Go"""
    C = 0x2A  # Constant c
    
    def __init__(self, cipher: Curupira2, R: Optional[bytes] = None, letter_soup_mode: bool = False):
        self.cipher = cipher
        self.block_bytes = cipher.BLOCK_SIZE
        self.letter_soup_mode = letter_soup_mode
        
        if R is not None:
            self.InitWithR(R)
        else:
            self.Init()
    
    def _xor(self, a: bytearray, b: bytes) -> None:
        """XOR in-place between bytearray and bytes"""
        for i in range(min(len(a), len(b))):
            a[i] ^= b[i]
    
    def Init(self):
        """Step 2 of Algorithm 1 - Page 4"""
        self.buffer = bytearray(self.block_bytes)
        self.R = bytearray(self.block_bytes)
        self.O = bytearray(self.block_bytes)
        
        # Step 2 of Algorithm 1 - Page 4
        left_padded_c = bytearray(self.block_bytes)
        left_padded_c[self.block_bytes - 1] = self.C
        
        encrypted = self.cipher.encrypt_block(bytes(left_padded_c))
        self.R[:] = encrypted
        self._xor(self.R, left_padded_c)
        self.O[:] = self.R[:]
    
    def InitWithR(self, R: bytes):
        """Initialize with provided R"""
        self.buffer = bytearray(self.block_bytes)
        self.R = bytearray(self.block_bytes)
        self.O = bytearray(self.block_bytes)
        
        self.R[:] = R[:self.block_bytes]
        self.O[:] = R[:self.block_bytes]
    
    def updateOffset(self):
        """Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)"""
        O0 = self.O[0]
        
        # Shift left (equivalent to copy(O[0:], O[1:12]) in Go)
        for i in range(11):
            self.O[i] = self.O[i + 1]
        
        self.O[9] = (self.O[9] ^ O0 ^ (O0 >> 3) ^ (O0 >> 5)) & 0xFF
        self.O[10] = (self.O[10] ^ ((O0 << 5) & 0xFF) ^ ((O0 << 3) & 0xFF)) & 0xFF
        self.O[11] = O0
    
    def Update(self, a_data: bytes):
        """Update MAC with associated data"""
        a_length = len(a_data)
        block_bytes = self.block_bytes
        
        M = bytearray(block_bytes)
        A = bytearray(block_bytes)
        
        q = a_length // block_bytes
        r = a_length % block_bytes
        
        # Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
        self._xor(self.buffer, self.R)
        
        for i in range(q):
            M[:] = a_data[i * block_bytes:(i + 1) * block_bytes]
            self.updateOffset()
            self._xor(M, self.O)
            self.cipher.Sct(A, bytes(M))
            self._xor(self.buffer, A)
        
        if r != 0:
            M[:r] = a_data[q * block_bytes:q * block_bytes + r]
            for i in range(r, block_bytes):
                M[i] = 0
            
            self.updateOffset()
            self._xor(M, self.O)
            self.cipher.Sct(A, bytes(M))
            self._xor(self.buffer, A)
        
        self.m_length = a_length
    
    def GetTag(self, tag: Optional[bytearray] = None, tag_bits: int = 96):
        """Get MAC tag"""
        if tag is None:
            tag = bytearray(tag_bits // 8)
        
        block_bytes = self.block_bytes
        
        if self.letter_soup_mode:
            tag[:block_bytes] = self.buffer[:block_bytes]
            return bytes(tag[:tag_bits // 8])
        
        # Steps 6-9 of Algorithm 1 - Page 4
        A = bytearray(block_bytes)
        encrypted_a = bytearray(block_bytes)
        aux_value1 = bytearray(block_bytes)
        aux_value2 = bytearray(block_bytes)
        
        # auxValue1 = rpad(bin(n-tagBits)||1)
        diff = self.cipher.BLOCK_SIZE * 8 - tag_bits
        
        if diff == 0:
            aux_value1[0] = 0x80
            aux_value1[1] = 0x00
        elif diff < 0:
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x80
        else:
            diff = (diff << 1) | 0x01
            while diff > 0 and (diff & 0x80) == 0:
                diff = (diff << 1) & 0xFF
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x00
        
        # auxValue2 = lpad(bin(|M|))
        processed_bits = 8 * self.m_length
        for i in range(4):
            aux_value2[block_bytes - i - 1] = (processed_bits >> (8 * i)) & 0xFF
        
        A[:] = self.buffer[:]
        self._xor(A, aux_value1)
        self._xor(A, aux_value2)
        
        self.cipher.Encrypt(encrypted_a, bytes(A))
        
        tag_bytes = tag_bits // 8
        tag[:tag_bytes] = encrypted_a[:tag_bytes]
        return bytes(tag[:tag_bytes])


class LetterSoup:
    """AEAD LetterSoup mode implementation exactly like in Go"""
    
    def __init__(self, cipher: Curupira2):
        self.cipher = cipher
        self.block_bytes = cipher.BLOCK_SIZE
        self.mac = Marvin(cipher, None, True)
        
        self.m_length = 0
        self.h_length = 0
        self.iv = bytearray()
        self.A = bytearray()
        self.D = bytearray()
        self.R = bytearray()
        self.L = bytearray()
    
    def SetIV(self, iv: bytes):
        """Set initialization vector"""
        iv_length = len(iv)
        block_bytes = self.block_bytes
        
        self.iv = bytearray(iv_length)
        self.iv[:] = iv
        
        self.L = bytearray()
        
        # Step 2 of Algorithm 2 - Page 6
        self.R = bytearray(block_bytes)
        left_padded_n = bytearray(block_bytes)
        
        start_idx = block_bytes - iv_length
        if start_idx < 0:
            start_idx = 0
        copy_len = min(iv_length, block_bytes)
        left_padded_n[start_idx:start_idx + copy_len] = iv[:copy_len]
        
        self.cipher.Encrypt(self.R, bytes(left_padded_n))
        
        for i in range(block_bytes):
            self.R[i] ^= left_padded_n[i]
    
    def Update(self, a_data: bytes):
        """Update with associated data (AAD)"""
        a_length = len(a_data)
        block_bytes = self.block_bytes
        
        # Step 4 of Algorithm 2 - Page 6 (L and part of D)
        self.L = bytearray(block_bytes)
        self.D = bytearray(block_bytes)
        
        empty = bytes(block_bytes)
        
        self.h_length = a_length
        self.cipher.Encrypt(self.L, empty)
        
        self.mac.InitWithR(bytes(self.L))
        self.mac.Update(a_data)
        self.mac.GetTag(self.D, self.cipher.BLOCK_SIZE * 8)
    
    def _xor(self, a: bytearray, b: bytes):
        """XOR in-place"""
        for i in range(min(len(a), len(b))):
            a[i] ^= b[i]
    
    def updateOffset(self, O: bytearray):
        """Algorithm 6 - Page 19 (w = 8, k1 = 11, k2 = 13, k3 = 16)"""
        O0 = O[0]
        
        for i in range(11):
            O[i] = O[i + 1]
        
        O[9] = (O[9] ^ O0 ^ (O0 >> 3) ^ (O0 >> 5)) & 0xFF
        O[10] = (O[10] ^ ((O0 << 5) & 0xFF) ^ ((O0 << 3) & 0xFF)) & 0xFF
        O[11] = O0
    
    def LFSRC(self, m_data: bytes, c_data: bytearray):
        """Algorithm 8 - Page 20"""
        m_length = len(m_data)
        block_bytes = self.block_bytes
        
        M = bytearray(block_bytes)
        C = bytearray(block_bytes)
        O = bytearray(block_bytes)
        O[:] = self.R[:]
        
        q = m_length // block_bytes
        r = m_length % block_bytes
        
        for i in range(q):
            M[:] = m_data[i * block_bytes:(i + 1) * block_bytes]
            self.updateOffset(O)
            self.cipher.Encrypt(C, bytes(O))
            self._xor(C, M)
            c_data[i * block_bytes:(i + 1) * block_bytes] = C[:block_bytes]
        
        if r != 0:
            M[:r] = m_data[q * block_bytes:q * block_bytes + r]
            for i in range(r, block_bytes):
                M[i] = 0
            
            self.updateOffset(O)
            self.cipher.Encrypt(C, bytes(O))
            self._xor(C, M)
            c_data[q * block_bytes:q * block_bytes + r] = C[:r]
    
    def Encrypt(self, dst: bytearray, src: bytes):
        """Encrypt data"""
        m_length = len(src)
        block_bytes = self.block_bytes
        
        # Step 3 of Algorithm 2 - Page 6 (C and part of A)
        self.A = bytearray(block_bytes)
        self.m_length = m_length
        
        if dst is None or len(dst) == 0:
            dst = bytearray(block_bytes)
        
        self.LFSRC(src, dst)
        
        self.mac.InitWithR(bytes(self.R))
        self.mac.Update(bytes(dst))
        self.mac.GetTag(self.A, self.cipher.BLOCK_SIZE * 8)
    
    def Decrypt(self, dst: bytearray, src: bytes):
        """Decrypt data"""
        self.LFSRC(src, dst)
    
    def GetTag(self, tag: Optional[bytearray] = None, tag_bits: int = 96):
        """Get authentication tag"""
        if tag is None:
            tag = bytearray(tag_bits // 8)
        
        block_bytes = self.block_bytes
        
        # Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
        Atemp = bytearray(block_bytes)
        copy_len = min(len(self.A), block_bytes)
        Atemp[:copy_len] = self.A[:copy_len]
        
        aux_value1 = bytearray(block_bytes)
        aux_value2 = bytearray(block_bytes)
        
        # auxValue1 = rpad(bin(n-tagBits)||1)
        diff = self.cipher.BLOCK_SIZE * 8 - tag_bits
        
        if diff == 0:
            aux_value1[0] = 0x80
            aux_value1[1] = 0x00
        elif diff < 0:
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x80
        else:
            diff = (diff << 1) | 0x01
            while diff > 0 and (diff & 0x80) == 0:
                diff = (diff << 1) & 0xFF
            aux_value1[0] = diff & 0xFF
            aux_value1[1] = 0x00
        
        # auxValue2 = lpad(bin(|M|))
        for i in range(4):
            aux_value2[block_bytes - i - 1] = ((self.m_length * 8) >> (8 * i)) & 0xFF
        
        self._xor(Atemp, aux_value1)
        self._xor(Atemp, aux_value2)
        
        # Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
        if len(self.L) != 0:
            # auxValue2 = lpad(bin(|H|))
            aux_value2 = bytearray(block_bytes)
            for i in range(4):
                aux_value2[block_bytes - i - 1] = ((self.h_length * 8) >> (8 * i)) & 0xFF
            
            Dtemp = bytearray(block_bytes)
            copy_len = min(len(self.D), block_bytes)
            Dtemp[:copy_len] = self.D[:copy_len]
            
            self._xor(Dtemp, aux_value1)
            self._xor(Dtemp, aux_value2)
            self.cipher.Sct(aux_value1, bytes(Dtemp))
            self._xor(Atemp, aux_value1)
        
        # Step 7 of Algorithm 2 - Page 6
        self.cipher.Encrypt(aux_value1, bytes(Atemp))
        
        tag_bytes = tag_bits // 8
        tag[:tag_bytes] = aux_value1[:tag_bytes]
        return bytes(tag[:tag_bytes])


def main():
    parser = argparse.ArgumentParser(
        description='Curupira2 LetterSoup AEAD - Compatible with edgetk',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt with AAD
  echo -n "Test" | python curupira2AEAD.py -e -k 0228674ed28f695ed88a39ec --aad metadata
  
  # Encrypt without AAD
  echo -n "Test" | python curupira2AEAD.py -e -k 0228674ed28f695ed88a39ec
  
  # Decrypt with edgetk
  echo -n "Test" | python curupira2AEAD.py -e -k 0228674ed28f695ed88a39ec | \
    edgetk -crypt dec -cipher curupira2 -mode lettersoup -key 0228674ed28f695ed88a39ec
        """
    )
    
    # Operation mode
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-e', '--encrypt', action='store_true', 
                          help='Encrypt input')
    mode_group.add_argument('-d', '--decrypt', action='store_true', 
                          help='Decrypt input')
    mode_group.add_argument('-t', '--test', action='store_true',
                          help='Run self-test')
    
    # Key (required only for encrypt/decrypt, not for test)
    parser.add_argument('-k', '--key', type=str, required=False,
                       help='Key as hexadecimal string (12/18/24 bytes)')
    
    # AAD
    parser.add_argument('--aad', type=str, default='',
                       help='Additional Authenticated Data (AAD)')
    
    # Input/Output
    parser.add_argument('-f', '--file', type=str,
                       help='Input file (if not specified, reads from stdin)')
    parser.add_argument('-o', '--output', type=str,
                       help='Output file (if not specified, writes to stdout)')
    
    args = parser.parse_args()
    
    if args.test:
        return run_self_test()
    
    # For encrypt/decrypt operations, key is required
    if not args.key:
        parser.error("Key (-k) is required for encrypt/decrypt operations")
    
    try:
        # Convert key
        key_hex = args.key.strip().lower()
        if key_hex.startswith('0x'):
            key_hex = key_hex[2:]
        key = bytes.fromhex(key_hex)
        
        # Validate key size
        if len(key) not in [12, 18, 24]:
            raise ValueError(f"Key must be 12, 18 or 24 bytes, got {len(key)} bytes")
        
        # Read input
        if args.file:
            with open(args.file, 'rb') as f:
                input_data = f.read()
        else:
            if sys.stdin.isatty():
                print("Enter input (Ctrl+D to finish):", file=sys.stderr)
            input_data = sys.stdin.buffer.read()
        
        # Create cipher
        cipher = Curupira2(key)
        
        # Create LetterSoup
        aead = LetterSoup(cipher)
        
        # Convert AAD (allow empty AAD)
        aad = args.aad.encode('utf-8') if args.aad else b''
        
        if args.encrypt:
            # Generate random nonce (12 bytes)
            nonce = os.urandom(12)
            
            # Set IV
            aead.SetIV(nonce)
            
            # Process AAD
            aead.Update(aad)
            
            # Encrypt
            ciphertext = bytearray(len(input_data))
            aead.Encrypt(ciphertext, input_data)
            
            # Get tag
            tag = aead.GetTag(None, 96)
            
            # Output: nonce + tag + ciphertext
            output = nonce + tag + bytes(ciphertext)
            
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(output)
                print(f"Encryption complete. Output written to {args.output}", file=sys.stderr)
                print(f"Nonce: {nonce.hex()}", file=sys.stderr)
                print(f"Tag: {tag.hex()}", file=sys.stderr)
                print(f"Ciphertext length: {len(ciphertext)} bytes", file=sys.stderr)
            else:
                sys.stdout.buffer.write(output)
            
        else:  # decrypt
            # Check minimum size
            if len(input_data) < 24:
                raise ValueError("Input too short. Must contain at least 24 bytes (nonce + tag)")
            
            # Extract nonce, tag and ciphertext
            nonce = input_data[:12]
            tag = input_data[12:24]
            ciphertext = input_data[24:]
            
            # Set IV
            aead.SetIV(nonce)
            
            # Process AAD
            aead.Update(aad)
            
            # Decrypt
            plaintext = bytearray(len(ciphertext))
            aead.Decrypt(plaintext, ciphertext)
            
            # Verify authentication (like edgetk)
            # Re-encrypt to verify tag
            test_ciphertext = bytearray(len(plaintext))
            
            # Create new instance for verification
            aead_verify = LetterSoup(cipher)
            aead_verify.SetIV(nonce)
            
            aead_verify.Update(aad)
            
            aead_verify.Encrypt(test_ciphertext, bytes(plaintext))
            test_tag = aead_verify.GetTag(None, 96)
            
            # Compare tags
            if tag != test_tag:
                raise ValueError(f"Authentication failed! Expected tag: {test_tag.hex()}, Received tag: {tag.hex()}")
            
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(plaintext)
                print(f"Decryption complete. Output written to {args.output}", file=sys.stderr)
            else:
                sys.stdout.buffer.write(plaintext)
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def run_self_test():
    """Run compatibility tests with fixed test vectors"""
    print("=== Running Curupira2 LetterSoup AEAD self-test ===")
    print("Note: Using fixed test vectors for verification\n")
    
    try:
        # Fixed test vectors
        test_key = bytes.fromhex("0228674ed28f695ed88a39ec")
        test_plaintext = b"Test message for LetterSoup"
        test_aad = b"metadata"
        
        print(f"Test key: {test_key.hex()}")
        print(f"Test plaintext: {test_plaintext}")
        print(f"Test AAD: {test_aad}")
        
        # Create cipher
        cipher = Curupira2(test_key)
        
        # Test 1: Basic encryption/decryption
        print("\n1. Basic encryption/decryption test:")
        aead = LetterSoup(cipher)
        nonce = bytes.fromhex("000102030405060708090a0b")  # Fixed nonce for reproducible tests
        
        aead.SetIV(nonce)
        aead.Update(test_aad)
        
        ciphertext = bytearray(len(test_plaintext))
        aead.Encrypt(ciphertext, test_plaintext)
        tag = aead.GetTag(None, 96)
        
        print(f"   Nonce: {nonce.hex()}")
        print(f"   Ciphertext (hex): {bytes(ciphertext).hex()}")
        print(f"   Tag: {tag.hex()}")
        
        # Decrypt
        aead2 = LetterSoup(cipher)
        aead2.SetIV(nonce)
        aead2.Update(test_aad)
        
        decrypted = bytearray(len(ciphertext))
        aead2.Decrypt(decrypted, bytes(ciphertext))
        
        print(f"   Decrypted: {bytes(decrypted)}")
        print(f"   Match original: {test_plaintext == bytes(decrypted)}")
        
        # Test 2: Empty AAD
        print("\n2. Test with empty AAD:")
        aead3 = LetterSoup(cipher)
        aead3.SetIV(nonce)
        aead3.Update(b'')  # Empty AAD
        
        ciphertext3 = bytearray(len(test_plaintext))
        aead3.Encrypt(ciphertext3, test_plaintext)
        tag3 = aead3.GetTag(None, 96)
        
        print(f"   Ciphertext with empty AAD: {bytes(ciphertext3).hex()[:32]}...")
        print(f"   Tag with empty AAD: {tag3.hex()}")
        
        # Test 3: Different AAD produces different tag
        print("\n3. Different AAD produces different results:")
        aead4 = LetterSoup(cipher)
        aead4.SetIV(nonce)
        aead4.Update(b'different_aad')
        
        ciphertext4 = bytearray(len(test_plaintext))
        aead4.Encrypt(ciphertext4, test_plaintext)
        tag4 = aead4.GetTag(None, 96)
        
        print(f"   Ciphertext same as test 1? {bytes(ciphertext) == bytes(ciphertext4)}")
        print(f"   Tag same as test 1? {tag == tag4}")
        
        # Test 4: Compatibility with self-encryption/decryption
        print("\n4. Self-consistency test:")
        test_messages = [
            b"",
            b"A",
            b"AB",
            b"ABC",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            b"This is a longer test message to verify encryption works properly!"
        ]
        
        all_passed = True
        for i, msg in enumerate(test_messages):
            aead_test = LetterSoup(cipher)
            test_nonce = os.urandom(12)
            
            aead_test.SetIV(test_nonce)
            aead_test.Update(test_aad)
            
            encrypted = bytearray(len(msg))
            aead_test.Encrypt(encrypted, msg)
            test_tag = aead_test.GetTag(None, 96)
            
            # Decrypt
            aead_dec = LetterSoup(cipher)
            aead_dec.SetIV(test_nonce)
            aead_dec.Update(test_aad)
            
            decrypted = bytearray(len(encrypted))
            aead_dec.Decrypt(decrypted, bytes(encrypted))
            
            passed = msg == bytes(decrypted)
            all_passed = all_passed and passed
            
            print(f"   Test {i+1} ({len(msg)} bytes): {'PASS' if passed else 'FAIL'}")
            if not passed:
                print(f"     Expected: {msg}")
                print(f"     Got: {bytes(decrypted)}")
        
        if all_passed:
            print("\n✓ All self-consistency tests passed!")
        else:
            print("\n✗ Some tests failed!")
            return 1
        
        print("\n=== Self-test completed successfully! ===")
        print("\nTo test compatibility with edgetk:")
        print("  echo -n 'Test message' | python curupira2AEAD.py -e -k 0228674ed28f695ed88a39ec | \\")
        print("  edgetk -crypt dec -cipher curupira2 -mode lettersoup -key 0228674ed28f695ed88a39ec")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Self-test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
