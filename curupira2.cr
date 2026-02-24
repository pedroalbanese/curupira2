# curupira2.cr (versão final com ordem corrigida)
module Curupira2
  # Constante do tamanho do bloco (12 bytes)
  BLOCK_SIZE = 12

  # Constante C para Marvin
  C = 0x2A_u8

  # Erro para chave inválida
  class InvalidKeyError < Exception
    def initialize
      super("curupira2: invalid key length (must be 12, 18, or 24 bytes)")
    end
  end

  # Tabela S-Box
  S_BOX_TABLE = [
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
  ].map(&.to_u8)

  # Tabela X-times
  X_TIMES_TABLE = [
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
  ].map(&.to_u8)

  # Funções auxiliares
  def self.s_box(v : UInt8) : UInt8
    S_BOX_TABLE[v]
  end

  def self.x_times(v : UInt8) : UInt8
    X_TIMES_TABLE[v]
  end

  def self.t0(v : UInt8) : UInt8
    ((v << 5) ^ (v << 3)).to_u8!
  end

  def self.t1(v : UInt8) : UInt8
    (v ^ (v >> 3) ^ (v >> 5)).to_u8!
  end

  # Interfaces definidas ANTES de serem usadas
  module MAC
    abstract def init : Nil
    abstract def init_with_r(r : Bytes) : Nil
    abstract def update(a_data : Bytes) : Nil
    abstract def get_tag(tag : Bytes?, tag_bits : Int32) : Bytes
  end

  module AEAD
    abstract def set_iv(iv : Bytes) : Nil
    abstract def update(a_data : Bytes) : Nil
    abstract def encrypt(dst : Bytes, src : Bytes) : Nil
    abstract def decrypt(dst : Bytes, src : Bytes) : Nil
    abstract def get_tag(tag : Bytes?, tag_bits : Int32) : Bytes
  end

  # Implementação do cifrador Curupira2
  class Cipher
    getter block_size : Int32
    getter key_enc : Bytes
    getter key_dec : Bytes
    getter key_length : UInt8
    getter number_of_rounds : UInt8

    def initialize(key : Bytes)
      @block_size = BLOCK_SIZE
      
      if key.size != 12 && key.size != 18 && key.size != 24
        raise InvalidKeyError.new
      end

      @key_enc = key.dup
      @key_dec = key.dup
      @key_length = (key.size - 1).to_u8
      @number_of_rounds = case key.size
                          when 12 then 10_u8
                          when 18 then 12_u8
                          else        14_u8
                          end

      # Gera as subchaves de decriptação
      msb = 0_u8
      @number_of_rounds.times do
        msb = create_next_key(@key_dec, msb, 1_u8)
      end
    end

    def encrypt(dst : Bytes, src : Bytes) : Nil
      if src.size < @block_size
        raise "curupira2: input not full block"
      end
      if dst.size < @block_size
        raise "curupira2: output not full block"
      end

      crypt(dst, src, 0_u8)
    end

    def decrypt(dst : Bytes, src : Bytes) : Nil
      if src.size < @block_size
        raise "curupira2: input not full block"
      end
      if dst.size < @block_size
        raise "curupira2: output not full block"
      end

      crypt(dst, src, 1_u8)
    end

    # Square Complete Transform (4 rounds não chaveados)
    def sct(dst : Bytes, src : Bytes) : Nil
      if src.size < @block_size
        raise "curupira2: input not full block"
      end
      if dst.size < @block_size
        raise "curupira2: output not full block"
      end

      tmp = src.dup

      4.times do
        s_on_row1(0, 3, tmp)
        swap_ct(2, 8, tmp)
        s_on_row1(6, 9, tmp)
        swap_ct(5, 11, tmp)

        4.times do |i|
          ptr = i * 3
          aux1 = tmp[ptr] ^ tmp[ptr + 1] ^ tmp[ptr + 2]
          aux1 = Curupira2.x_times(aux1)
          aux2 = Curupira2.x_times(aux1)

          tmp[ptr] ^= aux1
          tmp[ptr + 1] ^= aux2
          tmp[ptr + 2] ^= aux1 ^ aux2
        end
      end

      tmp.copy_to(dst)
    end

    private def crypt(dst : Bytes, src : Bytes, dir_decryption : UInt8) : Nil
      block = src.dup

      # Cria cópias locais das chaves
      key_enc_local = @key_enc.dup
      key_dec_local = @key_dec.dup

      key = dir_decryption == 0 ? key_enc_local : key_dec_local
      msb = dir_decryption == 0 ? 0_u8 : @number_of_rounds
      original_msb = msb

      # Whitening - NÃO modifica o msb original
      apply_key(block, key, msb)

      # Rounds - usa o msb original
      msb = original_msb

      (1..@number_of_rounds).each do |r|
        # Permutation layer
        s_on_row1(0, 3, block)
        swap_ct(2, 8, block)
        s_on_row1(6, 9, block)
        swap_ct(5, 11, block)

        # Cria chave da próxima rodada
        msb = create_next_key(key, msb, dir_decryption)

        if r == @number_of_rounds
          apply_key(block, key, msb)
          break
        end

        # Theta layer
        pos_msb = msb
        4.times do |i|
          aux3 = key[pos_msb]
          pos_msb = update_pos_msb(pos_msb)
          aux3 = Curupira2.s_box(aux3)

          ptr = i * 3
          aux1 = block[ptr] ^ block[ptr + 1] ^ block[ptr + 2]

          if dir_decryption != 0
            aux2 = pos_msb + 1
            aux2 = 0_u8 if aux2 > @key_length
            aux1 ^= aux3 ^ key[pos_msb] ^ key[aux2]
          end

          aux1 = Curupira2.x_times(aux1)
          aux2v = Curupira2.x_times(aux1)

          block[ptr] ^= aux1 ^ aux3
          block[ptr + 1] ^= aux2v ^ key[pos_msb]
          pos_msb = update_pos_msb(pos_msb)

          block[ptr + 2] ^= aux1 ^ aux2v ^ key[pos_msb]
          pos_msb = update_pos_msb(pos_msb)
        end
      end

      block.copy_to(dst)
    end

    private def create_next_key(key : Bytes, msb : UInt8, is_decryption : UInt8) : UInt8
      new_msb = msb
      aux1 : UInt8
      aux2 : UInt8

      if is_decryption != 0
        new_msb = 0_u8 if new_msb == 0
        new_msb -= 1 if new_msb > 0
        aux2 = key[new_msb]
        key[new_msb] ^= Curupira2.s_box(new_msb)
      else
        key[new_msb] ^= Curupira2.s_box(new_msb)
        aux2 = key[new_msb]
      end

      aux1 = new_msb != 0 ? new_msb - 1 : @key_length
      key[aux1] ^= Curupira2.t0(aux2)

      aux1 = aux1 != 0 ? aux1 - 1 : @key_length
      key[aux1] ^= Curupira2.t1(aux2)

      if is_decryption == 0
        new_msb += 1
        new_msb = 0_u8 if new_msb > @key_length
      end

      new_msb
    end

    private def swap_ct(ptr1 : Int32, ptr2 : Int32, block : Bytes) : Nil
      aux = Curupira2.s_box(block[ptr1])
      block[ptr1] = Curupira2.s_box(block[ptr2])
      block[ptr2] = aux
    end

    private def s_on_row1(ptr1 : Int32, ptr2 : Int32, block : Bytes) : Nil
      block[ptr1] = Curupira2.s_box(block[ptr1])
      block[ptr2] = Curupira2.s_box(block[ptr2])
      swap_ct(ptr1 + 1, ptr2 + 1, block)
    end

    private def update_pos_msb(pos_msb : UInt8) : UInt8
      new_pos = pos_msb + 1
      new_pos > @key_length ? 0_u8 : new_pos
    end

    private def apply_key(block : Bytes, key : Bytes, msb : UInt8) : UInt8
      pos_msb = msb
      i = 0

      while i < 12
        block[i] ^= Curupira2.s_box(key[pos_msb])
        i += 1
        pos_msb = update_pos_msb(pos_msb)
        break if i >= 12

        block[i] ^= key[pos_msb]
        i += 1
        pos_msb = update_pos_msb(pos_msb)
        break if i >= 12

        block[i] ^= key[pos_msb]
        i += 1
        pos_msb = update_pos_msb(pos_msb)
      end

      pos_msb
    end
  end

  # Implementação Marvin MAC
  class Marvin
    include MAC

    @buffer : Bytes
    @r : Bytes
    @o : Bytes
    @m_length : Int32 = 0
    @letter_soup_mode : Bool

    getter cipher : Cipher
    getter block_bytes : Int32

    def initialize(@cipher, r : Bytes? = nil, @letter_soup_mode = false)
      @block_bytes = @cipher.block_size
      @buffer = Bytes.new(@block_bytes, 0)
      @r = Bytes.new(@block_bytes, 0)
      @o = Bytes.new(@block_bytes, 0)

      if r
        init_with_r(r)
      else
        init
      end
    end

    def init : Nil
      # Step 2 of Algorithm 1 - Page 4
      left_padded_c = Bytes.new(@block_bytes, 0)
      left_padded_c[@block_bytes - 1] = C

      encrypted = Bytes.new(@block_bytes)
      @cipher.encrypt(encrypted, left_padded_c)

      @r = encrypted.dup
      xor_in_place(@r, left_padded_c)
      @o = @r.dup
    end

    def init_with_r(r : Bytes) : Nil
      len = Math.min(r.size, @block_bytes)
      @r[0, len].copy_from(r[0, len])
      @o.copy_from(@r)
    end

    def update(a_data : Bytes) : Nil
      a_length = a_data.size
      block_bytes = @block_bytes

      m = Bytes.new(block_bytes, 0)
      a = Bytes.new(block_bytes, 0)

      q = a_length // block_bytes
      r = a_length % block_bytes

      # Steps 1, 3-5, 6-7 (only R) of Algorithm 1 - Page 4
      xor_in_place(@buffer, @r)

      q.times do |i|
        m.copy_from(a_data[i * block_bytes, block_bytes])
        update_offset
        xor_in_place(m, @o)
        @cipher.sct(a, m)
        xor_in_place(@buffer, a)
      end

      if r != 0
        m.fill(0)
        m[0, r].copy_from(a_data[q * block_bytes, r])
        update_offset
        xor_in_place(m, @o)
        @cipher.sct(a, m)
        xor_in_place(@buffer, a)
      end

      @m_length = a_length
    end

    def get_tag(tag : Bytes? = nil, tag_bits : Int32 = 96) : Bytes
      tag_bytes = tag_bits // 8
      result = tag || Bytes.new(tag_bytes, 0)
      block_bytes = @block_bytes

      if @letter_soup_mode
        copy_bytes = Math.min(tag_bytes, block_bytes)
        result[0, copy_bytes].copy_from(@buffer[0, copy_bytes])
        return result
      end

      # Steps 6-9 of Algorithm 1 - Page 4
      a = Bytes.new(block_bytes, 0)
      encrypted_a = Bytes.new(block_bytes, 0)
      aux_value1 = Bytes.new(block_bytes, 0)
      aux_value2 = Bytes.new(block_bytes, 0)

      # auxValue1 = rpad(bin(n-tagBits)||1)
      diff = @cipher.block_size * 8 - tag_bits

      if diff == 0
        aux_value1[0] = 0x80_u8
        aux_value1[1] = 0x00_u8
      elsif diff < 0
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x80_u8
      else
        diff = (diff << 1) | 0x01
        while diff > 0 && (diff & 0x80) == 0
          diff = (diff << 1) & 0xFF
        end
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x00_u8
      end

      # auxValue2 = lpad(bin(|M|))
      processed_bits = 8 * @m_length
      4.times do |i|
        aux_value2[block_bytes - i - 1] = ((processed_bits >> (8 * i)) & 0xFF).to_u8!
      end

      a.copy_from(@buffer)
      xor_in_place(a, aux_value1)
      xor_in_place(a, aux_value2)

      @cipher.encrypt(encrypted_a, a)

      result[0, tag_bytes].copy_from(encrypted_a[0, tag_bytes])
      result
    end

    private def update_offset : Nil
      o0 = @o[0]

      # Shift left
      (0...11).each do |i|
        @o[i] = @o[i + 1]
      end

      @o[9] = (@o[9] ^ o0 ^ (o0 >> 3) ^ (o0 >> 5)).to_u8!
      @o[10] = (@o[10] ^ ((o0 << 5) & 0xFF) ^ ((o0 << 3) & 0xFF)).to_u8!
      @o[11] = o0
    end

    private def xor_in_place(a : Bytes, b : Bytes) : Nil
      len = Math.min(a.size, b.size)
      len.times do |i|
        a[i] ^= b[i]
      end
    end
  end

  # Implementação LetterSoup AEAD
  class LetterSoup
    include AEAD

    @cipher : Cipher
    @mac : MAC
    @block_bytes : Int32
    @m_length : Int32 = 0
    @h_length : Int32 = 0
    @iv : Bytes = Bytes.empty
    @a : Bytes = Bytes.empty
    @d : Bytes = Bytes.empty
    @r : Bytes = Bytes.empty
    @l : Bytes = Bytes.empty

    def initialize(@cipher)
      @block_bytes = @cipher.block_size
      @mac = Marvin.new(@cipher, nil, true)
    end

    def set_iv(iv : Bytes) : Nil
      iv_length = iv.size
      block_bytes = @block_bytes

      @iv = iv.dup
      @l = Bytes.empty

      # Step 2 of Algorithm 2 - Page 6
      @r = Bytes.new(block_bytes, 0)
      left_padded_n = Bytes.new(block_bytes, 0)

      start_idx = block_bytes - iv_length
      start_idx = 0 if start_idx < 0
      copy_len = Math.min(iv_length, block_bytes)
      
      left_padded_n[start_idx, copy_len].copy_from(iv[0, copy_len])

      encrypted = Bytes.new(block_bytes)
      @cipher.encrypt(encrypted, left_padded_n)

      @r = encrypted.dup
      xor_in_place(@r, left_padded_n)
    end

    def update(a_data : Bytes) : Nil
      a_length = a_data.size
      block_bytes = @block_bytes

      # Step 4 of Algorithm 2 - Page 6 (L and part of D)
      @l = Bytes.new(block_bytes, 0)
      @d = Bytes.new(block_bytes, 0)

      empty = Bytes.new(block_bytes, 0)

      @h_length = a_length
      @cipher.encrypt(@l, empty)

      mac = Marvin.new(@cipher, @l, true)
      mac.update(a_data)
      @d = mac.get_tag(nil, @cipher.block_size * 8)
    end

    def encrypt(dst : Bytes, src : Bytes) : Nil
      m_length = src.size
      block_bytes = @block_bytes

      # Step 3 of Algorithm 2 - Page 6 (C and part of A)
      @a = Bytes.new(block_bytes, 0)
      @m_length = m_length

      lfsrc(src, dst)

      mac = Marvin.new(@cipher, @r, true)
      mac.update(dst[0, m_length])
      @a = mac.get_tag(nil, @cipher.block_size * 8)
    end

    def decrypt(dst : Bytes, src : Bytes) : Nil
      lfsrc(src, dst)
    end

    def get_tag(tag : Bytes? = nil, tag_bits : Int32 = 96) : Bytes
      tag_bytes = tag_bits // 8
      result = tag || Bytes.new(tag_bytes, 0)
      block_bytes = @block_bytes

      # Step 3 of Algorithm 2 - Page 6 (completes the part of A due to M)
      atemp = Bytes.new(block_bytes, 0)
      copy_len = Math.min(@a.size, block_bytes)
      atemp[0, copy_len].copy_from(@a[0, copy_len])

      aux_value1 = Bytes.new(block_bytes, 0)
      aux_value2 = Bytes.new(block_bytes, 0)

      # auxValue1 = rpad(bin(n-tagBits)||1)
      diff = @cipher.block_size * 8 - tag_bits

      if diff == 0
        aux_value1[0] = 0x80_u8
        aux_value1[1] = 0x00_u8
      elsif diff < 0
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x80_u8
      else
        diff = (diff << 1) | 0x01
        while diff > 0 && (diff & 0x80) == 0
          diff = (diff << 1) & 0xFF
        end
        aux_value1[0] = diff.to_u8! & 0xFF
        aux_value1[1] = 0x00_u8
      end

      # auxValue2 = lpad(bin(|M|))
      4.times do |i|
        aux_value2[block_bytes - i - 1] = ((@m_length * 8) >> (8 * i)).to_u8! & 0xFF
      end

      xor_in_place(atemp, aux_value1)
      xor_in_place(atemp, aux_value2)

      # Steps 4-6 of Algorithm 2 - Page 6 (completes the part of A due to H)
      if !@l.empty?
        # auxValue2 = lpad(bin(|H|))
        aux_value2_h = Bytes.new(block_bytes, 0)
        4.times do |i|
          aux_value2_h[block_bytes - i - 1] = ((@h_length * 8) >> (8 * i)).to_u8! & 0xFF
        end

        dtemp = Bytes.new(block_bytes, 0)
        copy_len = Math.min(@d.size, block_bytes)
        dtemp[0, copy_len].copy_from(@d[0, copy_len])

        xor_in_place(dtemp, aux_value1)
        xor_in_place(dtemp, aux_value2_h)

        sct_result = Bytes.new(block_bytes)
        @cipher.sct(sct_result, dtemp)

        xor_in_place(atemp, sct_result)
      end

      # Step 7 of Algorithm 2 - Page 6
      encrypted = Bytes.new(block_bytes)
      @cipher.encrypt(encrypted, atemp)

      result[0, tag_bytes].copy_from(encrypted[0, tag_bytes])
      result
    end

    private def lfsrc(m_data : Bytes, c_data : Bytes) : Nil
      m_length = m_data.size
      block_bytes = @block_bytes

      m = Bytes.new(block_bytes, 0)
      c = Bytes.new(block_bytes, 0)
      o = @r.dup

      q = m_length // block_bytes
      r = m_length % block_bytes

      q.times do |i|
        m.copy_from(m_data[i * block_bytes, block_bytes])
        update_offset(o)
        @cipher.encrypt(c, o)
        xor_in_place(c, m)
        c_data[i * block_bytes, block_bytes].copy_from(c)
      end

      if r != 0
        m.fill(0)
        m[0, r].copy_from(m_data[q * block_bytes, r])
        update_offset(o)
        @cipher.encrypt(c, o)
        xor_in_place(c, m)
        c_data[q * block_bytes, r].copy_from(c[0, r])
      end
    end

    private def update_offset(o : Bytes) : Nil
      o0 = o[0]

      # Shift left
      (0...11).each do |i|
        o[i] = o[i + 1]
      end

      o[9] = (o[9] ^ o0 ^ (o0 >> 3) ^ (o0 >> 5)).to_u8!
      o[10] = (o[10] ^ ((o0 << 5) & 0xFF) ^ ((o0 << 3) & 0xFF)).to_u8!
      o[11] = o0
    end

    private def xor_in_place(a : Bytes, b : Bytes) : Nil
      len = Math.min(a.size, b.size)
      len.times do |i|
        a[i] ^= b[i]
      end
    end
  end
end
