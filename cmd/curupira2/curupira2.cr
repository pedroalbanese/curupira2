# curupira2_cli.cr (versão simples que funciona)
require "./curupira2"
require "option_parser"
require "random/secure"

# Funções auxiliares
def hex_to_bytes(hex : String) : Bytes
  hex = hex.downcase
  hex = hex[2..] if hex.starts_with?("0x")
  hex.hexbytes
end

def bytes_to_hex(bytes : Bytes) : String
  bytes.hexstring
end

# Modo de criptografia
def encrypt(key : Bytes, aad : String, input : Bytes) : Bytes
  nonce = Random::Secure.random_bytes(12)
  
  cipher = Curupira2::Cipher.new(key)
  aead = Curupira2::LetterSoup.new(cipher)
  
  aead.set_iv(nonce)
  aead.update(aad.to_slice)
  
  ciphertext = Bytes.new(input.size)
  aead.encrypt(ciphertext, input)
  tag = aead.get_tag(nil, 96)
  
  # Output: nonce + tag + ciphertext
  output = Bytes.new(nonce.size + tag.size + ciphertext.size)
  output[0, nonce.size].copy_from(nonce)
  output[nonce.size, tag.size].copy_from(tag)
  output[nonce.size + tag.size, ciphertext.size].copy_from(ciphertext)
  
  output
end

# Modo de decriptação
def decrypt(key : Bytes, aad : String, input : Bytes) : Bytes
  if input.size < 24
    raise "Input too short (need at least 24 bytes for nonce+tag)"
  end
  
  nonce = input[0, 12]
  tag = input[12, 12]
  ciphertext = input[24..-1]
  
  cipher = Curupira2::Cipher.new(key)
  aead = Curupira2::LetterSoup.new(cipher)
  
  aead.set_iv(nonce)
  aead.update(aad.to_slice)
  
  plaintext = Bytes.new(ciphertext.size)
  aead.decrypt(plaintext, ciphertext)
  
  # Verifica autenticação
  verify = Curupira2::LetterSoup.new(cipher)
  verify.set_iv(nonce)
  verify.update(aad.to_slice)
  
  test = Bytes.new(plaintext.size)
  verify.encrypt(test, plaintext)
  test_tag = verify.get_tag(nil, 96)
  
  # Comparação simples
  raise "Authentication failed" if tag != test_tag
  
  plaintext
end

# Lê todo o stdin para um Slice(UInt8)
def read_stdin : Bytes
  buffer = IO::Memory.new
  IO.copy(STDIN, buffer)
  buffer.to_slice
end

# Main
begin
  mode = nil
  key_hex = nil
  aad = ""
  
  OptionParser.parse do |parser|
    parser.banner = "Usage: curupira2 [-e|-d] -k KEY [--aad AAD]"
    
    parser.on("-e", "--encrypt", "Encrypt mode") { mode = "encrypt" }
    parser.on("-d", "--decrypt", "Decrypt mode") { mode = "decrypt" }
    parser.on("-k KEY", "--key=KEY", "Key in hex (12/18/24 bytes)") { |k| key_hex = k }
    parser.on("--aad AAD", "Additional authenticated data") { |a| aad = a }
    parser.on("-h", "--help", "Show help") { puts parser; exit }
  end
  
  unless mode
    puts "Error: Need -e or -d"
    puts "Use -h for help"
    exit 1
  end
  
  unless key_hex
    puts "Error: Need -k KEY"
    puts "Use -h for help"
    exit 1
  end
  
  begin
    # Converte a chave
    key = hex_to_bytes(key_hex.not_nil!)
    
    # Valida tamanho da chave
    unless [12, 18, 24].includes?(key.size)
      puts "Error: Key must be 12, 18 or 24 bytes, got #{key.size} bytes"
      exit 1
    end
    
    # Lê entrada do stdin
    input = read_stdin
    
    if mode == "encrypt"
      output = encrypt(key, aad, input)
      STDOUT.write(output)
    else
      output = decrypt(key, aad, input)
      STDOUT.write(output)
    end
    
  rescue e : ArgumentError
    STDERR.puts "Error: Invalid hex string: '#{key_hex}'"
    STDERR.puts "Hex string must have even length and contain only 0-9, a-f"
    exit 1
  rescue e
    STDERR.puts "Error: #{e.message}"
    exit 1
  end
end
