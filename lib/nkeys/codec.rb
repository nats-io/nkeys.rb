require "base32"

class Codec
  SeedDecode = Struct.new(:buf, :prefix)

  def self.encode(prefix, src)
    unless src.is_a?(Array)
      raise NKEYS::SerializationError
    end

    unless Prefixes.valid_prefix?(prefix)
      raise NKEYS::InvalidPrefixByte
    end

    _encode(false, prefix, src)
  end

  def self.encode_seed(prefix_byte, src)
    raise NKEYS::ApiError unless src.is_a?(Array)
    raise NKEYS::InvalidPrefixByte unless Prefixes.valid_public_prefix?(prefix_byte)
    raise NKEYS::InvalidSeedLen unless src.length == 32

    _encode(true, prefix_byte, src)
  end

  def self.decode(expected, src)
    raise NKEYS::InvalidPrefixByte unless Prefixes.valid_prefix?(expected)

    raw = _decode(src)
    raise NKEYS::InvalidPrefixByte unless raw[0].ord == expected

    raw[1..-1]
  end

  def self.decode_seed(src)
    raw    = _decode(src)
    prefix = _decode_prefix(raw)

    raise NKEYS::InvalidSeed unless prefix[0] == Prefix::SEED
    raise NKEYS::InvalidPrefixByte unless Prefixes.valid_public_prefix?(prefix[1])

    SeedDecode.new(raw[2..-1], prefix[1])
  end

  private

  def self._encode(seed, role, payload)
    raw = []
    if seed
      encoded_prefix = _encode_prefix(Prefix::SEED, role)
      raw[0...2]     = encoded_prefix
    else
      raw[0] = role
    end
    raw += payload

    checksum = NKEYS.crc16(raw)
    raw      += [checksum].pack('S').unpack('C*')

    Base32.encode(raw.pack('C*')).gsub("=", '')
  end

  def self._decode(src)
    raise NKEYS::InvalidEncoding if src.length < 4

    begin
      raw = Base32.decode(src)
    rescue => ex
      raise NKEYS::InvalidEncoding
    end

    check_offset = raw.length - 2
    checksum     = raw[check_offset..-1].unpack('S')[0]
    payload      = raw[0...check_offset]

    unless NKEYS.crc16(payload.bytes) == checksum
      raise NKEYS::InvalidChecksum
    end
    payload.bytes
  end

  def self._encode_prefix(kind, role)
    b1 = kind | (role >> 5)
    b2 = (role & 31) << 3 # 31 = 00011111
    [b1, b2]
  end

  def self._decode_prefix(raw)
    b1 = raw[0] & 248 # 248 = 11111000
    b2 = ((raw[0] & 7) << 5) | ((raw[1] & 248) >> 3) # 7 = 00000111
    [b1, b2]
  end
end
