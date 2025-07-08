module NKEYS
  class Error < StandardError; end

  class InvalidPrefixByte < Error
    def initialize
      super("nkeys: invalid prefix byte")
    end
  end

  class InvalidKey < Error
    def initialize
      super("nkeys: invalid key")
    end
  end

  class InvalidPublicKey < Error
    def initialize
      super("nkeys: invalid public key")
    end
  end

  class InvalidSeedLen < Error
    def initialize
      super("nkeys: invalid seed length")
    end
  end

  class InvalidSeed < Error
    def initialize
      super("nkeys: invalid seed")
    end
  end

  class InvalidEncoding < Error
    def initialize
      super("nkeys: invalid encoded key")
    end
  end

  class InvalidSignature < Error
    def initialize
      super("nkeys: signature verification failed")
    end
  end

  class CannotSign < Error
    def initialize
      super("nkeys: cannot sign, no private key available")
    end
  end

  class PublicKeyOnly < Error
    def initialize
      super("nkeys: no seed or private key available")
    end
  end

  class InvalidChecksum < Error
    def initialize
      super("nkeys: invalid checksum")
    end
  end

  class SerializationError < Error
    def initialize
      super("nkeys: serialization error")
    end
  end

  class ApiError < Error
    def initialize
      super("nkeys: api error")
    end
  end

  class ClearedPair < Error
    def initialize
      super("nkeys: pair is cleared")
    end
  end
end
