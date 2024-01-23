module Prefix
  UNKNOWN  = -1
  SEED     = 18 << 3
  PRIVATE  = 15 << 3
  OPERATOR = 14 << 3
  SERVER   = 13 << 3
  CLUSTER  = 2 << 3
  ACCOUNT  = 0
  USER     = 20 << 3
end

class Prefixes
  # Check if the prefix is in the public domain
  # @param [Integer] prefix
  def self.valid_public_prefix?(prefix)
    [Prefix::SERVER, Prefix::OPERATOR, Prefix::CLUSTER, Prefix::ACCOUNT, Prefix::USER].include?(prefix)
  end

  # Check if an encoded key has a valid prefix
  # @param [String] s
  def self.starts_with_valid_prefix?(s)
    case s[0]
    when 'S'
      prefix = Prefix::SEED
    when 'P'
      prefix = Prefix::PRIVATE
    when 'O'
      prefix = Prefix::OPERATOR
    when 'N'
      prefix = Prefix::SERVER
    when 'C'
      prefix = Prefix::CLUSTER
    when 'A'
      prefix = Prefix::ACCOUNT
    when 'U'
      prefix = Prefix::USER
    else
      return false
    end
    valid_prefix?(prefix)
  end

  # Check if the prefix is valid
  # @param [Integer] prefix
  # @return [TrueClass, FalseClass]
  def self.valid_prefix?(prefix)
    parse_prefix(prefix) != Prefix::UNKNOWN
  end

  # Returns the prefix if it's valid otherwise Prefix::UNKNOWN
  # @param [Integer] prefix
  # @return [Integer]
  def self.parse_prefix(v)
    case v
    when Prefix::SEED, Prefix::PRIVATE, Prefix::OPERATOR, Prefix::SERVER,
      Prefix::CLUSTER, Prefix::ACCOUNT, Prefix::USER
      v
    else
      Prefix::UNKNOWN
    end
  end
end
