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
  def self.valid_public_prefix?(prefix)
    [Prefix::SERVER, Prefix::OPERATOR, Prefix::CLUSTER, Prefix::ACCOUNT, Prefix::USER].include?(prefix)
  end

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

  def self.valid_prefix?(prefix)
    parse_prefix(prefix) != Prefix::UNKNOWN
  end

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
