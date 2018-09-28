# Copyright 2018 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
require 'base32'
require_relative 'nkeys/keypair'

module NATS
  module NKEYS

    # PREFIX_BYTE_SEED is the version byte used for encoded NATS Seeds
    PREFIX_BYTE_SEED     = 18 << 3    # Base32-encodes to 'S...'

    # PREFIX_BYTE_PRIVATE is the version byte used for encoded NATS Private keys
    PREFIX_BYTE_PRIVATE  = 15 << 3    # Base32-encodes to 'P...'

    # PREFIX_BYTE_SERVER is the version byte used for encoded NATS Servers
    PREFIX_BYTE_SERVER   = 13 << 3    # Base32-encodes to 'N...'

    # PREFIX_BYTE_CLUSTER is the version byte used for encoded NATS Clusters
    PREFIX_BYTE_CLUSTER  = 2 << 3     # Base32-encodes to 'C...'

    # PREFIX_BYTE_OPERATOR is the version byte used for encoded NATS Operators
    PREFIX_BYTE_OPERATOR = 14 << 3    # Base32-encodes to 'O...'

    # PREFIX_BYTE_ACCOUNT is the version byte used for encoded NATS Accounts
    PREFIX_BYTE_ACCOUNT  = 0          # Base32-encodes to 'A...'

    # PREFIX_BYTE_USER is the version byte used for encoded NATS Users
    PREFIX_BYTE_USER     = 20 << 3    # Base32-encodes to 'U...'

    class << self

      # Create a keypair to use for signing from a seed.
      # @param [String] seed The seed from which can create a public/private KeyPair.
      def from_seed(seed)
        _, raw_seed = decode_seed(seed)
        keys = Ed25519::SigningKey.new(raw_seed)

        KeyPair.new(seed: seed, keys: keys)
      end

      # Create a keypair capable of verifying signatures.
      # @param [String] public_key The public key to create the KeyPair.
      def from_public_key(public_key)
        KeyPair.new(public_key: public_key)
      end

      def decode_seed(src)
        # Take the encoded seed if provided and generate the private and public keys,
        # since both are needed to be able to sign things.
        base32_decoded = Base32.decode(src).bytes
        raw = base32_decoded[0...(base32_decoded.size-2)]

        # 248 = 11111000
        b1 = raw[0] & 248

        # 7 = 00000111
        b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)

        case
        when b1 != PREFIX_BYTE_SEED
          raise NKEYS::Error, "nkeys: Invalid Seed"
        when !valid_public_prefix_byte(b2)
          raise NKEYS::Error, "nkeys: Invalid Byte Prefix"
        end

        prefix = b2
        result = raw[2..(raw.size)].pack('c*')

        [prefix, result]
      end

      def valid_public_prefix_byte(prefix)
        case
        when prefix == PREFIX_BYTE_SERVER; true
        when prefix == PREFIX_BYTE_CLUSTER; true
        when prefix == PREFIX_BYTE_OPERATOR; true
        when prefix == PREFIX_BYTE_ACCOUNT; true
        when prefix == PREFIX_BYTE_USER; true
        else
          false
        end
      end

      def valid_prefix_byte(prefix)
        case
        when prefix == PREFIX_BYTE_OPERATOR; true
        when prefix == PREFIX_BYTE_SERVER; true
        when prefix == PREFIX_BYTE_CLUSTER; true
        when prefix == PREFIX_BYTE_ACCOUNT; true
        when prefix == PREFIX_BYTE_USER; true
        when prefix == PREFIX_BYTE_SEED; true
        when prefix == PREFIX_BYTE_PRIVATE; true
        else
          false
        end
      end
    end
  end
end
