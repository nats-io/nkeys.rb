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
require_relative 'nkeys/prefixes'
require_relative 'nkeys/errors'
require_relative 'nkeys/codec'
require_relative 'nkeys/keypair'

module NKEYS

  # PREFIX_BYTE_SEED is the version byte used for encoded NATS Seeds
  PREFIX_BYTE_SEED = 18 << 3 # Base32-encodes to 'S...'

  # PREFIX_BYTE_PRIVATE is the version byte used for encoded NATS Private keys
  PREFIX_BYTE_PRIVATE = 15 << 3 # Base32-encodes to 'P...'

  # PREFIX_BYTE_SERVER is the version byte used for encoded NATS Servers
  PREFIX_BYTE_SERVER = 13 << 3 # Base32-encodes to 'N...'

  # PREFIX_BYTE_CLUSTER is the version byte used for encoded NATS Clusters
  PREFIX_BYTE_CLUSTER = 2 << 3 # Base32-encodes to 'C...'

  # PREFIX_BYTE_OPERATOR is the version byte used for encoded NATS Operators
  PREFIX_BYTE_OPERATOR = 14 << 3 # Base32-encodes to 'O...'

  # PREFIX_BYTE_ACCOUNT is the version byte used for encoded NATS Accounts
  PREFIX_BYTE_ACCOUNT = 0 # Base32-encodes to 'A...'

  # PREFIX_BYTE_USER is the version byte used for encoded NATS Users
  PREFIX_BYTE_USER = 20 << 3 # Base32-encodes to 'U...'

  class << self

    # Create a keypair with correct prefix
    # @return [NKEYS::KeyPair]
    def create_pair(prefix)
      raw_seed = SecureRandom.random_bytes(Ed25519::KEY_SIZE).bytes
      seed     = Codec.encode_seed(prefix, raw_seed)
      KeyPair.new(seed)
    end

    # Create a keypair for an operator
    # @return [NKEYS::KeyPair]
    def create_operator
      create_pair(Prefix::OPERATOR)
    end

    # Create a keypair for an Account
    # @return [NKEYS::KeyPair]
    def create_account
      create_pair(Prefix::ACCOUNT)
    end

    # Create a keypair for a User
    # @return [NKEYS::KeyPair]
    def create_user
      create_pair(Prefix::USER)
    end

    # Create a keypair for a Cluster
    # @return [NKEYS::KeyPair]
    def create_cluster
      create_pair(Prefix::CLUSTER)
    end

    # Create a keypair for a Server
    # @return [NKEYS::KeyPair]
    def create_server
      create_pair(Prefix::SERVER)
    end

    # Create a keypair capable of verifying signatures.
    # @param [String] public_key The public key to create the KeyPair.
    def from_public(src)
      raw    = Codec._decode(src)
      prefix = Prefixes.parse_prefix(raw[0])
      if Prefixes.valid_public_prefix?(prefix)
        return PublicKey.new(src)
      end
      raise NKEYS::InvalidPublicKey
    end

    # Create a keypair to use for signing from a seed.
    # @param [String] seed The seed from which can create a public/private KeyPair.
    def from_seed(src)
      Codec.decode_seed(src)
      KeyPair.new(src)
    end

  end
end
