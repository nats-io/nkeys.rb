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
require 'ed25519'
require 'base32'
require 'nkeys/version'
require 'nkeys/crc16'

module NKEYS
  class PublicKey
    # Create a PublicKey from the encoded public key
    # @param [String] public_key
    def initialize(public_key)
      @public_key = public_key
    end

    # @return [String]
    def public_key
      unless @public_key
        raise NKEYS::ClearedPair
      end
      @public_key
    end

    # Private key is not available
    def private_key
      raise NKEYS::PublicKeyOnly
    end

    # Seed is not available
    def seed
      raise NKEYS::PublicKeyOnly
    end

    # Signing is not available
    def sign(input)
      raise NKEYS::CannotSign
    end

    # Verify the input against a signature utilizing the public key.
    # @param [String] input
    # @param [String] sig
    # @return [TrueClass, FalseClass] the result of verifying the signed input.
    def verify(input, sig)
      public_key
      buf = Codec._decode(@public_key)
      key = Ed25519::VerifyKey.new(buf[1..-1].pack('C*'))
      key.verify(sig, input)
    rescue Ed25519::VerifyError
      false
    end

    # Removes the public key
    def wipe!
      @public_key = nil
    end
  end

  class KeyPair
    # Create a KeyPair from the encoded seed
    # @param [String] seed
    def initialize(seed)
      @seed = seed
    end

    # Return the seed in bytes
    # @return [String]
    def raw_seed
      sd = Codec.decode_seed(seed)
      sd.buf
    end

    # Return the seed in readable form
    # @return [String]
    def seed
      unless @seed
        raise NKEYS::ClearedPair
      end
      @seed
    end

    # Return the public key with correct prefix
    # @return [String]
    def public_key
      sd = Codec.decode_seed(seed)
      kp = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      Codec.encode(sd.prefix, kp.verify_key.to_bytes.bytes)
    end

    # Return the private key with correct prefix
    # @return [String]
    def private_key
      kp = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      Codec.encode(Prefix::PRIVATE, kp.to_bytes.bytes + kp.verify_key.to_bytes.bytes)
    end

    # Sign the input utilizing the private key.
    # @param [String] input
    # @return [String] the signature bytes
    def sign(input)
      kp = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      kp.sign(input)
    end

    # Verify the input against a signature utilizing the public key.
    # @param [String] input
    # @param [String] sig
    # @return [TrueClass, FalseClass] the result of verifying the signed input.
    def verify(input, sig)
      key = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      key.verify_key.verify(sig, input)
    end

    # Removes the seed
    def wipe!
      @seed = nil
    end
  end
end
