
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

  class Error < StandardError; end #:nodoc:

  class InvalidSeed < Error; end #:nodoc:

  class InvalidPrefixByte < Error; end #:nodoc:

  class KeyPair
    attr_reader :seed, :public_key, :private_key

    def initialize(opts={})
      @seed = opts[:seed]
      @public_key = opts[:public_key]
      @private_key = opts[:private_key]
      @keys = opts[:keys]
    end

    # Sign will sign the input with KeyPair's private key.
    # @param [String] input
    # @return [String] signed raw data
    def sign(input)
      raise ::NKEYS::Error, "nkeys: Missing keys for signing" if @keys.nil?

      @keys.sign(input)
    end

    # Verify the input againt a signature utilizing the public key.
    # @param [String] input
    # @param [String] sig
    # @return [Bool] the result of verifying the signed input.
    def verify(input, sig)
      @keys.verify_key.verify(sig, input)
    rescue Ed25519::VerifyError
      false
    end

    def public_key
      return @public_key unless @public_key.nil?
      # TODO: If no keys present then try to generate from seed.
      # prefix, public_raw = ::NATS::NKEYS::decode_seed(@seed)

      pk = @keys.verify_key.to_bytes.unpack("C*")
      pk.prepend(PREFIX_BYTE_USER)

      # Include crc16 checksum.
      crc16 = NKEYS::crc16(pk)
      crc16_suffix = [crc16].pack("s<*")
      crc16_suffix.each_byte do |b|
        pk << b
      end
      res = pk.pack("c*")

      # Remove padding since Base32 library always uses padding...
      @public_key = Base32.encode(res).gsub("=", '')

      @public_key
    end

    def private_key
      return @private_key unless @private_key.nil?
      # TODO
    end

    def wipe
      @seed.clear if @seed
      @public_key.clear if @public_key
      @private_key.clear if @private_key
      @keys = nil
    end
    alias_method :wipe!, :wipe
  end
end
