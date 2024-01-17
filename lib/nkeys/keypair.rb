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
    def initialize(public_key)
      @public_key = public_key
    end

    def public_key
      unless @public_key
        raise NKEYS::ClearedPair
      end
      @public_key
    end

    def private_key
      raise NKEYS::PublicKeyOnly
    end

    def seed
      raise NKEYS::PublicKeyOnly
    end

    def sign(input)
      raise NKEYS::CannotSign
    end

    def verify(input, sig)
      public_key
      buf = Codec._decode(@public_key)
      key = Ed25519::VerifyKey.new(buf[1..-1].pack('C*'))
      key.verify(sig, input)
    end

    def clear
      @public_key = nil
    end
  end

  class KeyPair
    def initialize(seed)
      @seed = seed
    end

    def raw_seed
      sd = Codec.decode_seed(seed)
      sd.buf
    end

    def seed
      unless @seed
        raise NKEYS::ClearedPair
      end
      @seed
    end

    def public_key
      sd  = Codec.decode_seed(seed)
      kp  = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      Codec.encode(sd.prefix, kp.verify_key.to_bytes.bytes)
    end

    def private_key
      kp = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      Codec.encode(Prefix::PRIVATE, kp.to_bytes.bytes + kp.verify_key.to_bytes.bytes)
    end

    def sign(input)
      kp = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      kp.sign(input)
    end

    def verify(input, sig)
      key = Ed25519::SigningKey.new(raw_seed.pack('C*'))
      key.verify_key.verify(sig, input)
    end

    def clear
      @seed = nil
    end
  end
end
