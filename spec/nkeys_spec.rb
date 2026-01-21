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

require 'base64'
require 'spec_helper'

describe 'NKEYS' do
  it 'should generate a KeyPair from a seed that can be used for signing' do
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    nonce = "PXoWU7zWAMt75FY"
    kp = NKEYS::from_seed(seed)
    signed_nonce = kp.sign(nonce)
    encoded_signed_nonce = Base64.strict_encode64(signed_nonce)
    expect(encoded_signed_nonce).to eql("ZaAiVDgB5CeYoXoQ7cBCmq+ZllzUnGUoDVb8C7PilWvCs8XKfUchAUhz2P4BYAF++Dg3w05CqyQFRDiGL6LrDw==")
    expect(kp.verify(nonce, signed_nonce)).to be_truthy
  end

  it "should raise error when seed has bad padding" do
    expect do
      NKEYS::from_seed("UAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")
    end.to raise_error NKEYS::InvalidSeed
  end

  it "should raise error with invalid seeds" do
    expect do
      NKEYS::from_seed("AUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")
    end.to raise_error NKEYS::InvalidSeed

    expect do
      NKEYS::from_seed("")
    end.to raise_error NKEYS::InvalidSeed
  end

  it "should validate prefix bytes" do
    seeds = [
             "SNAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
             "SCAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
             "SOAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
             "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
            ]
    for seed in seeds do
      NKEYS::from_seed(seed)
    end

    invalid_seeds = [
                     'SDAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',                     
                     'SBAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU'
                    ]
    for seed in invalid_seeds do
      expect do
        NKEYS::from_seed(seed)
      end.to raise_error(NKEYS::InvalidPrefixByte)
    end

    invalid_seeds = [
                     'PWAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU',
                     'PMAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU'
                    ]
    for seed in invalid_seeds do
      expect do
        NKEYS::from_seed(seed)
      end.to raise_error(NKEYS::InvalidSeed)
    end
  end

  it "should wipe seed contents" do
    seed = "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
    initial_id = seed.object_id
    kp = NKEYS::from_seed(seed)
    result = kp.sign("something")
    encoded = Base64.urlsafe_encode64(result)
    expect(encoded).to eql("wXiEA0PRldwUH_fdmiyIbOALeVjVRzZKEPqbxgnn3lI3UwXWEw6LJcotqWq1C_tWhFzX3kYMa8jHY1NiiydTDA==")
    kp.wipe

    expect do 
      kp.sign("foo")
    end.to raise_error(NKEYS::Error)

    expect(seed.size).to eql(0)
    expect(seed.object_id).to eql(initial_id)
  end

  it "should be able to generate a public key from a seed" do
    kp = NKEYS::from_seed("SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")
    expect(kp.public_key).to eql("UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L")
    kp.wipe!
    expect(kp.public_key).to eql("")
  end
end
