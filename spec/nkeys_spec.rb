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
  end

  it "should be able to generate a public key from a seed" do
    kp = NKEYS::from_seed("SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")
    expect(kp.public_key).to eql("UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L")
  end

  it "should raise error when seed has bad padding" do
    expect do
      NKEYS::from_seed("UAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")
    end.to raise_error NKEYS::InvalidSeed
  end
end
