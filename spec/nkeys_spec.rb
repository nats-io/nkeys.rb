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
  let(:seed) {
    "SUAEL6RU3BSDAFKOHNTEOK5Q6FTM5FTAMWVIKBET6FHPO4JRII3CYELVNM"
  }

  let(:nonce) {
    "jxb0seV48g5ahgw="
  }

  it 'should generate a KeyPair from a seed that can be used to sign and messages' do
    kp = NATS::NKEYS::from_seed(seed)
    signed_nonce = kp.sign(nonce)
    encoded_signed_nonce = Base64.strict_encode64(signed_nonce)
    expect(encoded_signed_nonce).to eql("SOOgRmACgje+P1JcrZzs5vSlN70xu3h4tt6UQEO+VKfaD0BVuCeFqcoj6T1HYaLKW2UGa3F2DUVUSVh2rCUvCQ==")
  end

  it "should generate a public key from the KeyPair from a seed" do
    kp = NATS::NKEYS::from_seed(seed)
    expect(kp.public_key).to eql("UCARKS2E3KVB7YORL2DG34XLT7PUCOL2SVM7YXV6ETHLW6Z46UUJ2VZ3")
  end
end
