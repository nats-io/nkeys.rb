# Copyright 2010-2018 The NATS Authors
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

lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require File.expand_path('../lib/nkeys/version', __FILE__)

spec = Gem::Specification.new do |s|
  s.name = 'nkeys'
  s.version = NATS::NKEYS::VERSION
  s.summary = 'NATS Keys for Ruby'
  s.homepage = 'https://nats.io'
  s.description = 'NATS Keys for Ruby'
  s.licenses = ['MIT']
  s.authors = ['Waldemar Quevedo']
  s.email = ['wally@synadia.com']
  s.add_dependency('ed25519')
  s.add_dependency('base32')
  s.require_paths = ['lib']

  s.files = %w[
    nkeys.gemspec
    lib/nkeys.rb
    lib/nkeys/crc16.rb
    lib/nkeys/keypair.rb
    lib/nkeys/version.rb
  ]
end
