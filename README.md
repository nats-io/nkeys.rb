# NATS Keys for Ruby

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://travis-ci.org/nats-io/ruby-nkeys.svg?branch=master)](http://travis-ci.org/nats-io/ruby-nkeys)

A public-key signature system based on [Ed25519](https://ed25519.cr.yp.to/) for the [NATS](https://nats.io) ecosystem.

## Installation

```sh
gem install nkeys
```

## Usage

```ruby
require 'nkeys'
require 'base64'

# Load already generated seed to create a KeyPair 
# that can be used to signed messages.
seed = "SUADZTYQAKTY5NQM7XRB5XR3C24M6ROGZLBZ6P5HJJSSOFUGC5YXOOECOM"

kp = NATS::NKEYS::from_seed(seed)
puts "SEED:       #{kp.seed}"
puts "PUBLIC KEY: #{kp.public_key}"

# Example nonce sent by server
nonce = "Yv0MLXx29ApwLt4="
signed = kp.sign(nonce)
puts "SIGNED:     #{Base64.strict_encode64(signed)}"
```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
