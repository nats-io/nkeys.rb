# NATS Keys for Ruby

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://travis-ci.org/nats-io/nkeys.rb.svg?branch=master)](http://travis-ci.org/nats-io/nkeys.rb)
[![Gem Version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=rb&type=5&v=0.1.0)](https://rubygems.org/gems/nkeys/versions/0.1.0)

A public-key signature system based on [Ed25519](https://ed25519.cr.yp.to/) for the [NATS](https://nats.io) ecosystem.

## About

The NATS ecosystem will be moving to
[Ed25519](https://ed25519.cr.yp.to/) keys for identity, authentication
and authorization for entities such as Accounts, Users, Servers and
Clusters.

Ed25519 is fast and resistant to side channel attacks. Generation of a
seed key is all that is needed to be stored and kept safe, as the seed
can generate both the public and private keys.

The NATS system will utilize Ed25519 keys, meaning that NATS systems
will never store or even have access to any private
keys. Authentication will utilize a random challenge response
mechanism.

Dealing with 32 byte and 64 byte raw keys can be challenging. NKEYS is
designed to formulate keys in a much friendlier fashion and references
work done in cryptocurrencies, specifically
[Stellar](https://www.stellar.org/). Bitcoin and others used a form of
Base58 (or Base58Check) to endode raw keys. Stellar utilized a more
traditonal Base32 with a CRC16 and a version or prefix byte. NKEYS
utilizes a similar format where the prefix will be 1 byte for public
and private keys and will be 2 bytes for seeds. The base32 encoding of
these prefixes will yield friendly human readbable prefixes,
e.g. '**N**' = server, '**C**' = cluster, '**O**' = operator, '**A**'
= account, and '**U**' = user. '**P**' is used for private keys. For
seeds, the first encoded prefix is '**S**', and the second character
will be the type for the public key, e.g. "**SU**" is a seed for a
user key pair, "**SA**" is a seed for an account key pair.

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

kp = NKEYS::from_seed(seed)
puts "SEED:       #{kp.seed}"
puts "PUBLIC KEY: #{kp.public_key}"

# Sign some data with the KeyPair user.
data = "Yv0MLXx29ApwLt4="
signed = kp.sign(data)
puts "SIGNED:     #{Base64.urlsafe_encode64(signed)}"

# Clear the keys after using them
kp.wipe!
```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
