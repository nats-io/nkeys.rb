require 'spec_helper'

describe Codec do
  it "should fail to encode non Strings" do
    expect {
      Codec.encode(Prefix::PRIVATE, 10);
    }.to raise_error NKEYS::SerializationError
  end
  it "should fail to encode with invalid prefix" do
    expect {
      Codec.encode(13, SecureRandom.bytes(32).bytes);
    }.to raise_error NKEYS::InvalidPrefixByte
  end

  it "should encode and decode" do
    rand = SecureRandom.bytes(32).bytes
    enc  = Codec.encode(Prefix::PRIVATE, rand)
    expect(enc[0]).to eq "P"

    dec = Codec._decode(enc)
    expect(dec[0]).to eq Prefix::PRIVATE
    expect(dec[1..-1]).to eq rand
  end

  it "should fail to encode seeds that are not 32 bytes" do
    expect {
      Codec.encode_seed(Prefix::ACCOUNT, SecureRandom.bytes(64).bytes);
    }.to raise_error NKEYS::InvalidSeedLen
  end

  it "should encode seed and decode account" do
    rand = SecureRandom.bytes(32).bytes
    enc  = Codec.encode_seed(Prefix::ACCOUNT, rand)
    expect(enc[0]).to eq "S"
    expect(enc[1]).to eq "A"

    dec = Codec.decode(Prefix::SEED, enc)
    expect(dec[0]).to eq Prefix::ACCOUNT
    expect(dec[1..-1]).to eq rand
  end

  it "should encode and decode seed" do
    rand = SecureRandom.bytes(32).bytes
    enc  = Codec.encode_seed(Prefix::ACCOUNT, rand)
    expect(enc[0]).to eq "S"
    expect(enc[1]).to eq "A"

    seed = Codec.decode_seed(enc)
    expect(seed.prefix).to eq Prefix::ACCOUNT
    expect(seed.buf).to eq rand
  end

  it "should fail to decode non-base32" do
    expect {
      Codec.decode_seed("foo!");
    }.to raise_error NKEYS::InvalidEncoding
  end

  it "should fail to short string" do
    expect {
      Codec.decode_seed("OK");
    }.to raise_error NKEYS::InvalidEncoding
  end

  it "decode with invalid role should fail" do
    rand = SecureRandom.bytes(32).bytes
    seed = Codec.encode_seed(Prefix::ACCOUNT, rand)
    expect {
      Codec.decode("Z", seed);
    }.to raise_error NKEYS::InvalidPrefixByte
  end

  it "encode seed requires buffer" do
    expect {
      Codec.encode_seed("Z", "seed");
    }.to raise_error NKEYS::ApiError
  end

  it "decodeSeed with invalid role should fail" do
    rand     = SecureRandom.bytes(32).bytes
    bad_seed = Codec._encode(true, 23 << 3, rand)

    expect {
      Codec.decode_seed(bad_seed);
    }.to raise_error NKEYS::InvalidPrefixByte
  end

  it "decode unexpected prefix should fail" do
    rand = SecureRandom.bytes(32).bytes
    seed = Codec._encode(true, Prefix::ACCOUNT, rand)
    expect {
      Codec.decode(Prefix::USER, seed);
    }.to raise_error NKEYS::InvalidPrefixByte
  end
end
