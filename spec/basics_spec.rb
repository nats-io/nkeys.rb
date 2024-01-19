require "spec_helper"
# @param [NKEYS::KeyPair] kp
# @param [String] kind
def test_key(kp, kind)
  seed = kp.seed
  expect(seed[0]).to eq "S"
  expect(seed[1]).to eq kind

  public_key = kp.public_key
  expect(public_key[0]).to eq kind

  data = "HelloWorld"
  sig  = kp.sign(data)
  expect(sig.length).to eq 64
  expect(kp.verify(data, sig)).to be_truthy

  sk = NKEYS.from_seed(seed)
  expect(sk.verify(data, sig)).to be_truthy

  pub = NKEYS.from_public(public_key)
  expect(pub.public_key).to eq public_key
  expect(pub.verify(data, sig)).to be_truthy

  expect {
    pub.private_key
  }.to raise_error(NKEYS::PublicKeyOnly)
  expect(pub.verify(data, sig)).to be_truthy

  expect {
    pub.seed
  }.to raise_error(NKEYS::PublicKeyOnly)

  test_clear(kp)
  test_clear(pub)
end

def test_clear(kp)
  kp.clear

  expect {
    kp.public_key
  }.to raise_error(NKEYS::ClearedPair)

  expect {
    kp.verify("hello", "sig")
  }.to raise_error(NKEYS::ClearedPair)
end

describe "Basics" do
  let(:bad_key) do
    a  = NKEYS.create_account
    pk = a.public_key.bytes
    pk[pk.length - 1] = 0
    pk[pk.length - 2] = 0
    pk
  end

  it "creates an operator" do
    test_key(NKEYS.create_operator, "O")
  end

  it "creates an account" do
    test_key(NKEYS.create_account, "A")
  end

  it "creates an user" do
    test_key(NKEYS.create_user, "U")
  end

  it "creates an cluster" do
    test_key(NKEYS.create_cluster, "C")
  end

  it "creates an server" do
    test_key(NKEYS.create_server, "N")
  end

  it "basics - should fail with non public prefix" do
    expect {
      NKEYS.create_pair(Prefix::PRIVATE)
    }.to raise_error(NKEYS::InvalidPrefixByte)
  end

  it "basics - should fail getting public key on bad seed" do
    expect {
      kp = NKEYS::KeyPair.new("SEEDBAD")
      kp.public_key
    }.to raise_error(NKEYS::InvalidChecksum)
  end

  it "basics - should fail getting private key on bad seed" do
    expect {
      kp = NKEYS::KeyPair.new("SEEDBAD")
      kp.private_key
    }.to raise_error(NKEYS::InvalidChecksum)
  end

  it "basics - should fail signing on bad seed" do
    expect {
      kp = NKEYS::KeyPair.new("SEEDBAD")
      kp.sign("HelloWorld")
    }.to raise_error(NKEYS::InvalidChecksum)
  end

  it "basics - fromPublicKey should reject bad checksum" do
    expect {
      bk = bad_key
      NKEYS.from_public(bk.pack('C*'))
    }.to raise_error(NKEYS::InvalidEncoding)
  end

  it "basics - should reject decoding seed bad checksum" do
    expect {
      a = NKEYS.create_account
      pk = a.public_key
      Codec.decode_seed(pk)
    }.to raise_error(NKEYS::InvalidSeed)
  end
end
