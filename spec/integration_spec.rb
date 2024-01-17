require 'spec_helper'
require 'base64'

describe "Integration" do
  it "can verify" do
    data = {
      seed:        "SAAFYOZ5U4UBAJMHPITLSKDWAFBJNWH53K7LPZDQKOC5TXAGBIP4DY4WCA",
      public_key:  "AAASUT7FDZDS6UCTBE7JQS2G6KUZBJC5YW7VFVK45JLUK3UDVA6NXJWD",
      private_key: "PBODWPNHFAICLB32E24SQ5QBIKLNR7O2X236I4CTQXM5YBQKD7A6GAJKJ7SR4RZPKBJQSPUYJNDPFKMQURO4LP2S2VOOUV2FN2B2QPG3AHUA",
      nonce:       "uPMbFqF4nSX75B0Nlk9uug==",
      sig:         "y9t/0VxLZET6fYlSL7whq52TSv8tP7FBXZdqbQhfdpKCa3pveV7889zqkpiQcv8ivwtACQwumPe6EgrxFc7yDw==",
    }

    pk = NKEYS.from_public(data[:public_key])

    sig   = Base64.decode64(data[:sig])
    nonce = data[:nonce]
    pk.verify(nonce, sig)

    seed = NKEYS.from_seed(data[:seed])
    expect(seed.verify(nonce, sig)).to be_truthy
    sig2   = seed.sign(nonce)
    encsig = Base64.encode64(sig2).gsub("\n", '')
    expect(encsig).to eq(data[:sig])
  end

  it "returns stable values albertor" do
    data = {
      seed:        "SUAGC3DCMVZHI33SMFWGEZLSORXXEYLMMJSXE5DPOJQWYYTFOJ2G64VAPY",
      public_key:  "UAHJLSMYZDJCBHQ2SARL37IEALR3TI7VVPZ2MJ7F4SZKNOG7HJJIYW5T",
      private_key: "PBQWYYTFOJ2G64TBNRRGK4TUN5ZGC3DCMVZHI33SMFWGEZLSORXXEDUVZGMMRURATYNJAIV57UCAFY5ZUP22X45GE7S6JMVGXDPTUUUMRKXA",
      nonce:       "P6Gz7PfS+Cqt0qTgheqa9w==",
      sig:         "Dg8/bNrSx/TqBiETRjkVIa3+vx8bQc/DcoFBuFfUiHAEWDsSkzNLgseZlP+x9ndVCoka6YpDIoTzc5NjHTgPCA==",
    }
    v    = Codec.encode_seed(Prefix::USER, "albertoralbertoralbertoralbertor".bytes)
    expect(v).to eq data[:seed]

    kp = NKEYS.from_seed(v)
    expect(kp.seed).to eq data[:seed]
    expect(kp.public_key).to eq data[:public_key]
    expect(kp.private_key).to eq data[:private_key]
  end
end
