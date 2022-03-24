

RSpec.describe "ECC Engine Spec for Java" do

  it 'generates ECC keypair' do

    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig)
    expect(ecc != nil).to be true

    ecc.supported_curves.each do |c|
      kp = Ccrypto::AlgoFactory.engine(c).generate_keypair
      expect(kp != nil).to be true
      expect(kp.is_a?(Ccrypto::KeyBundle)).to be true
    end

  end

  it 'derive key from keypair' do
   
    ec = Ccrypto::ECCConfig.new
    ecc1 = Ccrypto::AlgoFactory.engine(ec).generate_keypair
    ecc2 = Ccrypto::AlgoFactory.engine(ec).generate_keypair

    v1 = ecc1.derive_dh_shared_secret(ecc2.public_key)
    v2 = ecc2.derive_dh_shared_secret(ecc1.public_key)

    expect(v1 == v2).to be true

    v11 = ecc1.derive_dh_shared_secret(ecc1.public_key)
    v22 = ecc1.derive_dh_shared_secret(ecc1.public_key)

    expect(v11 == v22).to be true

  end

  it 'encodes and decodes public key correctly' do
    ec = Ccrypto::ECCConfig.new
    ee = Ccrypto::AlgoFactory.engine(ec)

    ek = ee.generate_keypair

    rpekb = ek.public_key.to_bin 
    rpek = ek.public_key.class.to_key(rpekb)

    p rpek.to_bin
    p rpekb

    expect(rpek.to_bin == rpekb)

  end

end