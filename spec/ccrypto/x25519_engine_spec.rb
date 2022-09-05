

RSpec.describe "X25519 engine spec" do

  it 'generates X25519 keypair and derives session key' do
   
    conf = Ccrypto::X25519Config.new
    eng = Ccrypto::AlgoFactory.engine(conf)
    kp1 = eng.generate_keypair
    kp2 = eng.generate_keypair
    expect(kp1).not_to be nil
    expect(kp2).not_to be nil

    sec1 = kp1.derive_dh_shared_secret(kp2.public_key)
    expect(sec1).not_to be nil
    sec2 = kp2.derive_dh_shared_secret(kp1.public_key)
    expect(sec2).not_to be nil

    expect(sec1 == sec2).to be true
    
  end

end
