

RSpec.describe "ED25519 engine spec" do

  it 'generates ED25519 keypair, perform signing and verification' do
   
    require 'ccrypto/java'

    conf = Ccrypto::ED25519Config.new
    eng = Ccrypto::AlgoFactory.engine(conf)
    kp = eng.generate_keypair
    expect(kp).not_to be nil

    conf.keypair = kp

    data = "Integrity protected message"
    sign = eng.sign(data)
    expect(sign).not_to be nil

    veng = Ccrypto::AlgoFactory.engine(Ccrypto::ED25519Config)
    expect(veng.verify(kp.public_key, data, sign)).to be true
    expect(veng.verify(kp.public_key, "whatever invalid data", sign)).to be false

  end

end
