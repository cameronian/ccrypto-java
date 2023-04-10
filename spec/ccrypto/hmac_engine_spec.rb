
class DC
  extend Ccrypto::Java::DataConversion
end

RSpec.describe "HMAC on Java" do
  
  it 'Data signing using symmetric key' do
  
    #kc = Ccrypto::KeyConfig.new
    #kc.algo = :aes
    #kc.keysize = 256
    #sk = Ccrypto::AlgoFactory.engine(Ccrypto::KeyConfig).generate(kc)

    #p DC.to_hex(sk.key)

    gkey = "871e9e4194f2e5b13e09700ba242c566164c3251fd74f695890acb6ed687416b"

    conf = Ccrypto::HMACConfig.new
    #conf.key = sk
    conf.key = Ccrypto::SecretKey.new(:aes, DC.from_hex(gkey))
    conf.digest = :sha256
    sc = Ccrypto::AlgoFactory.engine(conf)
    expect(sc).not_to be nil

    d = sc.hmac_digest("password", :hex)
    expect(d == "6580ca226981acd4f3c7f8de88e28fdca9736a161abcc07f1408100aad374a1c").to be true

    dd = sc.hmac_digest("password", :b64)
    expect(dd == "ZYDKImmBrNTzx/jeiOKP3KlzahYavMB/FAgQCq03Shw=").to be true

  end

end
