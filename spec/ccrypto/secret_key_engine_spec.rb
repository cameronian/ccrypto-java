

RSpec.describe "Secret key engine test" do

  it 'generates secret key' do
    
    kc = Ccrypto::KeyConfig.new
    kc.algo = :aes
    kc.keysize = 256
    sk = Ccrypto::AlgoFactory.engine(Ccrypto::KeyConfig).generate(kc)
    expect(sk).not_to be nil

    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    iv = cipher.random_iv
    cipher.key = sk.key

    res = cipher.update("testing")+cipher.final


    c2 = OpenSSL::Cipher.new("AES-256-CBC")
    c2.decrypt
    c2.iv = iv
    c2.key = sk.key
    
    res2 = c2.update(res)+c2.final
    expect(res2 == "testing").to be true

  end

end
