

class DC
  extend Ccrypto::Java::DataConversion
end

RSpec.describe "Argon2 on Java" do

  it 'generate Argon2 output' do
    
    conf = Ccrypto::Argon2Config.new
    conf.outBitLength = 256
    sc = Ccrypto::AlgoFactory.engine(conf)
    expect(sc).not_to be nil

    conf.salt = DC.from_hex('666f336cde076b9510d497093604bf5a')
    conf.secret = DC.from_hex('f456174c1ee2473f0473a711a1cbc0de')

    res = sc.derive("password", :hex)
    expect(res == 'ab26786a60dbeb6e8881eb15b835aaa67859bbd42935f415c331eda551725144').to be true

    res = sc.derive("password", :b64)
    expect(res == "qyZ4amDb626IgesVuDWqpnhZu9QpNfQVwzHtpVFyUUQ=").to be true

  end

end
