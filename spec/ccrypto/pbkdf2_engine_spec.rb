
class DC
  extend Ccrypto::Java::DataConversion
end

RSpec.describe "PBKDF2 on Java" do
  
  it 'generates PBKDF2 output' do
   
    conf = Ccrypto::PBKDF2Config.new
    conf.outBitLength = 256
    conf.iter = 288800
    sc = Ccrypto::AlgoFactory.engine(conf)
    expect(sc).not_to be nil

    conf.salt = DC.from_hex("69a63bfdbe67c64cfed04a37ba817259")
    d = sc.derive("password", :hex)
    expect(d == "6bcd06586d638dc4b3451c3c2badce721ad5c476afd63e463f5f50676bf537e9").to be true

    dd = sc.derive("password", :b64)
    expect(dd == "a80GWG1jjcSzRRw8K63OchrVxHav1j5GP19QZ2v1N+k=").to be true

  end

end
