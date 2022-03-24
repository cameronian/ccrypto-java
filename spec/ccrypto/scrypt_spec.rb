
class DC
  extend Ccrypto::Java::DataConversion
end

RSpec.describe "Scrypt on Java" do
  
  it 'generates Scrypt output' do
   
    conf = Ccrypto::ScryptConfig.new
    conf.outBitLength = 256
    sc = Ccrypto::AlgoFactory.engine(conf)
    expect(sc).not_to be nil

    conf.salt = DC.from_hex("69a63bfdbe67c64cfed04a37ba817259")
    d = sc.derive("password", :hex)
    expect(d == "f2358c36f0ce75f129962508076e1db38d35e2dfa7686966d933e23aad92f603").to be true

    dd = sc.derive("password", :b64)
    expect(dd == "8jWMNvDOdfEpliUIB24ds4014t+naGlm2TPiOq2S9gM=").to be true

  end

end
