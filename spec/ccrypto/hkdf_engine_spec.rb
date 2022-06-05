
class DC
  extend Ccrypto::Java::DataConversion
end

RSpec.describe "HKDF on Java" do
  
  it 'generates HKDF output' do
   
    conf = Ccrypto::HKDFConfig.new
    conf.outBitLength = 256
    sc = Ccrypto::AlgoFactory.engine(conf)
    expect(sc).not_to be nil

    conf.salt = DC.from_hex("69a63bfdbe67c64cfed04a37ba817259")
    d = sc.derive("password", :hex)
    expect(d == "a62f92e435f2d8b6235058b4ccac03c977bfc8e8f43696c76f87c848390c0050").to be true

    dd = sc.derive("password", :b64)
    expect(dd == "pi+S5DXy2LYjUFi0zKwDyXe/yOj0NpbHb4fISDkMAFA=").to be true

  end

end
