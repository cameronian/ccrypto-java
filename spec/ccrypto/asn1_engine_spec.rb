

RSpec.describe "Building ASN1 object for Java" do

  it 'generate the ASN1 structure and convert back to value' do
   
    asn1 = Ccrypto::ASN1.engine
    expect(asn1).not_to be nil

    ver = asn1.build(:int, 0x0102)
    expect(ver).not_to be nil
    expect(ver.is_a?(Ccrypto::ASN1Object)).to be true
   
    v = ver.to_bin
    expect(v).not_to be nil

    pv = asn1.to_value(v, :int)
    expect(pv).not_to be nil
    expect(pv == 0x0102).to be true

    oid = asn1.build(:oid, "1.1.11")
    expect(oid).not_to be nil
    vo = oid.to_bin
    poid = asn1.to_value(vo)
    expect(poid == "1.1.11").to be true

    str = asn1.build(:str, "testing")
    expect(str).not_to be nil
    vs = str.to_bin
    pstr = asn1.to_value(vs)
    expect(pstr == "testing").to be true

    sd = Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig)
    data = sd.random_bytes(10)
    bin = asn1.build(:bin, data)
    expect(bin).not_to be nil
    vbin = bin.to_bin
    pbin = asn1.to_value(vbin)
    expect(pbin == data).to be true

    date = Time.now
    ad = asn1.build(:date, date)
    expect(ad).not_to be nil
    vad = ad.to_bin
    pvad = asn1.to_value(vad)
    expect(Time.at(pvad.time/1000).to_i == date.to_i).to be true

    res = []
    res << asn1.build(:int, 0x0110)
    res << asn1.build(:str, "testing")
    
    as = asn1.build(:seq, res)
    expect(as).not_to be nil
    asb = as.to_bin
    pasb = asn1.to_value(asb)
    expect(pasb == res).to be true

  end

  it 'calculate length of the ASN1' do
    
    asn1 = Ccrypto::ASN1.engine

    res = []
    res << asn1.build(:oid, "1.10.1.11.21.11")
    res << asn1.build(:int, 0x1234)
    res << asn1.build(:str, "String field")
    res << asn1.build(:bin, Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig).random_bytes(24))
    res << asn1.build(:date, Time.now)

    ares = asn1.build(:seq, res)

    bares = ares.to_bin

    len = asn1.asn1_length(bares)
    expect(len == 71).to be true
  end

end
