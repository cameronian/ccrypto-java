


RSpec.describe "X509 engine spec for Java" do

  it 'generates X.509 certificate' do
    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    expect(prof).not_to be nil

    prof.owner_name = "Jamma"
    prof.org = "SAA"

    prof.org_unit = ["asdf","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "jamma@saa.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timestamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp)
    expect(c).not_to be nil
    expect(c.is_a?(java.security.cert.Certificate)).to be true

  end

end
