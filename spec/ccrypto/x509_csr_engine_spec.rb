

RSpec.describe "X509 CSR engine spec for Javas" do

  before(:all) do

    # issuer
    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    @rootKp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Root CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Root.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = @rootKp.public_key

    now = Time.now
    prof.not_before = Time.new(now.year, now.month, now.day, 9,0,0)
    prof.validity(5, :years)

    fact = Ccrypto::AlgoFactory.engine(prof)

    @rootCert = fact.generate(@rootKp.private_key)
    
  end

  it 'generates CSR from user certificate for ECC keypair' do
    
    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CSRProfile.new
    prof.owner_name = "Fitz" 
    prof.org = "General"
    prof.org_unit = ["Hunter"]

    prof.dns_name = ["hunterdns.com"]
    prof.email = "fitz@general.com"
    prof.ip_addr = "1.10.12.112"
    prof.uri = ["https://hunter.com","https://hunter-dr.com"]

    #prof.add_custom_attribute("challengePassword","whatever is true")
    #prof.add_custom_attribute("1.2.840.113549.1.9.7","whatever is true")
    prof.add_custom_attribute("1.2.1.22.123.11","whatever is true")

    prof.add_custom_extension("1.24.23.44.223","For private use")

    prof.public_key = kp.public_key

    csrFact = Ccrypto::AlgoFactory.engine(prof)
    expect(csrFact).not_to be nil

    csr = csrFact.generate(kp.private_key)
    expect(csr).not_to be nil
    expect(csr.is_a?(Ccrypto::X509CSR)).to be true

    fos = java.io.FileOutputStream.new(java.io.File.new("csr.csr"))
    fos.write csr.to_bin
    fos.flush
    fos.close

    certProf = Ccrypto::X509::CertProfile.new
    # csr should handle the subject and attributes
    certProf.csr = csr
    certProf.issuer_cert = @rootCert

    certProf.key_usage.enable_digitalSignature.enable_nonRepudiation
    certProf.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    certProf.gen_subj_key_id = true
    certProf.gen_auth_key_id = true

    now = Time.now
    certProf.not_before = Time.new(now.year, now.month, now.day, 9,0,0)
    certProf.validity(2, :years)

    certProf.crl_dist_point = ["https://www.test.com/crl", "https://www.test2.com/crl"]
    certProf.ocsp_url = ["https://www.test.com/ocsp1","https://www.test2.com/ocsp2"] 
    certProf.issuer_url = ["https://www.test.com/issuer/issuerx","https://www.test2.com/issuerx"]

    certProf.add_domain_key_usage("1.2.11.22.33")

    fact = Ccrypto::AlgoFactory.engine(certProf)
    cert = fact.generate(@rootKp.private_key) 

    fos = java.io.FileOutputStream.new(java.io.File.new("cert_from_csr.crt"))
    fos.write(cert.to_der)
    fos.flush
    fos.close

  end

end
