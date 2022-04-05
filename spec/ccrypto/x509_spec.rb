


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
    #expect(c.is_a?(java.security.cert.Certificate)).to be true
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

  end

  it 'generates X.509 certificates tree and store in P12 file' do
    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    root = ecc.generate_keypair

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
    prof.public_key = root.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    rootCert = fact.generate(root)
    expect(rootCert).not_to be nil
    expect(rootCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("root.crt","wb") do |f|
      f.write rootCert.to_der
    end

    File.open("root.p12","wb") do |f|
      ksb = root.to_storage(:p12) do |key|
        case key
        when :cert
          rootCert
        when :certchain
          [rootCert]
        when :p12_pass
          "password"
        when :p12_name
          "Test Root CA"
        end
      end

      f.write ksb
    end

    puts "Root CA Cert Generated"

    subCA = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Sub CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Sub.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = rootCert
    prof.public_key = subCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    subCACert = fact.generate(root)
    expect(subCACert).not_to be nil
    expect(subCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("sub-ca.crt","wb") do |f|
      f.write subCACert.to_der
    end

    File.open("sub-ca.p12","wb") do |f|
      ksb = subCA.to_storage(:p12) do |key|
        case key
        when :cert
          subCACert
        when :certchain
          [rootCert]
        when :p12_pass
          "password"
        when :p12_name
          "Test Sub CA"
        end
      end

      f.write ksb
    end

    puts "Sub CA Certificate generated"

    leafCA = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Operational CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Ops.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = subCACert
    prof.public_key = leafCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    leafCACert = fact.generate(subCA)
    expect(leafCACert).not_to be nil
    expect(leafCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("ops-ca.crt","wb") do |f|
      f.write leafCACert.to_der
    end

    File.open("ops-ca.p12","wb") do |f|
      ksb = leafCA.to_storage(:p12) do |key|
        case key
        when :cert
          leafCACert
        when :certchain
          # for Java, sequence of certs is important
          [subCACert, rootCert]
        when :p12_pass
          "password"
        when :p12_name
          "Test Operational CA"
        end
      end

      f.write ksb
    end

    puts "Operational CA Certificate generated"


    subscriber = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Subscriber"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Subscriber@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = false
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = leafCACert
    prof.public_key = subscriber.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    userCert = fact.generate(leafCA)
    expect(userCert).not_to be nil
    expect(userCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("enduser.crt","wb") do |f|
      f.write userCert.to_der
    end

    File.open("enduser.p12","wb") do |f|
      ksb = subscriber.to_storage(:p12) do |key|
        case key
        when :cert
          userCert
        when :certchain
          # start from the leaf until to root
          [leafCACert, subCACert, rootCert] 
        when :p12_pass
          "password"
        when :p12_name
          "Test End User Certificate"
        end
      end

      f.write ksb
    end

    puts "User Certificate generated"

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser.p12"))
    }.to raise_exception(Ccrypto::KeypairEngineException)

    rkp,rcert,rchain = kpfc.from_storage(File.read("enduser.p12")) do |key|
      case key
      when :p12_pass
        "password"
      end
    end
    expect(rkp != nil).to be true
    expect(rkp.equal?(subscriber)).to be true
    expect(rcert.equal?(userCert)).to be true

    rchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert) )).to be true
    end

  end


end
