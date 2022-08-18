


RSpec.describe "X509 engine spec for Java" do

  it 'generates X.509 certificate with ECC keypair' do
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

    c = fact.generate(kp.private_key)
    expect(c).not_to be nil
    #expect(c.is_a?(java.security.cert.Certificate)).to be true
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

  end

  it 'generates X.509 certificate with AIA/CRL Dist Point for ECC keypair' do
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

    #prof.key_usage.enable_digitalSignature(true).enable_nonRepudiation
    prof.key_usage.enable_digitalSignature(true).enable_keyEncipherment

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timestamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    prof.crl_dist_point = ["https://www.test.com/crl", "https://www.test2.com/crl"]
    prof.ocsp_url = ["https://www.test.com/ocsp1","https://www.test2.com/ocsp2"] 
    prof.issuer_url = ["https://www.test.com/issuer/issuerx","https://www.test2.com/issuerx"]

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp.private_key)
    expect(c).not_to be nil
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

    File.open("test_aia.crt","wb") do |f|
      f.write c.to_der
    end

  end

  it 'generates X.509 certificate with custom ext key usage for ECC keypair' do
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

    prof.crl_dist_point = ["https://www.test.com/crl", "https://www.test2.com/crl"]
    prof.ocsp_url = ["https://www.test.com/ocsp1","https://www.test2.com/ocsp2"] 
    prof.issuer_url = ["https://www.test.com/issuer/issuerx","https://www.test2.com/issuerx"]

    prof.add_domain_key_usage("1.2.11.22.33")

    prof.add_custom_extension("1.2.12.44.11.88","Private use only")

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp.private_key)
    expect(c).not_to be nil
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

    File.open("test_custom_eku.crt","wb") do |f|
      f.write c.to_der
    end

  end


  it 'generates X.509 certificate with RSA keypair' do
    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
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

    c = fact.generate(kp.private_key)
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

    rootCert = fact.generate(root.private_key)
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
        when :store_pass
          "password"
        when :key_name
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

    subCACert = fact.generate(root.private_key)
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
        when :store_pass
          "password"
        when :key_name
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

    leafCACert = fact.generate(subCA.private_key)
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
        when :store_pass
          "password"
        when :key_name
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

    userCert = fact.generate(leafCA.private_key)
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
        when :store_pass
          "password"
        when :key_name
          "Test End User Certificate"
        end
      end

      f.write ksb
    end

    puts "User Certificate generated"

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser.p12"))
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rkp,rcert,rchain = kpfc.from_storage(File.read("enduser.p12")) do |key|
      case key
      when :store_pass
        "password"
      when :key_name
        "Test End User Certificate"
      end
    end
    expect(rkp != nil).to be true
    expect(rkp.equal?(subscriber)).to be true
    expect(rcert.equal?(userCert)).to be true

    rchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert)  or cc.equal?(userCert) )).to be true
    end


    File.open("enduser.jks","wb") do |f|
      ksb = subscriber.to_storage(:jks) do |key|
        case key
        when :cert
          userCert
        when :certchain
          # start from the leaf until to root
          [leafCACert, subCACert, rootCert] 
        when :store_pass
          "password"
        when :key_name
          "Test End User Certificate"
        end
      end

      f.write ksb
    end

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser.jks"))
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rrkp,rrcert,rrchain = kpfc.from_storage(File.read("enduser.jks")) do |key|
      case key
      when :store_pass
        "password"
      when :key_name
        "Test End User Certificate"
      end
    end
    expect(rrkp != nil).to be true
    expect(rrkp.equal?(subscriber)).to be true
    expect(rrcert.equal?(userCert)).to be true

    rrchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert)  or cc.equal?(userCert) )).to be true
    end

  end


  it 'generates X.509 RSA certificates tree and store in P12 file' do
    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new)
    root = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Root CA RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Root.CA-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = root.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    rootCert = fact.generate(root.private_key)
    expect(rootCert).not_to be nil
    expect(rootCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("root-rsa.crt","wb") do |f|
      f.write rootCert.to_der
    end

    File.open("root-rsa.p12","wb") do |f|
      ksb = root.to_storage(:p12) do |key|
        case key
        when :cert
          rootCert
        when :certchain
          [rootCert]
        when :store_pass
          "password"
        when :key_name
          "Test Root CA RSA"
        end
      end

      f.write ksb
    end

    puts "Root CA RSA Cert Generated"

    subCA = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Sub CA RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Sub.CA-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = rootCert
    prof.public_key = subCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    subCACert = fact.generate(root.private_key)
    expect(subCACert).not_to be nil
    expect(subCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("sub-ca-rsa.crt","wb") do |f|
      f.write subCACert.to_der
    end

    File.open("sub-ca-rsa.p12","wb") do |f|
      ksb = subCA.to_storage(:p12) do |key|
        case key
        when :cert
          subCACert
        when :certchain
          [rootCert]
        when :store_pass
          "password"
        when :key_name
          "Test Sub CA RSA"
        end
      end

      f.write ksb
    end

    puts "Sub CA RSA Certificate generated"

    leafCA = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Operational CA RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Ops.CA-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = subCACert
    prof.public_key = leafCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    leafCACert = fact.generate(subCA.private_key)
    expect(leafCACert).not_to be nil
    expect(leafCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("ops-ca-rsa.crt","wb") do |f|
      f.write leafCACert.to_der
    end

    File.open("ops-ca-rsa.p12","wb") do |f|
      ksb = leafCA.to_storage(:p12) do |key|
        case key
        when :cert
          leafCACert
        when :certchain
          # for Java, sequence of certs is important
          [subCACert, rootCert]
        when :store_pass
          "password"
        when :key_name
          "Test Operational CA RSA"
        end
      end

      f.write ksb
    end

    puts "Operational CA RSA Certificate generated"


    subscriber = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Subscriber RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Subscriber-rsa@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = false
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = leafCACert
    prof.public_key = subscriber.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    userCert = fact.generate(leafCA.private_key)
    expect(userCert).not_to be nil
    expect(userCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("enduser-rsa.crt","wb") do |f|
      f.write userCert.to_der
    end

    File.open("enduser-rsa.p12","wb") do |f|
      ksb = subscriber.to_storage(:p12) do |key|
        case key
        when :cert
          userCert
        when :certchain
          # start from the leaf until to root
          [leafCACert, subCACert, rootCert] 
        when :store_pass
          "password"
        when :key_name
          "Test End User RSA Certificate"
        end
      end

      f.write ksb
    end

    puts "User Certificate RSA generated"

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser-rsa.p12"))
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rkp,rcert,rchain = kpfc.from_storage(File.read("enduser-rsa.p12")) do |key|
      case key
      when :store_pass
        "password"
      end
    end
    expect(rkp != nil).to be true
    expect(rkp.equal?(subscriber)).to be true
    expect(rcert.equal?(userCert)).to be true

    rchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert)  or cc.equal?(userCert) )).to be true
    end


    File.open("enduser-rsa.jks","wb") do |f|
      ksb = subscriber.to_storage(:jks) do |key|
        case key
        when :cert
          userCert
        when :certchain
          # start from the leaf until to root
          [leafCACert, subCACert, rootCert] 
        when :store_pass
          "password"
        when :key_name
          "Test End User Certificate RSA"
        end
      end

      f.write ksb
    end

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser-rsa.jks"))
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rrkp,rrcert,rrchain = kpfc.from_storage(File.read("enduser-rsa.jks")) do |key|
      case key
      when :store_pass
        "password"
      when :key_name
        "Test End User Certificate RSA"
      end
    end
    expect(rrkp != nil).to be true
    expect(rrkp.equal?(subscriber)).to be true
    expect(rrcert.equal?(userCert)).to be true

    rrchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert) or cc.equal?(userCert) )).to be true
    end


  end


end
