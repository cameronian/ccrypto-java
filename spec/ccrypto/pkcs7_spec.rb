

RSpec.describe "Test PKCS7" do

  #before do
  #
  #  ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
  #  @kp = ecc.generate_keypair

  #  prof = Ccrypto::X509::CertProfile.new

  #  prof.owner_name = "Simmon"
  #  prof.org = "Agent"

  #  prof.org_unit = ["Sara","id=A119"]
  #  prof.dns_name = "https://agent.com"
  #  prof.email = "simmon@agent.com"

  #  prof.key_usage.enable_digitalSignature.enable_nonRepudiation

  #  prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

  #  prof.gen_subj_key_id = true
  #  prof.gen_auth_key_id = true
  #  prof.public_key = @kp.public_key

  #  fact = Ccrypto::AlgoFactory.engine(prof)
  #  @cert = fact.generate(@kp)

  #end

  it 'sign and verify default attached signature' do
    
    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new

    prof.owner_name = "Simmon"
    prof.org = "Agent"

    prof.org_unit = ["Sara","id=A119"]
    prof.dns_name = "https://agent.com"
    prof.email = "simmon@agent.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    cert = fact.generate(kp.private_key)

    #rsa = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
    #kp = rsa.generate_keypair

    #prof = Ccrypto::X509::CertProfile.new

    #prof.owner_name = "Simmon RSA"
    #prof.org = "Agent"

    #prof.org_unit = ["Sara","id=A119"]
    #prof.dns_name = "https://agent.com"
    #prof.email = "simmon@agent.com"

    #prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    #prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    #prof.gen_subj_key_id = true
    #prof.gen_auth_key_id = true
    #prof.public_key = kp.public_key

    #fact = Ccrypto::AlgoFactory.engine(prof)
    #cert = fact.generate(kp)

   
    conf = Ccrypto::PKCS7Config.new
    conf.private_key = kp.private_key
    conf.signerCert = cert

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil

    data = "testging 18181818"*120
    puts "data length : #{data.length}"
    res = p7.sign(data) 
    expect(res).not_to be nil

    vp7 = Ccrypto::AlgoFactory.engine(Ccrypto::PKCS7Config.new)
    vres = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        true
      when :attached_data
        expect(v == data.to_java.getBytes).to be true
      end
    end
    expect(vres).to be true

  end

  it 'sign and verify detached signature' do
    
    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new

    prof.owner_name = "Simmon"
    prof.org = "Agent"

    prof.org_unit = ["Sara","id=A119"]
    prof.dns_name = "https://agent.com"
    prof.email = "simmon@agent.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    cert = fact.generate(kp.private_key)


    conf = Ccrypto::PKCS7Config.new
    conf.private_key = kp.private_key
    conf.signerCert = cert

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil

    data = "testging 28282828"*128
    res = p7.sign(data) do |k,v|
      case k
      when :detached_sign
        true
      end
    end
    expect(res).not_to be nil

    vp7 = Ccrypto::AlgoFactory.engine(Ccrypto::PKCS7Config.new)
    # scenario 1: Application accepted cert, data correct
    vres = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        true
      when :signed_data
        data
      end
    end
    expect(vres).to be true

    # scenario 2: Application accepted cert, data wrong
    vres2 = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        true
      when :signed_data
        "obviously wrong data"
      end
    end
    expect(vres2).to be false

    # scenario 3: Application rejected cert. Data not needed
    vres3 = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        false
      end
    end
    expect(vres3).to be false

    # scenario 4: Application no checking on cert. Data correct.
    vres4 = vp7.verify(res) do |k,v|
      case k
      when :signed_data
        data
      end
    end
    expect(vres4).to be true

    # scenario 5: Application no checking on cert. Data garbage.
    vres5 = vp7.verify(res) do |k,v|
      case k
      when :signed_data
        "whatever you say"
      end
    end
    expect(vres5).to be false

  end

  it 'encrypt and decrypt PKCS7 envelope with RSA keypair' do
  
    # PKCS7 only support RSA keypair and not ECC keypair
    rsa = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
    kp = rsa.generate_keypair

    prof = Ccrypto::X509::CertProfile.new

    prof.owner_name = "Simmon RSA"
    prof.org = "Agent"

    prof.org_unit = ["Sara","id=A119"]
    prof.dns_name = "https://agent.com"
    prof.email = "simmon@agent.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    cert = fact.generate(kp.private_key)

    conf = Ccrypto::PKCS7Config.new
    conf.add_recipient_cert(cert)

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil 

    data = "testing "*102400
    enc = p7.encrypt(data)
    expect(enc).not_to be nil

    dconf = Ccrypto::PKCS7Config.new
    dconf.private_key = kp.private_key
    dconf.certForDecryption = cert
    dp7 = Ccrypto::AlgoFactory.engine(dconf)
    dec = dp7.decrypt(enc)
    expect(dec).not_to be nil
    expect(dec == data.to_java.getBytes).to be true

    ## On Ruby-3.0.2
    ## AES-256-CTR : error setting cipher
    ## AES-256-OCB : error setting cipher
    ## BF-CFB      : error setting cipher
    ## BF-OFB      : error setting cipher
    ## CHACHA20-POLY1305 : error setting cipher
    ## AES-256-GCM : malloc failure
    ## AES-256-CCM : malloc failure
    ## AES-256-XTS : malloc failure

    #cipher = [
    #  Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 128, mode: :cbc }),
    #  Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :cbc }),

    #  Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 128, mode: :ccm }),
    #  Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :ccm }),
    #
    #  # error...
    #  #Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :ctr }),
    #  #Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :cfb }),
    #  #Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :cfb }),

    #  #Ccrypto::DirectCipherConfig.new({ algo: :chacha20, keysize: 256, mode: :poly1305 }),

    #  Ccrypto::DirectCipherConfig.new({ algo: :camellia, keysize: 256, mode: :cbc, padding: :pkcs5 }),

    #  Ccrypto::DirectCipherConfig.new({ algo: :seed, keysize: 256, mode: :cbc, padding: :pkcs5 }),
    #]

    ce = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
    ciphers = [
      ce.get_cipher(:aes, 128, :cbc).first,
      ce.get_cipher(:aes, 256, :cbc).first,
      ce.get_cipher(:aes, 128, :ccm).first,
      ce.get_cipher(:aes, 256, :ccm).first,
      ce.get_cipher(:camellia, 256, :cbc).first,
      ce.get_cipher(:seed, 128, :cbc).first,
    ]
    ciphers.each do |c|
      raise "Cipher is NULL!" if c.nil?

      enc2 = p7.encrypt(data) do |k|
        case k
        when :cipher
          c
        end
      end

      dec2 = dp7.decrypt(enc2)
      expect(dec2).not_to be nil
      expect(dec2 == data.to_java.getBytes).to be true

    end

  end

end
