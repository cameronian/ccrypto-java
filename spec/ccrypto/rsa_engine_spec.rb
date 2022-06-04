

RSpec.describe "RSA Engine Spec for Java" do

  it 'generates RSA keypair' do

    require 'ccrypto/java'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig)
    expect(ecc != nil).to be true

    kp = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new).generate_keypair
    expect(kp != nil).to be true
    expect(kp.is_a?(Ccrypto::KeyBundle)).to be true

  end

  it 'encodes and decodes public key correctly' do
    ec = Ccrypto::RSAConfig.new
    ee = Ccrypto::AlgoFactory.engine(ec)

    ek = ee.generate_keypair

    rpekb = ek.public_key.to_bin 
    rpek = ek.public_key.class.to_key(rpekb)

    expect(rpek.equal?(rpekb))

  end

  #it 'write private key to PEM and read it back' do
  #  
  #  ecc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new)

  #  ecKey = ecc.generate_keypair

  #  res = ecKey.to_storage(:pem)
  #  p res

  #end

  it 'sign & verify data with RSA keypair' do

    conf = Ccrypto::RSAConfig.new(2048)
    kpf = Ccrypto::AlgoFactory.engine(conf)
    kp = kpf.generate_keypair

    conf.private_key = kp.private_key
    data_to_be_signed = "testing 123" * 128
    res = kpf.sign(data_to_be_signed)
    expect(res).not_to be nil

    expect {
      kpf.sign(data_to_be_signed) do |k|
        case k
        when :sign_hash
          "unknown"
        end
      end
    }.to raise_exception(Ccrypto::KeypairEngineException)

    vres = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig).verify(kp.public_key, data_to_be_signed, res)
    expect(vres).to be true

    expect(Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig).verify(kp.public_key, data_to_be_signed, res) do |k|
      case k
      when :pss_mode
        true
      end
    end).to be false

    res2 = kpf.sign(data_to_be_signed) do |key|
      case key
      when :pss_mode
        true
      end
    end
    expect(res2).not_to be nil

    vres2 = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig).verify(kp.public_key, data_to_be_signed, res2) do |k|
      case k
      when :pss_mode
        true
      end
    end
    expect(vres2).to be true
    
  end

  it 'encrypt & decrypt data with RSA keypair, default OAEP mode' do

    conf = Ccrypto::RSAConfig.new(2048)
    kpf = Ccrypto::AlgoFactory.engine(conf)
    kp = kpf.generate_keypair

    comp = Ccrypto::UtilFactory.instance(:compare)

    conf.private_key = kp.private_key

    # this is the max for oaep padding or it will hit data too large for keysize error
    # formula = (keysize in byte) - 42
    # 2048 key = (2048/8) - 42 = 256 - 42 = 214 bytes
    #
    # 8 * 26 = 208 + 6 = 214 bytes == 1712 bits. 
    # 2048 bits key size means 336 bits/42 bytes is for padding
    data_to_be_encrypted = ("testing " * 23)
    data_to_be_encrypted = "#{data_to_be_encrypted}123456"
    #data_to_be_encrypted = ("testing " * 26)
    #data_to_be_encrypted = "#{data_to_be_encrypted}123456"

    puts "feeding in data size : #{data_to_be_encrypted.length} in bytes (max #{(2048/8)-42} bytes)"

    sRsaEng = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig)
    enc = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted) do |k,v|
      case k
      when :max_data_size
        puts "max block size : #{v} bytes"
      end
    end
    expect(enc).not_to be nil

    plain = kpf.decrypt(enc)
    expect(plain).not_to be nil
    expect(comp.is_equal?(plain, data_to_be_encrypted)).to be true

    # pkcs1 padding
    # max input size = 240 + 5 = 245 bytes === 1960 bits
    # padding is 11 bytes
    data_to_be_encrypted = "testing "*30
    data_to_be_encrypted = "#{data_to_be_encrypted}12345"
    enc2 = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted) do |k|
      case k
      when :padding
        :pkcs1
      end
    end
    expect(enc2).not_to be nil

    plain2 = kpf.decrypt(enc2) do |k|
      case k
      when :padding
        :pkcs1
      end
    end
    expect(plain2).not_to be nil
    expect(comp.is_equal?(plain2, data_to_be_encrypted)).to be true

    # no padding
    # Full key size 2048 bits == 256 bytes = 8*32 bytes
    data_to_be_encrypted = "testing "*32
    enc3 = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted) do |k|
      case k
      when :padding
        :no_padding
      end
    end
    expect(enc3).not_to be nil

    plain3 = kpf.decrypt(enc3) do |k|
      case k
      when :padding
        :no_padding
      end
    end
    expect(plain3).not_to be nil
    expect(comp.is_equal?(plain3, data_to_be_encrypted)).to be true

  end


end
