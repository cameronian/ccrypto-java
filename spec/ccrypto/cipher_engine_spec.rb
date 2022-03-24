

RSpec.describe "Cipher engine spec for Java" do

  it 'encrypt and decrypt using system returned value' do

    require 'ccrypto/java'

    #cipher = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
    #expect(cipher).not_to be nil

    #skippedAlgo = ["ELGAMAL/PKCS1","GOST3412-2015/CBC","GOST3412-2015/CFB","GOST3412-2015/CFB8","GOST3412-2015/CTR","GOST3412-2015/OFB","RSA/1","RSA/2","RSA/ISO9796-1","RSA/OAEP","RSA/PKCS1","RSA/RAW"]

    #cipher.supported_ciphers.each do |c|
    #  
    #  next if skippedAlgo.include?(c)
    #  p c
    #  cc = Ccrypto::AlgoFactory.engine(Ccrypto::DirectCipherConfig.new(c))
    #  expect(cc).not_to be nil

    #  #iv = cc.random_iv
    #  #key = cc.random_key
    #  #cc.encrypt

    #  #data = "password"
    #  ## xts mode failed here
    #  #res = cc.update(data) + cc.final

    #  #cc.reset

    #  #cc.iv = iv
    #  #cc.key = key
    #  #cc.decrypt

    #  #if ((c =~ /ccm/) == nil) and (c =~ /CCM/) == nil
    #  #  dec = cc.update(res) + cc.final
    #  #  comp = Ccrypto::UtilFactory.instance(:compare)
    #  #  expect(comp.is_equal?(dec,data)).to be true
    #  #end

    #end
    
  end

  it 'encrypt and decrypt using user input' do
   
    require 'ccrypto/java'

    testkey = [
      Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 128, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :gcm, padding: :pkcs5, auth_data: "Header to be used for gcm aad" }),
     
      Ccrypto::DirectCipherConfig.new({ algo: :chacha20, keysize: 256, mode: :poly1305 }),

      Ccrypto::DirectCipherConfig.new({ algo: :camellia, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :camellia, keysize: 256, mode: :ctr, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :aria, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :aria, keysize: 256, mode: :ctr, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :twofish, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :twofish, keysize: 256, mode: :ctr, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :seed, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :seed, keysize: 256, mode: :ctr, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :sm4, keysize: 128, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :sm4, keysize: 128, mode: :ctr, padding: :pkcs5 }),

    ]

    testkey.each do |hc|

      spec = hc.clone
      spec.cipherOps = :encrypt

      cc = Ccrypto::AlgoFactory.engine(spec)
      expect(cc).not_to be nil

      data = "password"

      enc = cc.final(data)

      spec.cipherOps = :decrypt
      ccd = Ccrypto::AlgoFactory.engine(spec)

      dec = ccd.final(enc)

      expect(String.from_java_bytes(dec) == data).to be true
      
    end

  end

end
