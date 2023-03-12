
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    class X25519PublicKey < Ccrypto::X25519PublicKey
      include DataConversion

      def to_bin
        res = @native_pubKey.encoded 
        #puts "to_bion : #{to_hex(res)}"
        res
      end

      #def to_pem
      #  out = java.io.StringWriter.new
      #  pem = org.bouncycastle.openssl.jcajce.JcaPEMWriter.new(out)
      #  pem.write_object(@native_pubKey)
      #  pem.flush
      #  pem.close
      #  out.toString
      #end

    end # X25519PublicKey

    class X25519PrivateKey < Ccrypto::X25519PrivateKey

      def to_bin
        @native_privKey.encoded  
      end

      #def to_pem
      #  out = java.io.StringWriter.new
      #  pem = org.bouncycastle.openssl.jcajce.JcaPEMWriter.new(out)
      #  pem.write_object(@native_privKey)
      #  pem.flush
      #  pem.close
      #  out.toString
      #end

    end # X25519PrivateKey

    class X25519KeyBundle
      include Ccrypto::ED25519KeyBundle
      include Ccrypto::X25519KeyBundle

      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper
      teLogger_tag :x25519_kb_j

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = X25519PublicKey.new(@nativeKeypair.getPublic)
        end
        @pubKey
      end

      def private_key
        X25519PrivateKey.new(@nativeKeypair.getPrivate) 
      end

      def derive_dh_shared_secret(pubKey, &block)
        
        JCEProvider.instance.add_bc_provider

        ka = javax.crypto.KeyAgreement.getInstance("X25519",JCEProvider::BCProv.name)
        ka.init(@nativeKeypair.getPrivate)

        case pubKey
        when X25519PublicKey
          uPubKey = pubKey.native_pubKey
        else 
          raise KeypairEngineException, "Unsupported public key type '#{pubKey.class}'"
        end

        ka.doPhase(uPubKey, true)
        ka.generateSecret()

      end

      ## should be under keybundle_store but not sure how to do this
      def to_storage(eng = :ccrypto, &block)
        case eng
        when :ccrypto
          res = {  }

          rawPrivate = false
          rawPublic = false
          if block
            rawPrivate = block.call(:export_raw_private_key)
            rawPublic = block.call(:export_raw_public_key)
          end

          res[:private] = private_key.to_bin
          if rawPrivate == true
            # 5th Sept 2022 - untested code
            res[:private] = org.bouncycastle.crypto.params.X25519PrivateKeyParameters.new(res[:private],0).encoded 
            res[:raw_private] = true
          end

          res[:public] = public_key.to_bin
          if rawPublic == true
            # 5th Sept 2022 - untested code
            res[:public] = org.bouncycastle.crypto.params.X25519PublicKeyParameters.new(res[:public],0).encoded 
            res[:raw_public] = true
          end

          res
        else
          raise KeypairEngineException, "Unsupported storage type '#{eng}'"
        end
      end

      def self.from_storage(bin)
        case bin
        when Hash
          res = {  }
          JCEProvider.instance.add_bc_provider

          kf = java.security.KeyFactory.getInstance("X25519", JCEProvider::BCProv.name)

          if not_empty?(bin[:private])
            # raw_private = true means the given private key is in its raw data form
            # 5th Sept 22 - Not tested not sure how to generate raw key
            if bin[:raw_private] == true
              # 5th Sept 2022 - untested code
              info = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.new(org.bouncycastle.asn1.x509.AlgorithmIdentifier.new(org.bouncycastle.asn1.edec.EdECObjectIdentifiers::id_X25519), org.bouncycastle.asn1.DEROctetString.new(bin[:private]))

              spec = java.security.spec.PKCS8EncodedKeySpec.new(info.encoded)
            else
              spec = java.security.spec.PKCS8EncodedKeySpec.new(bin[:private])
            end

            res[:private] = X25519PrivateKey.new(kf.generatePrivate(spec))

            #res[:private] = X25519PrivateKey.new(org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters.new(bin[:private],0))
          end

          if not_empty?(bin[:public])
            if bin[:raw_public] == true
              # 5th Sept 2022 - untested code
              #pubRaw = org.bouncycastle.crypto.params.Ed25519PublicKeyParameters.new(bin[:public],0).encoded
              pubRaw = bin[:public]
              info = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.new(org.bouncycastle.asn1.x509.AlgorithmIdentifier.new(org.bouncycastle.asn1.edec.EdECObjectIdentifiers::id_X25519), bin[:public])

              spec = java.security.spec.X509EncodedKeySpec.new(info.encoded)
            else
              spec = java.security.spec.X509EncodedKeySpec.new(bin[:public])
            end

            res[:public] = X25519PublicKey.new(kf.generatePublic(spec))
          end

          res[:keypair] = X25519KeyBundle.new(java.security.KeyPair.new(res[:public].native_pubKey, res[:private].native_privKey)) if not_empty?(res[:public]) and not_empty?(res[:private])

          res

        else
          raise KeypairEngineException, "No sure how to handle storage input '#{bin.class}'"
        end
      end

    end # X25519KeyBundle

    class X25519Engine
      include TR::CondUtils
      include DataConversion
      
      include TeLogger::TeLogHelper
      teLogger_tag :x25519_eng_j

      def initialize(*args, &block)
        @config = args.first
      end

      def generate_keypair(&block)
       
        JCEProvider.instance.add_bc_provider
        kg = java.security.KeyPairGenerator.getInstance("X25519", JCEProvider::BCProv.name)
        kg.java_send(:initialize, [java.security.spec.AlgorithmParameterSpec], org.bouncycastle.jcajce.spec.XDHParameterSpec.new(org.bouncycastle.jcajce.spec.XDHParameterSpec::X25519))
        X25519KeyBundle.new(kg.generateKeyPair)

      end


    end

  end
end
