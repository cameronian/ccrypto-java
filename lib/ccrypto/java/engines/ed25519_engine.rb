
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    class ED25519PublicKey < Ccrypto::ED25519PublicKey

    end

    class ED25519KeyBundle
      include Ccrypto::ED25519KeyBundle
      include Ccrypto::X25519KeyBundle

      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper
      teLogger_tag :ed25519_kb_j

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = ED25519PublicKey.new(@nativeKeypair.getPublic)
        end
        @pubKey
      end

      def private_key
        ED25519PrivateKey.new(@nativeKeypair.getPrivate) 
      end

      def derive_dh_shared_secret(pubKey, &block)
        
        JCEProvider.instance.add_bc_provider

        ka = javax.crypto.KeyAgreement.getInstance("X25519",JCEProvider::BCProv.name)
        ka.init(@nativeKeypair.getPrivate)
        ka.doPhase(pubKey, true)
        ka.generateSecret()

      end

    end # ED25519KeyBundle

    class ED25519Engine
      include TR::CondUtils
      include DataConversion
      
      include TeLogger::TeLogHelper
      teLogger_tag :ed25519_eng_j

      def initialize(*args, &block)
        @config = args.first
      end

      def generate_keypair(&block)
        
        JCEProvider.instance.add_bc_provider
        kg = java.security.KeyPairGenerator.getInstance("ED25519", JCEProvider::BCProv.name)
        ED25519KeyBundle.new(kg.generateKeyPair)

      end

      def sign(val, &block)
        
        sign = java.security.Signature.getInstance("EdDSA", JCEProvider::BCProv.name)

        case @config.keypair
        when ED25519KeyBundle
          privKey = @config.keypair.nativeKeypair.getPrivate
        else
          raise KeypairEngineException,"Unsupported keypair type '#{@config.keypair.class}'"
        end

        sign.initSign(privKey)

        case val
        when java.io.InputStream
          buf = Java::byte[102400].new
          while((read = val.read(buf, 0, buf.length)) != nil)
            sign.update(buf,0,read)
          end
        else
          sign.update(to_java_bytes(val))
        end

        sign.sign

      end

      def self.verify(pubKey, val, sign)

        ver = java.security.Signature.getInstance("EdDSA", JCEProvider::BCProv.name)

        case pubKey
        when ED25519PublicKey
          uPubKey = pubKey.native_pubKey
        else
          raise KeypairEngineException, "Unsupported public key type '#{pubKey.class}'"
        end
        
        ver.initVerify(uPubKey)

        case val
        when java.io.InputStream
          buf = Java::byte[102400].new
          while((read = val.read(buf, 0 ,buf.length)) != nil)
            ver.update(buf,0, read)
          end
        else
          ver.update(to_java_bytes(val))
        end

        ver.verify(to_java_bytes(sign))

      end


    end

  end
end
