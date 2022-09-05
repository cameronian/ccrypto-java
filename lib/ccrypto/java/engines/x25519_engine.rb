
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    class X25519PublicKey < Ccrypto::ED25519PublicKey

    end

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
