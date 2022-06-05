
require_relative '../data_conversion'

require_relative '../keybundle_store/pkcs12'

module Ccrypto
  module Java

    class ECCPublicKey < Ccrypto::ECCPublicKey
      def to_bin
        @native_pubKey.encoded
      end

      def encoded
        to_bin
      end

      def self.to_key(bin)
        pubKey = java.security.KeyFactory.getInstance("ECDSA", "BC").generatePublic(java.security.spec.X509EncodedKeySpec.new(bin))
        ECCPublicKey.new(pubKey)
      end

    end

    class ECCKeyBundle
      include Ccrypto::ECCKeyBundle
      include TR::CondUtils
      include DataConversion

      include PKCS12

      include TeLogger::TeLogHelper

      teLogger_tag :j_ecc_keybundle

      def initialize(kp)
        @keypair = kp
      end

      def native_keypair
        @keypair
      end

      def public_key
        if @pubKey.nil?
          @pubKey = ECCPublicKey.new(@keypair.public)
        end
        @pubKey
      end

      def private_key
        ECCPrivateKey.new(@keypair.private)
      end

      def derive_dh_shared_secret(pubKey, &block)
        ka = javax.crypto.KeyAgreement.getInstance("ECDH") 
        ka.init(@keypair.private)
        ka.doPhase(pubKey.native_pubKey, true)
        if block
          keyType = block.call(:keytype)
        else
          keyType = "AES"
        end
        keyType = "AES" if is_empty?(keyType)
        teLogger.debug "Generate secret key type #{keyType}"
        ka.generateSecret(keyType).encoded
      end

      def is_public_key_equal?(pubKey)
        @keypair.public.encoded == pubKey.encoded
      end

      def to_storage(type, &block)
        
        case type
        when :p12, :pkcs12
          to_pkcs12 do |key|
            case key
            when :keypair
              @keypair
            else
              block.call(key) if block
            end
          end

        when :jks
          to_pkcs12 do |key|
            case key
            when :storeType
              "JKS"
            when :keypair
              @keypair
            else
              block.call(key) if key
            end
          end
         
        when :pem

          header = "-----BEGIN EC PRIVATE KEY-----\n"
          footer = "\n-----END EC PRIVATE KEY-----"

          out = StringIO.new
          out.write header
          out.write to_b64_mime(@keypair.private.encoded)
          out.write footer

          out.string

        else
          raise KeypairEngineException, "Unknown storage type #{type}"
        end

      end

      def self.from_storage(bin, &block)
       
        if is_pem?(bin)
        else
          from_pkcs12(bin, &block)
        end

      end

      def self.is_pem?(bin)
        begin
          (bin =~ /BEGIN/) != nil
        rescue ArgumentError => ex
          false
        end
      end

      def equal?(kp)
        case kp
        when Ccrypto::ECCKeyBundle
          @keypair.encoded == kp.private.encoded
        else
          false
        end
      end

      def method_missing(mtd, *args, &block)
        teLogger.debug "Sending to native #{mtd}"
        @keypair.send(mtd, *args, &block)
      end

      def respond_to_missing?(mtd, incPriv = false)
        teLogger.debug "Respond to missing #{mtd}"
        @keypair.respond_to?(mtd)
      end

    end

    class ECCEngine
      include TR::CondUtils
      include DataConversion
      
      include TeLogger::TeLogHelper
      teLogger_tag :j_ecc

      def self.supported_curves
        if @curves.nil?
          @curves = org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames.sort.to_a.map { |c| Ccrypto::ECCConfig.new(c) }
        end
        @curves
      end

      def initialize(*args,&block)
        @config = args.first
        raise KeypairEngineException, "1st parameter must be a #{Ccrypto::KeypairConfig.class} object" if not @config.is_a?(Ccrypto::KeypairConfig)
      end

      def generate_keypair(&block)

        algoName = "ECDSA"
        prov = Ccrypto::Java::JCEProvider::BCProv
        randomEngine = java.security.SecureRandom.new
        if block
          # it is the responsibility of caller program to add the 
          # provider into the provider list.
          # Here provider string shall be used
          uprov = block.call(:jce_provider)
          prov = uprov if not is_empty?(uprov) 

          uAlgo = block.call(:jce_algo_name)
          algoName = uAlgo if not is_empty?(uAlgo)

          uRandEng = block.call(:random_engine)
          randomEngine = uRandEng if not uRandEng.nil?
        end

        kpg = java.security.KeyPairGenerator.getInstance(algoName, prov)
        #kpg.java_send :initialize, [java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom], java.security.spec.ECGenParameterSpec.new(curve), java.security.SecureRandom.new
        kpg.java_send :initialize, [java.security.spec.AlgorithmParameterSpec, randomEngine.class], java.security.spec.ECGenParameterSpec.new(@config.curve), randomEngine
        kp = kpg.generate_key_pair

        kb = ECCKeyBundle.new(kp)
        kb

      end

      def sign(val, &block)
        raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        raise KeypairEngineException, "ECC keypair is required. Given #{@config.keypair}" if not @config.keypair.is_a?(ECCKeyBundle)
        kp = @config.keypair

        sign = java.security.Signature.getInstance("SHA256WithECDSA")
        sign.initSign(kp.private_key)
        teLogger.debug "Signing data : #{val}" 
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
        ver = java.security.Signature.getInstance("SHA256WithECDSA")
        ver.initVerify(pubKey)
        teLogger.debug "Verifing data : #{val}"
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
