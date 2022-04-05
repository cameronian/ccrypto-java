

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
        @keypair.private
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
        logger.debug "Generate secret key type #{keyType}"
        ka.generateSecret(keyType).encoded
      end

      def is_public_key_equal?(pubKey)
        @keypair.public.encoded == pubKey.encoded
      end

      def to_storage(type, &block)
        
        case type
        when :p12, :pkcs12
          raise KeypairEngineException, "block is required" if not block
          prof = block.call(:jce_provider)
          if not_empty?(prof)
            ks = java.security.KeyStore.getInstance("PKCS12", prof)
          else
            ks = java.security.KeyStore.getInstance("PKCS12")
          end

          ks.load(nil,nil)

          gcert = block.call(:cert)
          raise KeypairEngineException, "PKCS12 requires the X.509 certificate" if gcert.nil? or is_empty?(gcert)

          ca = block.call(:certchain) || [cert]
          ca = ca.unshift(gcert) if not ca.first.equal?(gcert)
          ca = ca.collect { |c|
            Ccrypto::X509Cert.to_java_cert(c) 
          }

          pass = block.call(:p12_pass)
          name = block.call(:p12_name) || "Ccrypto ECC"

          raise KeypairEngineException, "Password must be available" if is_empty?(pass)

          ks.setKeyEntry(name, @keypair.private, pass.to_java.toCharArray, ca.to_java(java.security.cert.Certificate))

          baos = java.io.ByteArrayOutputStream.new
          ks.store(baos, pass.to_java.toCharArray)
          
          baos.toByteArray

        when :jks
          raise KeypairEngineException, "block is required" if not block
          prof = block.call(:jce_provider)
          if not_empty?(prof)
            ks = java.security.KeyStore.getInstance("JKS", prof)
          else
            ks = java.security.KeyStore.getInstance("JKS")
          end

          ks.load(nil,nil)

          gcert = block.call(:cert)
          raise KeypairEngineException, "JKS requires the X.509 certificate" if gcert.nil? or is_empty?(gcert)

          ca = block.call(:certchain) || [cert]
          ca = ca.unshift(gcert) if not ca.first.equal?(gcert)
          ca = ca.collect { |c|
            Ccrypto::X509Cert.to_java_cert(c) 
          }

          pass = block.call(:jks_pass)
          name = block.call(:jks_name) || "Ccrypto ECC"

          raise KeypairEngineException, "Password must be available" if is_empty?(pass)

          ks.setKeyEntry(name, @keypair.private, pass.to_java.toCharArray, ca.to_java(java.security.cert.Certificate))

          baos = java.io.ByteArrayOutputStream.new
          ks.store(baos, pass.to_java.toCharArray)
          
          baos.toByteArray
          
        when :pem


        else
          raise KeypairEngineException, "Unknown storage type #{type}"
        end

      end

      def self.from_storage(bin, &block)
       
        if is_pem?(bin)
        else
          raise KeypairEngineException, "block is required" if not block

          prof = block.call(:jce_provider)
          if not_empty?(prof)
            ks = java.security.KeyStore.getInstance("PKCS12", prof)
          else
            ks = java.security.KeyStore.getInstance("PKCS12")
          end

          pass = block.call(:p12_pass) || block.call(:jks_pass)
          name = block.call(:p12_name) || block.call(:jks_name)

          case bin
          when String
            bbin = bin.to_java_bytes
          when ::Java::byte[]
            bbin = bin
          else
            raise KeypairEngineException, "Java byte array is expected. Given #{bin.class}"
          end

          ks.load(java.io.ByteArrayInputStream.new(bbin),pass.to_java.toCharArray)

          name = ks.aliases.to_a.first if is_empty?(name)

          userCert = Ccrypto::X509Cert.new(ks.getCertificate(name))
          chain = ks.get_certificate_chain(name).collect { |c| Ccrypto::X509Cert.new(c) }
          chain = chain.delete_if { |c| c.equal?(userCert) }

          [Ccrypto::Java::ECCKeyBundle.new(ks.getKey(name, pass.to_java.toCharArray)), userCert, chain]

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

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecckeybundle
        end
        @logger
      end
      def logger
        self.class.logger
      end

      def method_missing(mtd, *args, &block)
        logger.debug "Sending to native #{mtd}"
        @keypair.send(mtd, *args, &block)
      end

      def respond_to_missing?(mtd, incPriv = false)
        logger.debug "Respond to missing #{mtd}"
        @keypair.respond_to?(mtd)
      end

    end

    class ECCEngine
      include TR::CondUtils

      def self.supported_curves
        if @curves.nil?
          @curves = org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames.to_a.map { |c| Ccrypto::ECCConfig.new(c) }
        end
        @curves
      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecc_eng
        end
        @logger
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

      def sign(val)
        raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        raise KeypairEngineException, "ECC keypair is required. Given #{@config.keypair}" if not @config.keypair.is_a?(ECCKeyBundle)
        kp = @config.keypair

        sign = java.security.Signature.getInstance("SHA256WithECDSA")
        sign.initSign(kp.private_key)
        logger.debug "Signing data : #{val}" 
        sign.update(val)
        sign.sign
      end

      def self.verify(pubKey, val, sign)
        ver = java.security.Signature.getInstance("SHA256WithECDSA")
        ver.initVerify(pubKey)
        logger.debug "Verifing data : #{val}"
        ver.update(val)
        ver.verify(sign)
      end

      def logger
        self.class.logger
      end

    end
  end
end
