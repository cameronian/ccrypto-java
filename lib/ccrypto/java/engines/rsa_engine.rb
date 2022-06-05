
require_relative '../data_conversion'
require_relative '../keybundle_store/pkcs12'
#require_relative '../keybundle_store/pem_store'

module Ccrypto
  module Java
    
    class RSAPublicKey < Ccrypto::RSAPublicKey

      def to_bin
        @native_pubKey.encoded
      end

      def self.to_key(bin)
        pubKey = java.security.KeyFactory.getInstance("RSA", "BC").generatePublic(java.security.spec.X509EncodedKeySpec.new(bin))
        RSAPublicKey.new(pubKey)
      end

      def method_missing(mtd, *args, &block)
        @native_pubKey.send(mtd, *args, &block)
      end

    end # RSAPublicKey

    class RSAKeyBundle 
      include Ccrypto::RSAKeyBundle
      include TR::CondUtils

      include PKCS12
      #include PEMStore

      include TeLogger::TeLogHelper

      teLogger_tag :j_rsa_keybundle

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = RSAPublicKey.new(@nativeKeypair.public)
        end
        @pubKey
      end

      def private_key
        if @privKey.nil?
          @privKey = RSAPrivateKey.new(@nativeKeypair.private)
        end
        @privKey
      end

      def to_storage(type, &block)
        
        case type
        when :p12, :pkcs12
          to_pkcs12 do |key|
            case key
            when :keypair
              @nativeKeypair
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
              @nativeKeypair
            else
              block.call(key) if block
            end
          end
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
        when Ccrypto::RSAKeyBundle
          @nativeKeypair.encoded == kp.private.encoded
        else
          false
        end
      end

      def method_missing(mtd, *args, &block)
        teLogger.debug "Sending to native #{mtd}"
        @nativeKeypair.send(mtd, *args, &block)
      end

      def respond_to_missing?(mtd, incPriv = false)
        teLogger.debug "Respond to missing #{mtd}"
        @nativeKeypair.respond_to?(mtd)
      end

    end # RSAKeyBundle

    class RSAEngine
      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper

      teLogger_tag :j_rsa

      def initialize(*args, &block)
        @config = args.first
        raise KeypairEngineException, "1st parameter must be a #{Ccrypto::KeypairConfig.class} object" if not @config.is_a?(Ccrypto::KeypairConfig)

      end

      def generate_keypair(&block)
        prov = Ccrypto::Java::JCEProvider::DEFProv
        if block
          prov = block.call(:jce_provider)
        end
        prov = Ccrypto::Java::JCEProvider::DEFProv if is_empty?(prov)

        kpg = java.security.KeyPairGenerator.getInstance("RSA", prov)
        kpg.java_send :initialize, [::Java::int], @config.keysize
        kp = kpg.generate_key_pair

        RSAKeyBundle.new(kp)
      end

      def sign(val, &block)
        if block
          pss = block.call(:pss_mode)
          pss = false if is_empty?(pss) or not is_bool?(pss)

          if pss
            sign_pss(val, &block) 
          else
            sign_typical(val, &block)
          end
        else
          sign_typical(val,&block)
        end
      end

      def self.verify(pubKey, val, ssign, &block)
        if block
          pss = block.call(:pss_mode)
          pss = false if is_empty?(pss) or not is_bool?(pss)

          if pss
            verify_pss(pubKey, val, ssign, &block)
          else
            verify_typical()
          end

        else
          verify_typical(pubKey, val, ssign, &block)
        end
      end

      def self.encrypt(pubKey, val, &block)

        raise KeypairEngineException, "Public key is required" if is_empty?(pubKey)

        prov = nil
        if block
          prov = block.call(:jce_provider)
          padding = block.call(:padding)
          digAlgo = block.call(:oaep_digest)
          mode = block.call(:mode)
        end
        padding = :oaep if is_empty?(padding)
        digAlgo = :sha256 if is_empty?(digAlgo)
        mode = :none if is_empty?(mode)

        case padding
        when :pkcs1
          teLogger.owarn "RSA with PKCS1Padding mode is vulnerable. :oeap mode recommended"
          transform = "RSA/#{mode.to_s.upcase}/PKCS1Padding"

        when :oaep
          transform = "RSA/None/OAEPWith#{digAlgo.to_s.upcase}AndMGF1Padding"

          # standardize BC vs Oracle defaults
          # https://stackoverflow.com/a/50299291/3625825
          case digAlgo
          when :sha1
            oaepSpec = javax.crypto.spec.OAEPParameterSpec.new(digAlgo.to_s.upcase, "MGF1", java.security.spec.MGF1ParameterSpec::SHA1, javax.crypto.spec.PSource::PSpecified::DEFAULT)
          when :sha224
            oaepSpec = javax.crypto.spec.OAEPParameterSpec.new(digAlgo.to_s.upcase, "MGF1", java.security.spec.MGF1ParameterSpec::SHA224, javax.crypto.spec.PSource::PSpecified::DEFAULT)
          when :sha256
            oaepSpec = javax.crypto.spec.OAEPParameterSpec.new(digAlgo.to_s.upcase, "MGF1", java.security.spec.MGF1ParameterSpec::SHA256, javax.crypto.spec.PSource::PSpecified::DEFAULT)
          when :sha384
            oaepSpec = javax.crypto.spec.OAEPParameterSpec.new(digAlgo.to_s.upcase, "MGF1", java.security.spec.MGF1ParameterSpec::SHA384, javax.crypto.spec.PSource::PSpecified::DEFAULT)
          when :sha512
            oaepSpec = javax.crypto.spec.OAEPParameterSpec.new(digAlgo.to_s.upcase, "MGF1", java.security.spec.MGF1ParameterSpec::SHA512, javax.crypto.spec.PSource::PSpecified::DEFAULT)
          else
            raise KeypairEngineException, "Unknown #{digAlgo} digest for OAEP mode"
          end

        when :no_padding
          teLogger.owarn "RSA with NoPadding mode is vulnerable. :oeap mode recommended"
          transform = "RSA/#{mode.to_s.upcase}/NoPadding"

        else
          raise KeypairEngineException, "Padding requires either :pkcs1, :no_padding or :oaep. Default is :oaep"
        end

        begin

          if prov.nil?
            teLogger.debug "Encrypt transformation #{transform} with nil provider"
            cipher = javax.crypto.Cipher.getInstance(transform)
          else
            teLogger.debug "Encrypt transformation #{transform} with provider #{prov.is_a?(String) ? prov : prov.name}"
            cipher = javax.crypto.Cipher.getInstance(transform, prov)
          end


          if oaepSpec.nil?
            teLogger.debug "Init cipher with default parameter spec"
            cipher.init(javax.crypto.Cipher::ENCRYPT_MODE, pubKey.native_pubKey)
          else
            teLogger.debug "Init cipher with parameter spec #{oaepSpec}"
            cipher.init(javax.crypto.Cipher::ENCRYPT_MODE, pubKey.native_pubKey, oaepSpec)
          end

          if block
            # this is share with caller to ensure input data should not be longer then this size
            block.call(:max_data_size, cipher.getBlockSize)
          end

          out = java.io.ByteArrayOutputStream.new
          case val
          when java.io.InputStream
            buf = ::Java::byte[102400].new
            while((read = val.read(buf, 0, buf.length)) != nil)
              out.write(cipher.update(buf, 0, read))
            end
          else
            inDat = to_java_bytes(val)
            teLogger.debug "Encrypting #{inDat.length} bytes"
            ed = cipher.update(inDat)
            out.write(ed) if not_empty?(ed)
          end

          last = cipher.doFinal
          out.write(last) if not_empty?(last)
          #out.write(cipher.doFinal)

          out.toByteArray

        rescue Exception => ex
          raise KeypairEngineException, ex
        end

      end

      def decrypt(enc, &block)

        raise KeypairEngineException, "Private key is required" if not @config.has_private_key?
        raise KeypairEngineException, "RSA private key is required. Given #{@config.private_key}" if not @config.private_key.is_a?(RSAPrivateKey)

        prov = nil
        if block
          prov = block.call(:jce_provider)
          padding = block.call(:padding)
          digAlgo = block.call(:oaep_digest)
          mode = block.call(:mode)
        end
        padding = :oaep if is_empty?(padding)
        digAlgo = :sha256 if is_empty?(digAlgo)
        mode = :none if is_empty?(mode)

        case padding
        when :pkcs1
          transform = "RSA/#{mode.to_s.upcase}/PKCS1Padding"
        when :oaep
          transform = "RSA/None/OAEPWith#{digAlgo.to_s.upcase}AndMGF1Padding"
        when :no_padding
          transform = "RSA/#{mode.to_s.upcase}/NoPadding"
        else
          raise KeypairEngineException, "Padding requires either :pkcs1, :no_padding or :oaep. Default is :oaep"
        end

        begin

          if prov.nil?
            cipher = javax.crypto.Cipher.getInstance(transform)
          else
            cipher = javax.crypto.Cipher.getInstance(transform, prov)
          end

          cipher.init(javax.crypto.Cipher::DECRYPT_MODE, @config.private_key.native_privKey)

          out = java.io.ByteArrayOutputStream.new
          case enc
          when java.io.InputStream
            buf = ::Java::byte[102400].new
            while((read = enc.read(buf, 0, buf.length)) != nil)
              out.write(cipher.update(buf,0, read))
            end
          else
            inDat = to_java_bytes(enc)
            teLogger.debug "Decrypting #{inDat.length} bytes"
            pd = cipher.update(inDat)
            out.write(pd) if not_empty?(pd)
          end

          last = cipher.doFinal
          out.write(last) if not_empty?(last)

          out.toByteArray

        rescue Exception => ex
          raise KeypairEngineException, ex
        end

      end


      ##############################################
      ## Private section
      ###
      private
      def sign_typical(val, &block)

        prov = block.call(:jce_provider) if block

        signHash = block.call(:sign_hash) if block
        signHash = :sha256 if is_empty?(signHash)

        signAlgo = "#{signHash.to_s.upcase}WithRSA"

        begin

          if is_empty?(prov)
            teLogger.debug "Provider is nil"
            sign = java.security.Signature.getInstance(signAlgo) 
          else
            teLogger.debug "Provider is '#{prov.name}'"
            sign = java.security.Signature.getInstance(signAlgo, prov) 
          end 

          teLogger.debug "Private key is #{@config.private_key.native_privKey}"
          sign.initSign(@config.private_key.native_privKey)

          algoSpec = block.call(:signAlgoSpec) if block

          if not_empty?(algoSpec) and algoSpec.is_a?(java.security.spec.AlgorithmParameterSpec)
            sign.setParameter(algoSpec)
            teLogger.debug "Sign Algo Parameter : '#{algoSpec}'"
          end

          case val
          when java.io.InputStream
            buf = ::Java::byte[102400].new
            while((read = val.read(buf, 0, buf.length)) != nil)
              sign.update(buf, 0, read)
            end
          else
            sign.update(to_java_bytes(val))
          end

          sign.sign

        rescue Exception => ex
          raise KeypairEngineException, ex
        end

      end

      def sign_pss(val, &block)
        
        raise KeypairEngineException, "Private key is required" if not @config.has_private_key?
        raise KeypairEngineException, "RSA private key is required." if not @config.private_key.is_a?(RSAPrivateKey)

        privKey = @config.private_key

        if block
          signHash = block.call(:sign_hash)
          mgf1Hash = block.call(:mgf1_hash)
          saltLen = block.call(:salt_length)
          prov = block.call(:jce_provider)
          trailer = block.call(:trailer_field)
        end

        mgf1Hash = :sha256 if is_empty?(mgf1Hash)
        # Comment under post https://stackoverflow.com/a/48854106/3625825
        # indicated 20 is the value when use with OpenSSL
        #saltLen = 20 if is_empty?(saltLen)
        saltLen = 32 if is_empty?(saltLen)
        signHash = "sha256" if is_empty?(signHash)
        # there is post on StackOverflow indicated to verify with OpenSSL
        # trailer = 0xBC
        #trailer = 0xBC if is_empty?(trailer)
        trailer = 1 if is_empty?(trailer)

        case mgf1Hash.to_sym
        when :sha1
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA1
        when :sha224
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA224
        when :sha256
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA256
        when :sha384
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA384
        when :sha512
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA512
        when :sha512_224
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA512_224
        when :sha512_256
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA512_256
        else
          raise KeypairEngineException, "Not supported mgf1Hash value #{mgf1Hash}. Supported value including: :sha1, :sha224, :sha256, :sha384, :sha512, :sha512_224 and :sha512_256"
        end

        if prov.nil?
          sign = java.security.Signature.getInstance("#{signHash.to_s.strip.upcase}WithRSA/PSS")
        else
          sign = java.security.Signature.getInstance("#{signHash.to_s.strip.upcase}WithRSA/PSS", prov)
        end

        sign.setParameter(java.security.spec.PSSParameterSpec.new(signHash.to_s.strip.upcase,"MGF1", mgf1Spec, saltLen, trailer))

        sign.initSign(privKey.native_privKey)

        case val
        when java.io.InputStream
          buf = ::Java::byte[102400].new
          while((read = val.read(buf, 0, buf.length)) != nil)
            sign.update(buf, 0, read)
          end
        else
          sign.update(to_java_bytes(val))
        end

        sign.sign

      end

      def self.verify_typical(pubKey, val, ssign, &block)

        #raise KeypairEngineException, "block is required" if not block

        prov = block.call(:jce_provider) if block

        signAlgo = block.call(:signAlgo) if block
        signAlgo = "SHA256WithRSA" if is_empty?(signAlgo)

        case pubKey.native_pubKey
        when java.security.cert.Certificate, java.security.PublicKey
          
          if is_empty?(prov)
            teLogger.debug "Provider is nil"
            sign = java.security.Signature.getInstance(signAlgo)
          else
            teLogger.debug "Provider is '#{prov.name}'"
            sign = java.security.Signature.getInstance(signAlgo, prov)
          end 

          sign.initVerify(pubKey.native_pubKey)

        else
          raise KeypairEngineException, "Unknown pubKey type #{pubKey}"
        end

        case val
        when java.io.InputStream
          buf = ::Java::byte[102400].new
          while((read = val.read(buf, 0, buf.length)) != nil)
            sign.update(buf, 0, read)
          end
        else
          sign.update(to_java_bytes(val))
        end

        sign.verify(to_java_bytes(ssign))     

      end

      def self.verify_pss(pubKey, val, ssign, &block)

        raise KeypairEngineException, "Public key is required" if pubKey.nil? 
        raise KeypairEngineException, "RSA public key is required. Given #{pubKey}" if not pubKey.is_a?(RSAPublicKey)

        if block
          signHash = block.call(:sign_hash)
          mgf1Hash = block.call(:mgf1_hash)
          saltLen = block.call(:salt_length)
          prov = block.call(:jce_provider)
          trailer = block.call(:trailer_field)
        end

        mgf1Hash = :sha256 if is_empty?(mgf1Hash)
        # Comment under post https://stackoverflow.com/a/48854106/3625825
        # indicated 20 is the value when use with OpenSSL
        #saltLen = 20 if is_empty?(saltLen)
        saltLen = 32 if is_empty?(saltLen)
        signHash = "sha256" if is_empty?(signHash)
        # there is post on StackOverflow indicated to verify with OpenSSL
        # trailer = 0xBC
        #trailer = 0xBC if is_empty?(trailer)
        trailer = 1 if is_empty?(trailer)

        case mgf1Hash.to_sym
        when :sha1
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA1
        when :sha224
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA224
        when :sha256
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA256
        when :sha384
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA384
        when :sha512
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA512
        when :sha512_224
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA512_224
        when :sha512_256
          mgf1Spec = java.security.spec.MGF1ParameterSpec::SHA512_256
        else
          raise KeypairEngineException, "Not supported mgf1Hash value #{mgf1Hash}. Supported value including: :sha1, :sha224, :sha256, :sha384, :sha512, :sha512_224 and :sha512_256"
        end

        if prov.nil?
          sign = java.security.Signature.getInstance("#{signHash.to_s.strip.upcase}WithRSA/PSS")
        else
          sign = java.security.Signature.getInstance("#{signHash.to_s.strip.upcase}WithRSA/PSS", prov)
        end

        sign.setParameter(java.security.spec.PSSParameterSpec.new(signHash.to_s.strip.upcase,"MGF1", mgf1Spec, saltLen, trailer))

        sign.initVerify(pubKey.native_pubKey)

        case val
        when java.io.InputStream
          buf = ::Java::byte[102400].new
          while((read = val.read(buf, 0, buf.length)) != nil)
            sign.update(buf, 0, read)
          end
        else
          sign.update(to_java_bytes(val))
        end

        sign.verify(ssign)
       
      end


    end

  end
end
