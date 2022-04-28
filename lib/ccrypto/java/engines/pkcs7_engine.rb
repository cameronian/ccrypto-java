
require_relative '../data_conversion'
'

'

module Ccrypto
  module Java
   
    class PKCS7EngineException < StandardError; end

    class PKCS7Engine
      include TR::CondUtils
      include DataConversion

      def initialize(config)
        raise PKCS7EngineException, "Ccrypto::PKCS7Config is expected. Given #{config}" if not config.is_a?(Ccrypto::PKCS7Config)
        @config = config
      end

      def sign(val, outForm = :bin, &block)

        validate_input(val, "signing")
        validate_key_must_exist("signing")

        raise PKCS7EngineException, "signerCert is required for PKCS7 sign operation" if is_empty?(@config.signerCert)
        raise PKCS7EngineException, "Given signerCert must be a Ccrypto::X509Cert object" if not @config.signerCert.is_a?(Ccrypto::X509Cert)

        privKey = @config.keybundle.private_key

        prov = nil
        signHash = nil
        attached = true
        caCerts = []
        os = nil
        readBufSize = 1024000
        signSpec = nil
        if block
          prov = block.call(:jce_provider)
          signHash = block.call(:sign_hash)
          detSign = block.call(:detached_sign)
          attached = ! detSign if is_bool?(detSign)
          caCerts = block.call(:ca_certs)
          os = block.call(:output_stream)
          if not (os.nil? or os.is_a?(java.io.OutputStream))
            raise PKCS7EngineException, "Given output_stream is not type of java.io.OutputStream (Given #{os}). Please provide an java.io.OutputStream object or use default which is java.io.ByteArrayOutputStream"
          end
          readBufSize = block.call(:read_buffer_size)
          signSpec = block.call(:signing_spec)
        end

        caCerts = [] if caCerts.nil?
        prov = Ccrypto::Java::JCEProvider::DEFProv if is_empty?(prov)
        signHash = :sha256 if is_empty?(signHash)
        attached = true if is_empty?(attached)
        readBufSize = 1024000 if readBufSize.to_i > 0

        os = java.io.ByteArrayOutputStream.new if os.nil? 

        lst = java.util.ArrayList.new 
        lst.add(@config.signerCert.nativeX509)
        caCerts.each do |cc|
          list.add(cc.nativeX509)
        end
        store = org.bouncycastle.cert.jcajce.JcaCertStore.new(lst)

        gen = org.bouncycastle.cms.CMSSignedDataStreamGenerator.new

        if is_empty?(signSpec)
          case privKey
          when ::Java::OrgBouncycastleJcajceProviderAsymmetricEc::BCECPrivateKey
            signSpec = "#{signHash.upcase}withECDSA"
          when java.security.interfaces.RSAPrivateKey
            signSpec = "#{signHash.to_s.upcase}withRSA"
          else
            raise PKCS7EngineException, "Unknown private key type '#{privKey.class}' to derive the hash algo from"
          end
        end

        signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signSpec).setProvider(prov).build(privKey)
        infoGen = org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder.new(org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder.new.setProvider(prov).build()).build(signer, @config.signerCert.nativeX509)
        gen.addSignerInfoGenerator(infoGen)
        
        gen.addCertificates(store)
      
        begin

          if attached
            logger.debug "Initiated attached sign"
          else
            logger.debug "Initiated detached sign"
          end

          sos = gen.open(os, attached)

          case val
          when java.io.InputStream
            logger.debug "InputStream data-to-be-signed detected"
            buf = ::Java::Byte[readBufSize].new
            read = 0
            processed = 0
            while((read = val.read(buf, 0, buf.length)) != -1)
              sos.write(buf, 0 ,read)
              processed += read
              block.call(:processed, processed) if block
            end
          else
            logger.debug "Byte array data-to-be-signed detected"
            ba = to_java_bytes(val)
            if ba.is_a?(::Java::byte[])
              sos.write(ba)
              sos.flush
              sos.close
            else
              raise PKCS7EngineException, "Not able to convert given input into byte array. Got #{val.class}"
            end
          end

          os.toByteArray

        rescue Exception => ex
          raise PKCS7EngineException, ex
        ensure 

          begin
            sos.close
          rescue Exception; end
        end

      end

      def verify(val, inForm = :bin, &block)

        srcData = nil
        os = nil
        prov = Ccrypto::Java::JCEProvider::DEFProv
        if block
          srcData = block.call(:signed_data)
          os = block.call(:output_stream)
          prov = block.call(:jce_provider)
        end

        os = java.io.ByteArrayOutputStream.new if os.nil?
        prov = Ccrypto::Java::JCEProvider::DEFProv if is_empty?(prov)

        data = nil
        case srcData
        when java.io.File
          data = org.bouncycastle.cms.CMSProcessableFile.new(val)
          logger.debug "Given original data is a java.io.File"
        else
          if not_empty?(srcData)
            ba = to_java_bytes(srcData)
            if ba.is_a?(::Java::byte[])
              data = org.bouncycastle.cms.CMSProcessableByteArray.new(ba)
              logger.debug "Given original data is a byte array"
            else
              raise PKCS7EngineException, "Failed to read original data. Given #{srcData}"
            end
          else
            logger.debug "Original data for signing is not given."
          end
        end

        case val
        when java.io.InputStream
          if data.nil?
            logger.debug "Attached signature with java.io.InputStream signature detected during verification"
            signed = org.bouncycastle.cms.CMSSignedData.new(val)
          else
            logger.debug "Detached signature with java.io.InputStream signature detected during verification"
            signed = org.bouncycastle.cms.CMSSignedData.new(data, val)
          end
        else
          if not_empty?(val)
            ba = to_java_bytes(val)
            if ba.is_a?(::Java::byte[])
              if data.nil?
                logger.debug "Attached signature with byte array signature detected during verification"
                signed = org.bouncycastle.cms.CMSSignedData.new(ba)
              else
                logger.debug "Detached signature with byte array signature detected during verification"
                signed = org.bouncycastle.cms.CMSSignedData.new(data, ba)
              end
            else
              raise PKCS7EngineException, "Failed to convert input to java byte array. Given #{val.class}"
            end
          else
            raise PKCS7EngineException, "Given signature to verify is empty."
          end
        end

        certs = signed.certificates
        signerInfo = signed.getSignerInfos
        signers = signerInfo.getSigners
        signatureVerified = false
        signers.each do |signer|

          certVerified = true
          certs.getMatches(signer.getSID).each do |c|
            begin

              if block
                certVerified = block.call(:verify_certificate, c)
                if certVerified.nil?
                  logger.debug "Certificate with subject #{c.subject} / Issuer : #{c.issuer} / SN : #{c.serial_number.to_s(16)} passed through (no checking by application)"
                  certVerified = true
                elsif is_bool?(certVerified)
                  if certVerified
                    logger.debug "Certificate with subject #{c.subject} / Issuer : #{c.issuer} / SN : #{c.serial_number.to_s(16)} accepted by application"
                  else
                    logger.debug "Certificate with subject #{c.subject} / Issuer : #{c.issuer} / SN : #{c.serial_number.to_s(16)} rejected by application"
                  end
                else
                  logger.debug "Certificate with subject #{c.subject} / Issuer : #{c.issuer} / SN : #{c.serial_number.to_s(16)} passed through (no checking by application. Given #{certVerified})"
                end
              else
                logger.debug "Certificate with subject #{c.subject} / Issuer : #{c.issuer} / SN : #{c.serial_number.to_s(16)} passed through (no checking by application)"
              end

              if certVerified

                logger.debug "Verifing signature against certificate '#{c.subject}'"
                verifier = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder.new.setProvider(prov).build(c)
                if signer.verify(verifier)
                  logger.debug "Signer with #{c.subject} verified!"
                  if block
                    block.call(:verification_result, true)
                    if data.nil?
                      block.call(:attached_data, signed.getSignedContent.getContent)
                    end
                  end

                  signatureVerified = true

                else
                  logger.debug "Signer with #{c.subject} failed. Retry with subsequent certificate"
                  signatureVerified = false
                end

              end
            rescue ::Java::OrgBouncycastleCms::CMSSignerDigestMismatchException => ex
              logger.error "Signer digest mismatch exception : #{ex.message}" 
              signatureVerified = false
              break
            rescue Exception => ex
              logger.error ex
              logger.error ex.message
              logger.error ex.backtrace.join("\n")
            end
          end
          # end certs.getMatches

          break if signatureVerified

        end
        # end signers.each

        signatureVerified

      end

      def encrypt(val, &block)
      
        gen = org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator.new
        @config.recipient_certs.each do |re|
          gen.addRecipientInfoGenerator(to_cms_recipint_info(re))
        end

        intBufSize = 1024000
        if block
          cipher = block.call(:cipher)
          logger.debug "Application given cipher #{cipher}"

          prov = block.call(:jce_provider)
          intBufSize = block.call(:int_buffer_size)
          os = block.call(:output_stream)
          if not os.nil? and not os.is_a?(java.io.OutputStream)
            raise PKCS7EngineException, "java.io.OutputStream expected but was given '#{os.class}'"
          end
        end

        cipher = Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :cbc }) if cipher.nil?
        prov =  Ccrypto::Java::JCEProvider::DEFProv if is_empty?(prov)
        intBufSize = 1024000 if is_empty?(intBufSize)

        os = java.io.ByteArrayOutputStream.new if os.nil?

        encOut = gen.open(os, org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder.new(cipher_to_bc_cms_algo(cipher)).setProvider(prov).build())

        case val
        when java.io.InputStream
          
          begin
            total = 0
            buf = ::Java::byte[intBufSize].new
            while((read = val.read(buf, 0, buf.length)) != -1)
              encOut.write(buf, 0, read)
            end

            encOut.flush
            encOut.close

          rescue Exception
          ensure
            begin
              encOut.close
            rescue Exception
            end
          end

        else

          if val.nil?
            raise PKCS7EngineException, "Nil input is given."
          else
            ba = to_java_bytes(val)
            case ba
            when ::Java::byte[]
              encOut.write(ba)
              encOut.close
              encOut.close
            else
              raise PKCS7EngineException, "Unknown format given as input #{val}"
            end
          end

        end

        os.toByteArray if os.is_a?(java.io.ByteArrayOutputStream)

      end

      def decrypt(val, &block)
        validate_input(val, "decrypt") 
        validate_key_must_exist("decrypt")

        raise PKCS7EngineException, "certForDecryption is required for PKCS7 decrypt operation" if is_empty?(@config.certForDecryption)
        raise PKCS7EngineException, "Given certForDecryption must be a Ccrypto::X509Cert object" if not @config.certForDecryption.is_a?(Ccrypto::X509Cert)

        case val
        when java.io.ByteArrayInputStream
          envp = org.bouncycastle.cms.CMSEnvelopedData.new(val)
        else
          if not val.nil?
            ba = to_java_bytes(val)
            case ba
            when ::Java::byte[]
              envp = org.bouncycastle.cms.CMSEnvelopedData.new(ba)
            else
              raise PKCS7EngineException, "Unknown input type '#{ba}' is given"
            end
          else
            raise PKCS7EngineException, "Null input is given"
          end
        end

        if block
          os = block.call(:output_stream)
          intBufSize = block.call(:int_buffer_size)
        end

        os = java.io.ByteArrayOutputStream.new if os.nil?
        intBufSize = 1024000 if is_empty?(intBufSize)

        kt = decryption_key_to_recipient(@config.keybundle.private_key)

        lastEx = nil
        recipients = envp.getRecipientInfos.getRecipients
        recipients.each do |r|

          begin
            encIs = r.getContentStream(kt).getContentStream
          rescue Exception => ex
            lastEx = ex
            logger.debug "Got exception : #{ex.message}. Retry with another envelope"
            next
          end

          begin
            total = 0
            buf = ::Java::byte[intBufSize].new
            while((read = encIs.read(buf, 0, buf.length)) != -1)
              os.write(buf,0, read)
            end

            os.flush
          rescue Exception
          ensure
            begin
              encIs.close
            rescue Exception
            end
          end

          lastEx = nil
          break
        end

        if not lastEx.nil?
          raise PKCS7EngineException, lastEx
        end

        os.toByteArray if os.is_a?(java.io.ByteArrayOutputStream)

      end

      protected
      def validate_input(val, ops)
        raise PKCS7EngineException, "Given data to #{ops} operation is empty" if is_empty?(val) 
        #raise PKCS7EngineException, "X509_cert is required for PKCS7 #{ops}" if is_empty?(@config.x509_cert)
        #raise PKCS7EngineException, "Given x509_cert must be a Ccrypto::X509Cert object" if not @config.x509_cert.is_a?(Ccrypto::X509Cert)
      end

      def validate_key_must_exist(ops)
        raise PKCS7EngineException, "Keybundle is required for PKCS7 #{ops}" if is_empty?(@config.keybundle)
        raise PKCS7EngineException, "Given key must be a Ccrypto::KeyBundle object" if not @config.keybundle.is_a?(Ccrypto::KeyBundle)
      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :pkcs7_engine
        end
        @logger
      end

      def to_cms_recipint_info(obj, prov = Ccrypto::Java::JCEProvider::DEFProv)

        case obj
        when java.security.Certificate
          logger.debug "Given recipient info is java.security.Certificate"
          org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator.new(obj).setProvider(prov)
        when Ccrypto::X509Cert
          logger.debug "Given recipient info is Ccrypto::X509Cert"
          org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator.new(obj.nativeX509).setProvider(prov)
        else
          raise PKCS7EngineException, "Unknown object to conver to CMS recipient info. Given #{obj}"
        end

        #if Pkernel::Certificate.is_cert_object?(obj)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given recipient info is certificate"
        #  cert = Pkernel::Certificate.ensure_java_cert(obj)
        #  org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator.new(cert).setProvider(provider)
        #elsif GcryptoJce::SecretKey.is_secret_key?(obj)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given recipient info is secret key"
        #  #org.bouncycastle.operator.jcajce.JceSymmetricKeyWrapper.new(obj).setProvider(provider)
        #  org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator.new(SecureRandom.hex(8).to_java.getBytes, obj).setProvider(provider)
        #elsif obj.is_a?(Gcrypto::SecretKeyCryptoContext)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given recipient info is secret key crypto context"
        #  prov = obj.key_provider
        #  prov = provider if prov.nil?
        #  #wrapper = org.bouncycastle.operator.jcajce.JceSymmetricKeyWrapper.new(obj.key).setProvider(prov)
        #  org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator.new(obj.name.to_java.getBytes, obj.key).setProvider(prov)
        #elsif obj.is_a?(String)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given recipient info is string --> password recipient"
        #  #algo = org.bouncycastle.cms.CMSAlgorithm::AES256_GCM
        #  algo = org.bouncycastle.cms.CMSAlgorithm::AES256_CBC
        #  salt = GcryptoJce::SecureRandomEngine.generate
        #  iter = rand(1000...3000)
        #  org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator.new(algo, obj.to_java.toCharArray).setPasswordConversionScheme(org.bouncycastle.cms.PasswordRecipient::PKCS5_SCHEME2).setSaltAndIterationCount(salt,iter)
        #elsif obj.java_kind_of?(Java::byte[])
        #  GcryptoBcCms::GConf.instance.glog.debug "Given recipient info is java byte array. Assume string --> password recipient"
        #  #algo = org.bouncycastle.cms.CMSAlgorithm::AES256_GCM
        #  algo = org.bouncycastle.cms.CMSAlgorithm::AES256_CBC
        #  salt = GcryptoJce::SecureRandomEngine.generate
        #  iter = rand(1000...3000)
        #  org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator.new(algo, String.from_java_bytes(obj).toCharArray).setPasswordConversionScheme(org.bouncycastle.cms.PasswordRecipient::PKCS5_SCHEME2).setSaltAndIterationCount(salt,iter)
        #elsif obj.java_kind_of?(Java::char[])
        #  GcryptoBcCms::GConf.instance.glog.debug "Given recipient info is java char array. Assume string --> password recipient"
        #  #algo = org.bouncycastle.cms.CMSAlgorithm::AES256_GCM
        #  algo = org.bouncycastle.cms.CMSAlgorithm::AES256_CBC
        #  salt = GcryptoJce::SecureRandomEngine.generate
        #  iter = rand(1000...3000)
        #  org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator.new(algo, obj).setPasswordConversionScheme(org.bouncycastle.cms.PasswordRecipient::PKCS5_SCHEME2).setSaltAndIterationCount(salt,iter)
        #else
        #  raise GcryptoBcCms::Error, "Unsupported object for encryption recipient info conversion '#{obj.class}'"
        #end

      end  # to_cms_recipient_info

      def cipher_to_bc_cms_algo(cipher)
        case cipher
        when Ccrypto::CipherConfig
          case cipher.algo
          when :seed
            eval("org.bouncycastle.cms.CMSAlgorithm::#{cipher.algo.to_s.upcase}_#{cipher.mode.to_s.upcase}")
          else
            eval("org.bouncycastle.cms.CMSAlgorithm::#{cipher.algo.to_s.upcase}#{cipher.keysize}_#{cipher.mode.to_s.upcase}")
          end
        else
          raise PKCS7EngineException, "Invalid cipher object '#{cipher}'. Expecting Ccrypto::Cipher object"
        end
      end

       def decryption_key_to_recipient(decKey, prov = Ccrypto::Java::JCEProvider::DEFProv)
        case decKey
        when java.security.PrivateKey
          org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient.new(decKey).setProvider(prov)
        else
          raise PKCS7EngineException, "Unsupported decryption key type '#{decKey}'"
        end

        #if Pkernel::KeyPair.is_private_key?(obj)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is private key"
        #  org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient.new(obj).setProvider(provider)
        #elsif GcryptoJce::SecretKey.is_secret_key?(obj)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is secret key"
        #  #w = org.bouncycastle.operator.jcajce.JceSymmetricKeyUnwrapper.new(obj).setProvider(provider)
        #  if provider.nil?
        #    org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient.new(obj)
        #  else
        #    org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient.new(obj).setProvider(provider)
        #  end
        #elsif obj.is_a?(Gcrypto::SecretKeyCryptoContext)
        #  prov = obj.key_provider
        #  prov = provider if prov.nil?
        #  if prov.nil?
        #    GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is secret key crypto context."
        #    org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient.new(obj.key)
        #  else
        #    GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is secret key crypto context. '#{prov.nil? ? '' : "Using provider #{prov.name}" }'"
        #    org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient.new(obj.key).setProvider(prov)
        #  end
        #  #org.bouncycastle.operator.jcajce.JceSymmetricKeyUnwrapper.new(obj.key).setProvider(prov)
        #elsif obj.is_a?(String)
        #  GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is string --> password recipient"
        #  org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient.new(obj.to_java.toCharArray).setPasswordConversionScheme(org.bouncycastle.cms.PasswordRecipient::PKCS5_SCHEME2)
        #elsif obj.java_kind_of?(Java::byte[])
        #  GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is java byte array. Assume string --> password recipient"
        #  org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient.new(String.from_java_bytes(obj).to_java.toCharArray).setPasswordConversionScheme(org.bouncycastle.cms.PasswordRecipient::PKCS5_SCHEME2)
        #elsif obj.java_kind_of?(Java::char[])
        #  GcryptoBcCms::GConf.instance.glog.debug "Given decryption artifacts is java char array. Assume string --> password recipient"
        #  org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient.new(obj).setPasswordConversionScheme(org.bouncycastle.cms.PasswordRecipient::PKCS5_SCHEME2)
        #else
        #  raise GcryptoBcCms::Error, "Unsupported object for decryption recipient object conversion '#{obj.class}'"
        #end

      end

     
    end

  end
end
