
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    module PKCS12
      include TR::CondUtils
      include DataConversion

      class PKCS12StorageException < KeyBundleStorageException; end

      module ClassMethods
        include DataConversion
        include TeLogger::TeLogHelper
        teLogger_tag :j_p12

        def from_pkcs12(bin, &block)

          raise PKCS12StorageException, "block is required" if not block

          storeType = block.call(:store_type)
          storeType = "PKCS12" if is_empty?(storeType)

          case storeType
          when :p12, :pkcs12
            storeType = "PKCS12"
          else
            storeType = "PKCS12"
          end

          prof = block.call(:jce_provider)
          prof = JCEProvider::DEFProv if prof.nil?

          if not_empty?(prof)
            teLogger.debug "Keystore type '#{storeType}' with provider #{prof}"
            ks = java.security.KeyStore.getInstance(storeType, prof)
          else
            teLogger.debug "Keystore type '#{storeType}' with nil provider"
            ks = java.security.KeyStore.getInstance(storeType)
          end

          pass = block.call(:store_pass)
          name = block.call(:key_name)

          inForm = block.call(:in_format)
          case inForm
          when :b64
            inp = from_b64(bin)
          when :hex
            inp = from_hex(bin)
          else
            inp = bin
          end

          bbin = to_java_bytes(inp)

          ks.load(java.io.ByteArrayInputStream.new(bbin),pass.to_java.toCharArray)


          teLogger.debug "Aliases : #{ks.aliases.to_a.join(", ")}"
          teLogger.debug "Given key name : #{name}"

          name = ks.aliases.to_a.first if is_empty?(name)

          userCert = Ccrypto::X509Cert.new(ks.getCertificate(name))
          chain = ks.get_certificate_chain(name).collect { |c| Ccrypto::X509Cert.new(c) }
          #chain = chain.delete_if { |c| c.equal?(userCert) }

          key = ks.getKey(name, pass.to_java.toCharArray)
          kp = java.security.KeyPair.new(userCert.getPublicKey, key)
          case key
          when java.security.interfaces.ECPrivateKey
            [Ccrypto::Java::ECCKeyBundle.new(kp), userCert, chain]
          when java.security.interfaces.RSAPrivateKey
            [Ccrypto::Java::RSAKeyBundle.new(kp), userCert, chain]
          else
            raise PKCS12StorageException, "Unknown key type #{key}"
          end

        end

      end
      def self.included(klass)
        klass.extend(ClassMethods)
      end

      def to_pkcs12(&block)

        raise KeypairEngineException, "block is required" if not block

        storeType = block.call(:store_type)
        storeType = "PKCS12" if is_empty?(storeType)

        prof = block.call(:jce_provider)
        if not_empty?(prof)
          ks = java.security.KeyStore.getInstance(storeType, prof)
        else
          ks = java.security.KeyStore.getInstance(storeType)
        end

        ks.load(nil,nil)

        gcert = block.call(:cert)
        raise KeypairEngineException, "PKCS12 requires the X.509 certificate" if is_empty?(gcert)

        ca = block.call(:certchain) || [gcert]
        ca = [gcert] if ca.nil?
        ca = ca.unshift(gcert) if not ca.first.equal?(gcert)
        ca = ca.collect { |c|
          Ccrypto::X509Cert.to_java_cert(c) 
        }

        pass = block.call(:store_pass)
        raise KeypairEngineException, "Password is required" if is_empty?(pass)

        name = block.call(:key_name)
        name = "Ccrypto P12" if is_empty?(name)

        keypair = block.call(:keypair)
        raise KeypairEngineException, "Keypair is required" if is_empty?(keypair)

        ks.setKeyEntry(name, keypair.private, pass.to_java.toCharArray, ca.to_java(java.security.cert.Certificate))

        baos = java.io.ByteArrayOutputStream.new
        ks.store(baos, pass.to_java.toCharArray)
        res = baos.toByteArray

        outForm = block.call(:out_format)
        case outForm
        when :b64
          to_b64(res)
        when :hex
          to_hex(res)
        else
          res
        end

      end
      
    end

  end
end
