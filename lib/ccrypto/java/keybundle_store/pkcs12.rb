
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    module PKCS12
      include TR::CondUtils
      include DataConversion

      class PKCS12StorageException < KeyBundleStorageException; end

      module ClassMethods
        include DataConversion

        def from_pkcs12(bin, &block)

          raise PKCS12StorageException, "block is required" if not block

          storeType = block.call(:store_type)
          storeType = "PKCS12" if is_empty?(storeType)

          prof = block.call(:jce_provider)
          if not_empty?(prof)
            ks = java.security.KeyStore.getInstance(storeType, prof)
          else
            ks = java.security.KeyStore.getInstance(storeType)
          end

          pass = block.call(:p12_pass) || block.call(:jks_pass)
          name = block.call(:p12_name) || block.call(:jks_name)

          #case bin
          #when String
          #  bbin = bin.to_java_bytes
          #when ::Java::byte[]
          #  bbin = bin
          #else
          #  raise KeypairEngineException, "Java byte array is expected. Given #{bin.class}"
          #end

          bbin = to_java_bytes(bin)

          ks.load(java.io.ByteArrayInputStream.new(bbin),pass.to_java.toCharArray)

          name = ks.aliases.to_a.first if is_empty?(name)

          userCert = Ccrypto::X509Cert.new(ks.getCertificate(name))
          chain = ks.get_certificate_chain(name).collect { |c| Ccrypto::X509Cert.new(c) }
          chain = chain.delete_if { |c| c.equal?(userCert) }

          key = ks.getKey(name, pass.to_java.toCharArray)
          case key
          when java.security.interfaces.ECPrivateKey
            [Ccrypto::Java::ECCKeyBundle.new(key), userCert, chain]
          when java.security.interfaces.RSAPrivateKey
            [Ccrypto::Java::RSAKeyBundle.new(key), userCert, chain]
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

        ca = block.call(:certchain) || [cert]
        ca = [cert] if is_empty?(ca)
        ca = ca.unshift(gcert) if not ca.first.equal?(gcert)
        ca = ca.collect { |c|
          Ccrypto::X509Cert.to_java_cert(c) 
        }

        pass = block.call(:p12_pass) || block.call(:jks_pass)
        raise KeypairEngineException, "Password is required" if is_empty?(pass)

        name = block.call(:p12_name) || block.call(:jks_name)
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
