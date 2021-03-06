
require_relative 'java/engines/ecc_engine'
require_relative 'java/engines/digest_engine'
require_relative 'java/engines/x509_engine'

require_relative 'java/engines/scrypt_engine'
require_relative 'java/engines/secure_random_engine'
require_relative 'java/engines/cipher_engine'

require_relative 'java/engines/secret_key_engine'
require_relative 'java/engines/hmac_engine'
require_relative 'java/engines/hkdf_engine'
require_relative 'java/engines/pbkdf2_engine'


require_relative 'java/utils/comparator'
require_relative 'java/utils/memory_buffer'

require_relative 'java/utils/native_helper'

require_relative 'java/engines/asn1_engine'
require_relative 'java/engines/compression_engine'
require_relative 'java/engines/decompression_engine'

require_relative 'java/engines/data_conversion_engine'

require_relative 'java/engines/secret_sharing_engine'

require_relative 'java/engines/pkcs7_engine'

require_relative 'java/engines/rsa_engine'

module  Ccrypto
  module Java
    class Provider
      include TR::CondUtils

      def self.provider_name
        "java-bc"
      end

      def self.algo_instance(*args, &block)
        config = args.first


        if config.is_a?(Class) or config.is_a?(Module)
          if config == Ccrypto::ECCConfig
            ECCEngine
          elsif config == Ccrypto::RSAConfig
            RSAEngine
          elsif config == Ccrypto::ECCKeyBundle
            ECCKeyBundle
          elsif config == Ccrypto::RSAKeyBundle
            RSAKeyBundle
          elsif config == Ccrypto::DigestConfig
            DigestEngine
          elsif config == Ccrypto::SecureRandomConfig
            SecureRandomEngine
          elsif config == Ccrypto::CipherConfig
            CipherEngine
          elsif config == Ccrypto::ECCPublicKey
            Ccrypto::Java::ECCPublicKey
          elsif config == Ccrypto::KeyConfig
            SecretKeyEngine
          elsif config == SecretSharingConfig
            SecretSharingEngine
          else
            raise CcryptoProviderException, "Config class '#{config}' is not supported for provider '#{self.provider_name}'"
          end
        else
          case config
          when Ccrypto::ECCConfig
            ECCEngine.new(*args, &block)
          when Ccrypto::RSAConfig
            RSAEngine.new(*args, &block)
          when Ccrypto::DigestConfig
            DigestEngine.instance(*args, &block)
          when Ccrypto::X509::CertProfile
            X509Engine.new(*args,&block)
          when Ccrypto::ScryptConfig
            ScryptEngine.new(*args,&block)
          when Ccrypto::HKDFConfig
            HKDFEngine.new(*args,&block)
          when Ccrypto::PBKDF2Config
            PBKDF2Engine.new(*args,&block)
          when Ccrypto::CipherConfig
            CipherEngine.new(*args, &block)
          when Ccrypto::HMACConfig
            HMACEngine.new(*args, &block)
          when Ccrypto::SecretSharingConfig
            SecretSharingEngine.new(*args,&block)
          when Ccrypto::PKCS7Config
            PKCS7Engine.new(*args, &block)
          else
            raise CcryptoProviderException, "Config instance '#{config}' is not supported for provider '#{self.provider_name}'"
          end
        end


      end

      def self.asn1_engine(*args, &block)
        ASN1Engine
      end

      def self.util_instance(*args, &block)
        algo = args.first
        case algo
        when :comparator, :compare
          ComparatorUtil
        when :data_conversion, :converter, :data_converter
          DataConversionEngine
        when :memory_buffer, :membuf, :buffer, :mem
          ManagedMemoryBuffer

        when :compression, :compressor
          Compression.new(*(args[1..-1]), &block)

        when :decompression
          Decompression.new(*(args[1..-1]), &block)

        when :native_helper
          NativeHelper

        else
          raise CcryptoProviderException, "Util #{algo} is not supported for provider #{self.provider_name}"
        end
      end

    end
  end
end
