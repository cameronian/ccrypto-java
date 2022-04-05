
require_relative 'java/engines/ecc_engine'
require_relative 'java/engines/digest_engine'
require_relative 'java/engines/x509_engine'

require_relative 'java/engines/scrypt_engine'
require_relative 'java/engines/secure_random_engine'
require_relative 'java/engines/cipher_engine'

require_relative 'java/engines/secret_key_engine'
require_relative 'java/engines/hmac_engine'

require_relative 'java/utils/comparator'
require_relative 'java/utils/memory_buffer'

require_relative 'java/engines/asn1_engine'
require_relative 'java/engines/compression_engine'
require_relative 'java/engines/decompression_engine'

require_relative 'java/engines/data_conversion_engine'

require_relative 'java/engines/secret_sharing_engine'

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
          elsif config == Ccrypto::ECCKeyBundle
            ECCKeyBundle
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
          when Ccrypto::DigestConfig
            DigestEngine.instance(*args, &block)
          when Ccrypto::X509::CertProfile
            X509Engine.new(*args,&block)
          when Ccrypto::ScryptConfig
            ScryptEngine.new(*args,&block)
          #when Ccrypto::HKDFConfig
          #  HKDFEngine.new(*args,&block)
          when Ccrypto::CipherConfig
            CipherEngine.new(*args, &block)
          when Ccrypto::HMACConfig
            HMACEngine.new(*args, &block)
          when Ccrypto::SecretSharingConfig
            SecretSharingEngine.new(*args,&block)
          else
            raise CcryptoProviderException, "Config instance '#{config}' is not supported for provider '#{self.provider_name}'"
          end
        end


        #case algo
        #when :ecc
        #  ECCEngine
        #when :x509
        #  if args.length > 1
        #    X509Engine.new(*args[1..-1])
        #  else
        #    X509Engine
        #  end
        #else
        #  if DigestEngine.is_supported?(algo, &block)
        #    DigestEngine.instance(algo, &block)
        #  elsif CipherEngine.is_supported_cipher?(algo)
        #    if not_empty?(args)
        #      CipherEngine.instance(*args)
        #    else
        #      CipherEngine
        #    end
        #  else
        #    raise CcryptoProviderException, "Algo '#{algo}' is not supported for provider '#{self.provider_name}'"
        #  end
        #end
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

        else
          raise CcryptoProviderException, "Util #{algo} is not supported for provider #{self.provider_name}"
        end
      end

    end
  end
end
