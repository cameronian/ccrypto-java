
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    class PBKDF2Engine
      include TR::CondUtils
      include DataConversion

      def initialize(*args, &block)
        @config = args.first

        raise KDFEngineException, "KDF config is expected. Given #{@config}" if not @config.is_a?(Ccrypto::PBKDF2Config)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{@config.outBitLength})" if is_empty?(@config.outBitLength) or @config.outBitLength <= 0

        raise KDFEngineException, "Digest algo is not supported. Given #{@config.digest}, supported: #{supported_digest.join(", ")}" if not @config.digest.nil? and not is_digest_supported?(@config.digest)

        @config.digest = default_digest if is_empty?(@config.digest)

        @config.salt = SecureRandom.random_bytes(16) if is_empty?(@config.salt)
      end

      def derive(input, output = :binary)
        
        begin

          case input
          when String
            if input.ascii_only?
              pass = input.to_java.toCharArray
            else
              pass = to_hex(to_java_bytes(input)).to_java.toCharArray
            end
          when ::Java::byte[]
            pass = to_hex(to_java_bytes(input)).to_java.toCharArray
          else
            raise KDFEngineException, "Input type '#{input.class}' cannot convert to char array"
          end

          skf = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHMAC#{@config.digest.upcase}",JCEProvider::DEFProv)
          keySpec = javax.crypto.spec.PBEKeySpec.new(pass.to_java, to_java_bytes(@config.salt), @config.iter, @config.outBitLength)

          sk = skf.generateSecret(keySpec)
          out = sk.encoded

          case output
          when :b64
            to_b64(out)
          when :hex
            to_hex(out)
          else
            out
          end

        rescue Exception => ex
          raise KDFEngineException, ex
        end
        
      end

      def default_digest
        :sha256
      end

      private
      def logger
        if @logger.nil?
          @logger = TeLogger::Tlogger.new
          @logger.tag = :j_pbkdf2
        end
        @logger
      end

      def is_digest_supported?(dig)
        supported_digest.include?(dig)
      end

      def supported_digest
        [:sha1, :sha256, :sha224, :sha384, :sha512]
      end

      
    end

  end
end
