
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


        @config.salt = SecureRandom.random_bytes(16) if is_empty?(@config.salt)
      end

      def derive(input, output = :binary)
        
        begin

          skf = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHMAC#{@config.digest.upcase}",JCEProvider::DEFProv)
          keySpec = javax.crypto.spec.PBEKeySpec.new(input.to_java.toCharArray,@config.salt, @config.iter, @config.outBitLength)

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

      
    end

  end
end
