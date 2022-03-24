
require_relative '../data_conversion'

module Ccrypto
  module Java
    class HKDFEngine
      include DataConversion
      include TR::CondUtils

      def initialize(*args, &block)
        raise KDFEngineException, "KDF config is expected" if not @config.is_a?(Ccrypto::KDFConfig)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{@config.outBitLength})" if is_empty?(@config.outBitLength) or @config.outBitLength <= 0


        @config.salt = SecureRandom.random_bytes(16) if is_empty?(@config.salt)
      end

      def derive(input, output = :binary)
        begin
          macAlgo = to_jce_spec(@config)
          logger.debug "Mac algo : #{macAlgo}"
          @hmac = javax.crypto.Mac.getInstance(to_jce_spec(@config))
          @hmac.init(@config.key.to_jce_secret_key)
        rescue Exception => ex
          raise HMACEngineException, ex
        end
        
      end

    end
  end
end
