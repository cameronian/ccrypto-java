
require_relative '../data_conversion'

module Ccrypto
  module Java
    class ScryptEngine 
      include DataConversion
      include TR::CondUtils

      def initialize(conf, &block)
        raise KDFEngineException, "KDF config is expected" if not conf.is_a?(Ccrypto::KDFConfig)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{conf.outBitLength})" if is_empty?(conf.outBitLength) or conf.outBitLength <= 0
        @config = conf

        if is_empty?(@config.salt)
          @config.salt = Java::byte[16].new
          java.security.SecureRandom.getInstance("NativePRNG").random_bytes(@config.salt)
        end
      end

      def derive(input, output = :binary)
        res =  org.bouncycastle.crypto.generators.SCrypt.generate(to_java_bytes(input), to_java_bytes(@config.salt),@config.cost, @config.blockSize, @config.parallel, @config.outBitLength/8)
        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end

    end
  end
end
