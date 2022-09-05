
require_relative '../data_conversion'

module Ccrypto
  module Java
    
    class Argon2Engine
      include DataConversion
      include TR::CondUtils
      
      include TeLogger::TeLogHelper
      teLogger_tag :argon2

      def initialize(conf, &block)
        
        raise KDFEngineException, "KDF config is expected" if not conf.is_a?(Ccrypto::KDFConfig)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{conf.outBitLength})" if is_empty?(conf.outBitLength) or conf.outBitLength <= 0

        teLogger.warn "Memory cost is less then 1GB recommended value" if conf.cost < 1024*1024*1024

        @config = conf

      end

      def derive(input, outFormat = :binary)
       
        gen = org.bouncycastle.crypto.generators.Argon2BytesGenerator.new
        builder = org.bouncycastle.crypto.params.Argon2Parameters::Builder.new

        outBuf = ::Java::byte[@config.outBitLength/8].new

        builder.withIterations(@config.iter)

        builder.withMemoryAsKB(@config.cost/1024)  # unit here is Kilobyte. Config standardize to byte length

        builder.withParallelism(@config.parallel)

        builder.withSalt(@config.salt)

        builder.withSecret(@config.secret)

        case @config.variant
        when :argon2d
          builder.withVersion(0)
        when :argon2i
          builder.withVersion(1)
        when :argon2id
          builder.withVersion(2)
        when :argon2_version_10
          # 0x10
          builder.withVersion(16)
        when :argon2_version_13
          # 0x13
          builder.withVersion(19)
        else
          raise KDFEngineException, "Unknown variant '#{@config.variant}'"
        end

        gen.init(builder.build())

        gen.generateBytes(to_java_bytes(input), outBuf)

        case outFormat
        when :hex
          to_hex(outBuf)
        when :b64
          to_b64(outBuf)
        else
          outBuf
        end

      end

    end

  end
end
