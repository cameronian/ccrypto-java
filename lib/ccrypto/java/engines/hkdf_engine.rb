
require_relative '../data_conversion'

module Ccrypto
  module Java
    class HKDFEngine
      include DataConversion
      include TR::CondUtils

      def initialize(*args, &block)
        @config = args.first

        raise KDFEngineException, "KDF config is expected. Given #{@config}" if not @config.is_a?(Ccrypto::KDFConfig)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{@config.outBitLength})" if is_empty?(@config.outBitLength) or @config.outBitLength <= 0


        @config.salt = SecureRandom.random_bytes(16) if is_empty?(@config.salt)
      end

      def derive(input, output = :binary)
        begin

          case @config.digest
          #when :sha1
          #  dig = org.bouncycastle.crypto.digests.SHA1Digest.new
          #when :sha224
          #  dig = org.bouncycastle.crypto.digests.SHA224Digest.new
          when :sha256
            dig = org.bouncycastle.crypto.digests.SHA256Digest.new
          when :sha384
            dig = org.bouncycastle.crypto.digests.SHA384Digest.new
          when :sha512
            dig = org.bouncycastle.crypto.digests.SHA512Digest.new
          #when :sha3_224
          #  dig = org.bouncycastle.crypto.digests.SHA3Digest.new(224)
          when :sha3_256
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(256)
          when :sha3_384
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(384)
          when :sha3_512
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(512)
          else
            raise KDFEngineException, "Digest #{@config.digest} not supported"
          end

          # https://soatok.blog/2021/11/17/understanding-hkdf/
          # info field should be the randomness entrophy compare to salt
          # HKDf can have fix or null salt but better have additional info for each purposes
          @config.info = "" if @config.info.nil?

          hkdf = org.bouncycastle.crypto.generators.HKDFBytesGenerator.new(dig)
          hkdfParam = org.bouncycastle.crypto.params.HKDFParameters.new(to_java_bytes(input), to_java_bytes(@config.salt) ,to_java_bytes(@config.info))
          hkdf.init(hkdfParam)

          out = ::Java::byte[@config.outBitLength/8].new
          hkdf.generateBytes(out, 0, out.length)

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
