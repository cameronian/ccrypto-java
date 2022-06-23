
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

          case @config.digest
          when :sha1
            dig = org.bouncycastle.crypto.digests.SHA1Digest.new
          when :sha224
            dig = org.bouncycastle.crypto.digests.SHA224Digest.new
          when :sha256
            dig = org.bouncycastle.crypto.digests.SHA256Digest.new
          when :sha384
            dig = org.bouncycastle.crypto.digests.SHA384Digest.new
          when :sha512
            dig = org.bouncycastle.crypto.digests.SHA512Digest.new
          when :sha3_224
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(224)
          when :sha3_256
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(256)
          when :sha3_384
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(384)
          when :sha3_512
            dig = org.bouncycastle.crypto.digests.SHA3Digest.new(512)
          else
            raise KDFEngineException, "Digest #{@config.digest} not supported"
          end

          skf = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHMACSHA256",JCEProvider::DEFProv)
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
