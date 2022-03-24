
require_relative '../data_conversion'

module Ccrypto
  module Java
    class DigestEngine
      include TR::CondUtils
      include DataConversion

      Potential = [

        Ccrypto::SHA1.provider_info("SHA-1"),
        Ccrypto::SHA224.provider_info("SHA-224"),
        Ccrypto::SHA256.provider_info("SHA-256"),
        Ccrypto::SHA384.provider_info("SHA-384"),
        Ccrypto::SHA512.provider_info("SHA-512"),
        Ccrypto::SHA512_224.provider_info("SHA-512/224"),
        Ccrypto::SHA512_256.provider_info("SHA-512/256"),

        Ccrypto::SHA3_224.provider_info("SHA3-224"),
        Ccrypto::SHA3_256.provider_info("SHA3-256"),
        Ccrypto::SHA3_384.provider_info("SHA3-384"),
        Ccrypto::SHA3_512.provider_info("SHA3-512"),

        Ccrypto::BLAKE2b160.provider_info("BLAKE2B-160"),
        Ccrypto::BLAKE2b256.provider_info("BLAKE2B-256"),
        Ccrypto::BLAKE2b384.provider_info("BLAKE2B-384"),
        Ccrypto::BLAKE2b512.provider_info("BLAKE2B-512"),

        Ccrypto::BLAKE2s128.provider_info("BLAKE2S-128"),
        Ccrypto::BLAKE2s160.provider_info("BLAKE2s-160"),
        Ccrypto::BLAKE2s224.provider_info("BLAKE2s-224"),
        Ccrypto::BLAKE2s256.provider_info("BLAKE2s-256"),

        Ccrypto::HARAKA256.provider_info("HARAKA-256"),
        Ccrypto::HARAKA512.provider_info("HARAKA-512"),

        Ccrypto::KECCAK224.provider_info("KECCAK-224"),
        Ccrypto::KECCAK256.provider_info("KECCAK-256"),
        Ccrypto::KECCAK288.provider_info("KECCAK-288"),
        Ccrypto::KECCAK384.provider_info("KECCAK-384"),
        Ccrypto::KECCAK512.provider_info("KECCAK-512"),

        Ccrypto::RIPEMD128.provider_info("RIPEMD128"),
        Ccrypto::RIPEMD160.provider_info("RIPEMD160"),
        Ccrypto::RIPEMD256.provider_info("RIPEMD256"),
        Ccrypto::RIPEMD320.provider_info("RIPEMD320"),

        Ccrypto::SHAKE128_256.provider_info("SHAKE128-256"),
        Ccrypto::SHAKE256_512.provider_info("SHAKE256-512"),

        Ccrypto::SKEIN1024_1024.provider_info("SKEIN-1024-1024"),
        Ccrypto::SKEIN1024_384.provider_info("SKEIN-1024-384"),
        Ccrypto::SKEIN1024_512.provider_info("SKEIN-1024-512"),

        Ccrypto::SKEIN256_128.provider_info("SKEIN-256-128"),
        Ccrypto::SKEIN256_160.provider_info("SKEIN-256-160"),
        Ccrypto::SKEIN256_224.provider_info("SKEIN-256-224"),
        Ccrypto::SKEIN256_256.provider_info("SKEIN-256-256"),

        Ccrypto::SKEIN512_128.provider_info("SKEIN-512-128"),
        Ccrypto::SKEIN512_160.provider_info("SKEIN-512-160"),
        Ccrypto::SKEIN512_224.provider_info("SKEIN-512-224"),
        Ccrypto::SKEIN512_256.provider_info("SKEIN-512-256"),
        Ccrypto::SKEIN512_384.provider_info("SKEIN-512-384"),
        Ccrypto::SKEIN512_512.provider_info("SKEIN-512-512"),

        SM3 = Ccrypto::SM3.provider_info("SM3"),
        WHIRLPOOL = Ccrypto::WHIRLPOOL.provider_info("WHIRLPOOL")
      ]

      def self.supported
        if @supported.nil?
          @supported = []
          probe = java.security.Security.getAlgorithms("MessageDigest").to_a.delete_if { |e| e.include?(".") }
          Potential.each do |po|
            @supported << po if probe.include?(po.provider_config)
          end
        end
        @supported
      end

      def self.is_supported?(eng, prov = nil)
        if is_empty?(eng)
          false
        else

          jceName = algo_jce_map[eng]
          begin
            if not_empty?(prov)
              #java.security.MessageDigest.getInstance(eng.to_s.gsub("_","-"), prov)
              java.security.MessageDigest.getInstance(jceName, prov)
            else
              #java.security.MessageDigest.getInstance(eng.to_s.gsub("_","-"))
              java.security.MessageDigest.getInstance(jceName)
            end
            true
          rescue java.security.NoSuchAlgorithmException => ex
            p ex.message
            false
          end
        end
      end

      def self.default_algo
        "SHA256"
      end

      def self.instance(conf, &block)
        if block
          prov = block.call(:jce_provider)
          if not_empty?(prov)
            DigestEngine.new(conf.provider_config, prov, &block)
          else
            DigestEngine.new(conf.provider_config, &block)
          end
        else
          DigestEngine.new(conf.provider_config, &block)
        end
      end

      def self.digest(key, &block)
        res = engineKeys[key]
        if is_empty?(res)
          raise DigestEngine, "Not supported digest engine #{key}"
        else
          if block
            digProv = block.call(:digest_jceProvider)
          end

          if digProv.nil?
            DigestEngine.new(res.provider_config)
          else
            DigestEngine.new(res.provider_config, digProv)
          end
        end
      end

      def self.engineKeys
        if @engineKeys.nil?
          @engineKeys = {}
          supported.each do |a|
            @engineKeys[a.algo.to_sym] = a
          end
        end
        @engineKeys
      end

      def self.algo_jce_map
        if @algoMap.nil?
          @algoMap = {}
          supported.each do |a|
            @algoMap[a.algo.to_sym] = a.provider_config
          end
        end
        @algoMap
      end

      def initialize(algo, prov = nil, &block)
        logger.debug "Algo : #{algo}"
        @algo =  algo #algo.to_s.gsub("_","-")
        begin
          if not_empty?(prov)
            @inst = java.security.MessageDigest.getInstance(@algo, prov)
          else
            @inst = java.security.MessageDigest.getInstance(@algo)
          end
        #rescue java.security.NoSuchAlgorithmException => ex
        rescue Exception => ex
          raise DigestEngineException, ex
        end
      end

      def digest(val, output = :binary)
        digest_final(val, output)
      end

      def digest_update(val)
        @inst.update(to_java_bytes(val))
      end

      def digest_final(val = nil, output = :binary)
        if not_empty?(val)
          @inst.update(to_java_bytes(val))
        end
        res = @inst.digest
        @inst.reset
        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end

      def reset
        @inst.reset
      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :digest_eng
        end
        @logger
      end

    end
  end
end
