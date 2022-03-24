
require_relative '../data_conversion'

module Ccrypto
  module Java
    class CipherEngine
      include TR::CondUtils
      include DataConversion

      def self.supported_ciphers
        res = java.security.Security.getAlgorithms("Cipher").to_a.delete_if { |e| e.include?(".") }.sort
      end

      def self.is_supported_cipher?(c)
        case c
        when String, java.lang.String
          javax.crypto.Cipher.getInstance(c)
        when Hash
          spec = to_spec(c)
          javax.crypto.Cipher.getInstance(spec)
        else
          raise CipherEngineException, "Unsupported input #{c} to check supported cipher"
        end
      end

      def self.to_spec(hash)
        res = []
        res << hash[:algo].to_s
        res << hash[:mode].to_s
        res << hash[:padding].to_s
        res.join("/")
      end

      def supported_ciphers
        self.class.supported_ciphers
      end

      def initialize(*args, &block)

        @spec = args.first

        case @spec
        when String, java.lang.String, Hash
          @spec = Ccrypto::DirectCipherConfig.new(@spec)
        when Ccrypto::CipherConfig
        else
          raise Ccrypto::CipherEngineException, "Unsupported config type #{@spec.class}"
        end

        @logger = Tlogger.new
        @logger.tag = :cipher_eng

        if block
          @cipherJceProvider = block.call(:cipher_jceProvider)
          @keygenJceProvider = block.call(:keygen_jceProvider)
        end

        cSpec = to_cipher_spec(@spec)
        if @cipherJceProvider.nil?
          begin
            @logger.debug "Cipher instance #{cSpec} with null provider"
            @cipher = javax.crypto.Cipher.getInstance(cSpec)
          rescue Exception => ex
            @logger.debug "Error #{ex.message} for spec '#{cSpec}' using null provider. Retest with BC provider"
            @cipher = javax.crypto.Cipher.getInstance(cSpec, Ccrypto::Java::JCEProvider::BCProv.name)
          end
        else
          @logger.debug "Cipher instance #{cSpec} with provider '#{@cipherJceProvider.is_a?(String) ? @cipherJceProvider : @cipherJceProvider.name}'"
          @cipher = javax.crypto.Cipher.getInstance(cSpec, @cipherJceProvider)
        end


        if @spec.has_key?
          @logger.debug "Using given cipher key"

        else
          
          @logger.debug "Generating cipher key"
          if @keygenJceProvider.nil?
            kg = javax.crypto.KeyGenerator.getInstance(to_algo(@spec.algo))
          else
            kg = javax.crypto.KeyGenerator.getInstance(to_algo(@spec.algo), @keygenJceProvider)
          end

          kg.init(@spec.keysize.to_i)
          @spec.key = kg.generateKey

        end


        if @spec.is_mode?(:gcm) or @spec.is_algo?(:chacha20)
          if is_empty?(@spec.iv)
            @logger.debug "Generating 12 bytes of IV"
            @spec.iv = Ccrypto::Java::SecureRandomEngine.random_bytes(12)
          else
            @logger.debug "Using given IV"
          end
          ivParam = javax.crypto.spec.GCMParameterSpec.new(128, @spec.iv) # 16 bytes

        elsif @spec.is_algo?(:blowfish)
          if is_empty?(@spec.iv)
            @logger.debug "Generating 8 bytes of IV"
            @spec.iv = Ccrypto::Java::SecureRandomEngine.random_bytes(8)
          else
            @logger.debug "Using given IV"
          end
          ivParam = javax.crypto.spec.IvParameterSpec.new(@spec.iv)

        elsif @spec.is_mode?(:cbc) or @spec.is_mode?(:ctr) or @spec.is_mode?(:cfb) or @spec.is_mode?(:ofb)
          if is_empty?(@spec.iv)
            @logger.debug "Generating 16 bytes of IV" 
            @spec.iv = Ccrypto::Java::SecureRandomEngine.random_bytes(16)
          else
            @logger.debug "Using given IV"
          end
          ivParam = javax.crypto.spec.IvParameterSpec.new(@spec.iv)

        end

        #@logger.debug "IV : #{@spec.iv}"

        case @spec.key
        when Ccrypto::SecretKey
          skey = @spec.key.key
        when ::Java::byte[]
          skey = javax.crypto.spec.SecretKeySpec.new(@spec.key, @spec.algo.to_s)
        when String
          skey = javax.crypto.spec.SecretKeySpec.new(to_java_bytes(@spec.key), @spec.algo.to_s)
        when javax.crypto.spec.SecretKeySpec
          skey = @spec.key
        else
          raise CipherEngineException, "Unknown key type '#{@spec.key}'"
        end

        #@logger.debug "SKey : #{skey.encoded}"

        case @spec.cipherOps
        when :encrypt, :enc
          if ivParam.nil?
            @logger.debug "Encryption mode"
            @cipher.init(javax.crypto.Cipher::ENCRYPT_MODE, skey)
          else
            @logger.debug "Encryption mode with IV"
            @cipher.init(javax.crypto.Cipher::ENCRYPT_MODE, skey, ivParam)
          end

        when :decrypt, :dec
          if ivParam.nil?
            @logger.debug "Decryption mode"
            @cipher.init(javax.crypto.Cipher::DECRYPT_MODE, skey)
          else
            @logger.debug "Decryption mode with IV"
            @cipher.init(javax.crypto.Cipher::DECRYPT_MODE, skey, ivParam)
          end

        else
          raise Ccrypto::CipherEngineException, "Cipher operation must be given"
        end

        if @spec.is_mode?(:gcm) and not_empty?(@spec.auth_data)
          @logger.debug "Adding additional authenticated data for GCM mode"
          @cipher.updateAAD(to_java_bytes(@spec.auth_data))
        end

      end

      def update(val)
        @logger.debug "Passing #{val.length} bytes to cipher"
        res = @cipher.update(to_java_bytes(val))  
        if res.nil?
          @logger.debug "Cipher update returns nothing"
        else
          @logger.debug "Cipher update output length #{res.length}"
        end
        res
      end

      def final(val = nil, &block)
        if not_empty?(val)
          update(val)
        end

        begin
          res = @cipher.doFinal

          @logger.debug "Final output length : #{res.length}"

          if @spec.is_mode?(:gcm) and @spec.is_encrypt_cipher_mode?
            # extract auth_tag
            @spec.auth_tag = res[-16..-1]
            @spec.auth_tag = String.from_java_bytes(@spec.auth_tag) if not_empty?(@spec.auth_tag)
          end 

          res
        rescue Exception => ex
          raise Ccrypto::CipherEngineException, ex
        end
      end

      def reset
        #@cipher.reset
      end

      private
      def to_algo(algo)
        algo.to_s.gsub("_","-")
      end

      def to_cipher_spec(spec)
        res = []

        res << spec.algo.to_s.gsub("_","-")

        res << spec.mode if not_empty?(spec.mode)

        if spec.algo.to_s.downcase == "aria" and spec.mode.to_s.downcase == "gcm"
          # for some reasons only aria gcm trigger this error
          res << "NoPadding"
        elsif spec.mode.to_s.downcase != "poly1305"
          case spec.padding 
          when :pkcs5
            res << "PKCS5Padding"
          when :pkcs7
            res << "PKCS7Padding"
          when :nopadding
            res << "NOPadding"
          end
        end

        if spec.is_algo?(:chacha20)
          res.join("-")
        elsif spec.is_algo?(:blowfish)
          res[0]
        else
          res.join("/")
        end
      end

    end
  end
end
