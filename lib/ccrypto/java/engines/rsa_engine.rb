

module Ccrypto
  module Java
    
    class RSAPublicKey < Ccrypto::RSAPublicKey

      def to_bin
        @native_pubKey.encoded
      end

      def self.to_key(bin)
        #$rk = OpenSSL::PKey::RSA.new(bin)
        #$RSAPublicKey.new(rk)
      end

      def method_missing(mtd, *args, &block)
        @native_pubKey.send(mtd, *args, &block)
      end

    end # RSAPublicKey

    class RSAKeyBundle 
      include Ccrypto::RSAKeyBundle
      include TR::CondUtils

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = RSAPublicKey.new(@nativeKeypair.public)
        end
        @pubKey
      end

      def private_key
        if @privKey.nil?
          @privKey = @nativeKeypair.private
        end
        @privKey
      end

    end # RSAKeyBundle

    class RSAEngine
      include TR::CondUtils

      def initialize(*args, &block)
        @config = args.first
        raise KeypairEngineException, "1st parameter must be a #{Ccrypto::KeypairConfig.class} object" if not @config.is_a?(Ccrypto::KeypairConfig)
      end

      def generate_keypair(&block)
        prov = Ccrypto::Java::JCEProvider::DEFProv
        if block
          prov = block.call(:jce_provider)
        end
        prov = Ccrypto::Java::JCEProvider::DEFProv if is_empty?(prov)

        kpg = java.security.KeyPairGenerator.getInstance("RSA", prov)
        kpg.java_send :initialize, [::Java::int], @config.keysize
        kp = kpg.generate_key_pair

        RSAKeyBundle.new(kp)
      end

      def sign(val, &block)
        
        #raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        #raise KeypairEngineException, "RSA keypair is required" if not @config.keypair.is_a?(RSAKeyBundle)

        #kp = @config.keypair

        #privKey = kp.private_key

        #signHash = "sha256"
        #if block
        #  signHash = block.call(:sign_hash)
        #end

        #begin
        #  shash = OpenSSL::Digest.new(signHash)
        #rescue Exception => ex
        #  raise KeypairEngineException, ex
        #end

        #privKey.sign(shash, val)

      end

      def sign_pss(val, &block)
        
        #raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        #raise KeypairEngineException, "RSA keypair is required" if not @config.keypair.is_a?(RSAKeyBundle)

        #kp = @config.keypair

        #privKey = kp.private_key

        #signHash = "sha256"
        #mgf1Hash = "sha256"
        #saltLen = :max
        #if block
        #  signHash = block.call(:sign_hash)
        #  mgf1Hash = block.call("mgf1_hash")
        #  saltLen = block.call("salt_length")
        #end
        #mgf1Hash = "sha256" if is_empty?(mgf1Hash)
        #saltLen = :max if is_empty?(saltLen)
        #signHash = "sha256" if is_empty?(signHash)

        #privKey.sign_pss(signHash, val, salt_length: saltLen, mgf1_hash: mgf1Hash)

      end


      def self.verify(pubKey, val, sign, &block)
        #uPubKey = pubKey.native_pubKey

        #signHash = "sha256"
        #if block
        #  signHash = block.call(:sign_hash)
        #end

        #begin
        #  shash = OpenSSL::Digest.new(signHash)
        #rescue Exception => ex
        #  raise KeypairEngineException, ex
        #end

        #res = uPubKey.verify(shash, sign, val)
        #res
        
      end

      def self.verify_pss(pubKey, val, sign, &block)
        #uPubKey = pubKey.native_pubKey

        #signHash = "sha256"
        #mgf1Hash = "sha256"
        #saltLen = :auto
        #if block
        #  signHash = block.call(:sign_hash)
        #  mgf1Hash = block.call("mgf1_hash")
        #  saltLen = block.call("salt_length")
        #end
        #mgf1Hash = "sha256" if is_empty?(mgf1Hash)
        #saltLen = :auto if is_empty?(saltLen)
        #signHash = "sha256" if is_empty?(signHash)

        #res = uPubKey.verify_pss(signHash, sign, val, salt_length: saltLen, mgf1_hash: mgf1Hash)
        #res
        
      end


      def self.encrypt(pubKey, val, &block)
        #raise KeypairEngineException, "Public key is required" if is_empty?(pubKey)

        #padding = :oaep
        #if block
        #  padding = block.call(:padding)
        #end

        #case padding
        #when :pkcs1
        #  padVal = OpenSSL::PKey::RSA::PKCS1_PADDING
        #when :oaep
        #  padVal = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        #when :no_padding
        #  padVal = OpenSSL::PKey::RSA::NO_PADDING
        #else
        #  raise KeypairEngineException, "Padding requires either :pkcs1 or :oaep. Default is :oaep"
        #end

        #pubKey.public_encrypt(val, padVal)
      end

      def decrypt(enc, &block)

        #raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        #raise KeypairEngineException, "RSA keypair is required" if not @config.keypair.is_a?(RSAKeyBundle)

        #padding = :oaep
        #if block
        #  padding = block.call(:padding)
        #end

        #case padding
        #when :pkcs1
        #  padVal = OpenSSL::PKey::RSA::PKCS1_PADDING
        #when :oaep
        #  padVal = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        #when :no_padding
        #  padVal = OpenSSL::PKey::RSA::NO_PADDING
        #else
        #  raise KeypairEngineException, "Padding requires either :pkcs1 or :oaep. Default is :oaep"
        #end

        #kp = @config.keypair
        #kp.private_key.private_decrypt(enc, padVal)
      end

    end

  end
end
