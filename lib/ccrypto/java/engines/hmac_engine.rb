
require_relative '../data_conversion'

module Ccrypto
  module Java
    class HMACEngine
      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper
      teLogger_tag :j_hmac

      def initialize(*args, &block)
        @config = args.first

        raise HMACEngineException, "HMAC config is expected" if not @config.is_a?(Ccrypto::HMACConfig) 

        raise HMACEngineException, "Signing key is required" if is_empty?(@config.key)
        raise HMACEngineException, "Secret key as signing key is required. Given #{@config.key.class}" if not @config.key.is_a?(Ccrypto::SecretKey)

        teLogger.debug "Config : #{@config.inspect}"
        begin
          macAlgo = to_jce_spec(@config)
          teLogger.debug "Mac algo : #{macAlgo}"
          @hmac = javax.crypto.Mac.getInstance(to_jce_spec(@config))
          @hmac.init(@config.key.to_jce_secret_key)
        rescue Exception => ex
          raise HMACEngineException, ex
        end

      end

      def hmac_update(val)
        @hmac.update(to_java_bytes(val)) if not_empty?(val)
      end

      def hmac_final
        @hmac.doFinal 
      end

      def hmac_digest(val, output = :binary)
        hmac_update(val)
        res = hmac_final

        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end


      private
      def to_jce_spec(config)
        res = []
        res << "HMAC"

        salgo = config.digest.to_s
        if salgo =~ /_/
          res << salgo.gsub("_","-").upcase
        else
          res << salgo.upcase
        end
       
        res.join

      end


    end
  end
end
