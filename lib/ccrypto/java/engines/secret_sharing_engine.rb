
require_relative '../data_conversion'

module Ccrypto
  module Java
    class SecretSharingEngine
      include DataConversion

      def initialize(*args, &block)
        @config = args.first
        raise SecretSharingException, "SecretSharingConfig is required" if not @config.is_a?(Ccrypto::SecretSharingConfig)
        raise SecretSharingException, "split_into value must be more than 1" if not @config.split_into.to_i > 1
        raise SecretSharingException, "required_parts value (#{@config.required_parts}) must be less than or equal split_into value (#{@config.split_into})." if not @config.required_parts.to_i < @config.split_into.to_i
      end

      def split(secVal)
        eng = com.codahale.shamir.Scheme.new(java.security.SecureRandom.new, @config.split_into.to_i, @config.required_parts.to_i) 
        case secVal
        when Ccrypto::SecretKey
          val = secVal.to_bin
        when ::Java::byte[]
          val = secVal
        when String
          val = to_java_bytes(secVal)
        else
          raise SecretSharingException, "Unknown secret value to split (#{secVal.class})"
        end
        eng.split(val)
      end

      def self.combine(req, parts)
        jhash = java.util.HashMap.new
        case parts
        when Hash
          # need to lock the key to java.lang.Integer
          # as the automated conversion of JRuby will turn the key into
          # java.lang.Long instead of java.lang.Integer
          # Using Map with parameterize auto conversion will failed inside the Java
          parts.each do |k,v|
            if not v.is_a?(::Java::byte[])
              vv = to_java_bytes(v)
            else
              vv = v
            end

            jhash.put(java.lang.Integer.new(k),vv)
          end
        when java.util.Map
          jhash = parts
        else
          raise SecretSharingException, "Unsupported parts of #{parts.class}"
        end

        com.codahale.shamir.Scheme.join(jhash)
      end

    end
  end
end
