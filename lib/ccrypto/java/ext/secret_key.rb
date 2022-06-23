
require_relative '../data_conversion'

module Ccrypto
  class SecretKey
    include Java::DataConversion

    include TeLogger::TeLogHelper
    teLogger_tag :j_secretkey_ext

    def to_jce_secret_key
      case @key
      when javax.crypto.spec.SecretKeySpec
        @key
      when ::Java::byte[]
        javax.crypto.spec.SecretKeySpec.new(@key, @algo.to_s)

      else
        case @key.key
        when javax.crypto.spec.SecretKeySpec
          @key.key
        when ::Java::byte[]
          javax.crypto.spec.SecretKeySpec.new(@key.key, @algo.to_s)
        else
          raise Ccrypto::Error, "Unknown key to conver to jce #{@key.key}"
        end
      end
    end

    def to_bin
      case @key
      when javax.crypto.spec.SecretKeySpec
        @key.encoded
      else
        raise Ccrypto::Error, "Unsupported key type #{@key.class}"
      end
    end

    def length
      case @key
      when javax.crypto.spec.SecretKeySpec
        @key.encoded.length
      when ::Java::byte[]
        @key.length
      else
        @key.key.encoded.length
      end
    end

    def equals?(key)
      case key
      when Ccrypto::SecretKey
        teLogger.debug "Given key is Ccrypto::SecretKey"
        to_jce_secret_key.encoded == key.to_jce_secret_key.encoded
      when javax.crypto.spec.SecretKeySpec
        teLogger.debug "Given key is java SecretKeySpec"
        to_jce_secret_key.encoded == key.encoded
      when ::Java::byte[]
        to_jce_secret_key.encoded == key
      when String
        to_jce_secret_key.encoded == to_java_bytes(key)
      else
        teLogger.debug "Not sure how to compare : #{self} / #{key}"
        to_jce_secret_key == key
      end
    end

    #def each_char(&block)
    #  to_bin.each do |b|
    #    block.call(b)
    #  end
    #end

  end
end
