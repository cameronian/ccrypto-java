
require_relative '../data_conversion'

module Ccrypto
  module Java
    class SecureRandomEngine
      include TR::CondUtils
      extend DataConversion


      def self.random_bytes(size, &block)
        buf = ::Java::byte[size].new
        engine(&block).next_bytes(buf)
        buf
      end

      def self.random_hex(size,&block)
        to_hex(random_bytes(size,&block))
      end

      def self.random_b64(size, &block)
        to_b64(random_bytes(size, &block)) 
      end

      def self.random_uuid
        java.util.UUID.randomUUID.to_s 
      end

      def self.random_alphanu(size, &block)
        SecureRandom.alphanumeric(size) 
      end

      def self.random_number(val, &block)
        if val.is_a?(Range) 
          v = engine(&block).next_int(val.max)
          if v < val.min
            v = v+val.min
          end
          v
        elsif val.is_a?(Integer)
          engine(&block).next_int(val)
        elsif is_empty?(val)
          engine(&block).next_double
        end
      end


      private
      def self.engine(&block)
        if @srEngine.nil?
          srJceProvider = nil
          algo = "NativePRNG"
          if block
            jceProv = block.call(:jce_provider)
            srJceProvider = jceProv 
            
            al = block.call(:secure_random_engine_name)
            algo = al if not_empty?(al)
          else
            algo = "NativePRNG"
          end

          if srJceProvider.nil? 
            @srEngine = java.security.SecureRandom.getInstance(algo)
          else
            @srEngine = java.security.SecureRandom.getInstance(algo,srJceProvider)
          end
        end

        @srEngine
      end


    end
  end
end
