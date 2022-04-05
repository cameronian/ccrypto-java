

module Ccrypto
  module Java
    module DataConversion
      
      def to_hex(bin)
        String.from_java_bytes(org.bouncycastle.util.encoders.Hex.encode(bin))
      end
      # end to_hex

      def from_hex(str)
        org.bouncycastle.util.encoders.Hex.decode(str)
      end
      # end from_hex

      def to_b64(bin)
        String.from_java_bytes(java.util.Base64.encoder.encode(bin))
      end
      # end to_b64
      #

      def to_b64_mime(bin)
        String.from_java_bytes(java.util.Base64.mime_encoder.encode(bin))
      end

      def from_b64(str)
        java.util.Base64.decoder.decode(str)
      end
      # end from_b64

      def to_str(bin)
        if bin.is_a?(::Java::byte[])
          String.from_java_bytes(bin)
        else
          bin
        end
      end

      def to_bin(str)
        if str.nil?
          ::Java::byte[0].new
        else
          str.to_java.getBytes
        end
      end

      def to_java_bytes(val, encoding = nil)
        case val
        when String
          val.to_java_bytes
        when java.lang.String
          if not_empty?(encoding)
            val.getBytes(encoding)
          else
            val.getBytes
          end
        when Ccrypto::Java::ManagedMemoryBuffer
          val.bytes
        else
          val
        end
      end

    end
  end
end
