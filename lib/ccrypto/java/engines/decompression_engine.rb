
require_relative '../data_conversion'

module Ccrypto
  module Java
    class Decompression
      include DataConversion
      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :j_decompression

      def initialize(*args,&block)
       
        @eng = java.util.zip.Inflater.new

        @os = java.io.ByteArrayOutputStream.new

      end

      def update(val)
        teLogger.debug "Given #{val.length} bytes for decompression"
        if val.length > 0

          @eng.setInput(to_java_bytes(val))

          baos = java.io.ByteArrayOutputStream.new
          buf = ::Java::byte[102400].new
          while not @eng.finished
            done = @eng.inflate(buf)
            teLogger.debug "Done #{done} bytes"
            @os.write(buf,0,done)
          end

          @os.toByteArray

        else
          ::Java::byte[0].new

        end
      end

      def final
      end

    end
  end
end
