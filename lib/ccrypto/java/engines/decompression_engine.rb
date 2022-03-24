
require_relative '../data_conversion'

module Ccrypto
  module Java
    class Decompression
      include DataConversion
      include TR::CondUtils

      def initialize(*args,&block)
       
        @eng = java.util.zip.Inflater.new

        @os = java.io.ByteArrayOutputStream.new

      end

      def update(val)
        logger.debug "Given #{val.length} bytes for decompression"
        if val.length > 0

          @eng.setInput(to_java_bytes(val))

          baos = java.io.ByteArrayOutputStream.new
          buf = ::Java::byte[102400].new
          while not @eng.finished
            done = @eng.inflate(buf)
            logger.debug "Done #{done} bytes"
            @os.write(buf,0,done)
          end

          @os.toByteArray

        else
          ::Java::byte[0].new

        end
      end

      def final
      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :decomp
        end
        @logger
      end

    end
  end
end
