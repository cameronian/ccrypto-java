
require_relative '../data_conversion'

module Ccrypto
  module Java
    class Compression
      include DataConversion
      include TR::CondUtils

      include TeLogger::TeLogHelper

      teLogger_tag :j_compression

      def initialize(*args, &block)

        @config = args.first
        raise CompressionError, "Compress Config is expected. Given #{@config}" if not @config.is_a?(Ccrypto::CompressionConfig)
        
        #if block

        #  outPath = block.call(:out_path)
        #  if is_empty?(outPath)
        #    outFile = block.call(:out_file) 
        #    raise CompressionError, "OutputStream required" if not outFile.is_a?(java.io.OutputStream)
        #    @out = outFile
        #  else
        #    @out = java.io.RandomAccessFile.new(java.io.File.new(outPath), "w")
        #  end

        #  @intBufSize = block.call(:int_buf_size) || 102400

        #else
        #  @intBufSize = 102400

        #end

        #@in = java.io.RandomAccessFile.new(java.nio.file.Files.createTempFile(nil,".zl").toFile, "rw")
        #@inPtr = 0

        case @config.level
        when :best_compression
          teLogger.debug "Compression with best compression"
          @eng = java.util.zip.Deflater.new(java.util.zip.Deflater::BEST_COMPRESSION)
        when :best_speed
          teLogger.debug "Compression with best speed"
          @eng = java.util.zip.Deflater.new(java.util.zip.Deflater::BEST_SPEED)
        when :no_compression
          teLogger.debug "No compression"
          @eng = java.util.zip.Deflater.new(java.util.zip.Deflater::NO_COMPRESSION)
        else
          teLogger.debug "Default compression"
          @eng = java.util.zip.Deflater.new(java.util.zip.Deflater::DEFAULT_COMPRESSION)
        end

        teLogger.debug "Default strategy"
        @eng.setStrategy(java.util.zip.Deflater::DEFAULT_STRATEGY)

        @os = java.io.ByteArrayOutputStream.new
        
      end

      # returns compressed output length
      def update(val)
        if val.length > 0
          teLogger.debug "Given #{val.length} bytes for compression"
          #teLogger.debug "Write ready-to-compress data : #{val.length}"
          #@in.write(to_java_bytes(val))

          @eng.setInput(to_java_bytes(val))

          @eng.finish

          baos = java.io.ByteArrayOutputStream.new
          buf = ::Java::byte[102400].new
          while not @eng.finished
            done = @eng.deflate(buf)
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
