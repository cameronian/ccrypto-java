
require_relative '../data_conversion'

module Ccrypto
  module Java
    class ManagedMemoryBuffer
      include DataConversion

      def initialize(*args, &block)
        @raf = java.io.RandomAccessFile.new(java.nio.file.Files.createTempFile(nil,".ccl").toFile, "rw")
      end

      def bytes
        buf = ::Java::byte[@raf.length].new
        @raf.seek(0)
        @raf.read_fully(buf)
        buf
      end

      # Return current cursor position
      def pos
        @raf.getFilePointer
      end

      def length
        @raf.length
      end

      def rewind
        @raf.seek(0)
      end

      def dispose(wcnt = 32)
        len = @raf.length
        @raf.seek(0)
       
        cnt = 0
        loop do
          @raf.write(SecureRandomEngine.random_bytes(len))
          @raf.seek(0)

          cnt += 1
          break if cnt >= wcnt
        end

        @raf = nil
        GC.start
      end

      def write(val)
        @raf.write(to_java_bytes(val))
      end

      def read(len)
        buf = ::Java::byte[len].new
        @raf.read(buf,0,len)
        buf
      end

      def respond_to_missing?(mtd, *args, &block)
        @raf.respond_to?(mtd, *args, &block)
      end

      def equals?(val)
        case val
        when ::Java::byte[]
          bytes == val
        when String
          bytes == to_java_bytes(val)
        else
          raise MemoryBufferException, "Unknown how to compare with #{val}"
        end
      end

    end
  end
end
