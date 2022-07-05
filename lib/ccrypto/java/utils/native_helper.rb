

module Ccrypto
  module Java

    class NativeHelper

      def self.is_byte_array?(dat)
        if not dat.nil?
          dat.is_a?(::Java::byte[])
        else
          false
        end
      end

    end
    
  end
end
