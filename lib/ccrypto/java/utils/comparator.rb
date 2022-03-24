
require_relative '../data_conversion'

module Ccrypto
  module Java
    class ComparatorUtil
      extend DataConversion

      def self.is_equal?(val1, val2)

        bval1 = to_java_bytes(val1) 
        bval2 = to_java_bytes(val2)

        bval1 == bval2
      end
      self.singleton_class.alias_method :is_equals?, :is_equal?

    end
  end
end
