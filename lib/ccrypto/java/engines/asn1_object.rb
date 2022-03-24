

module Ccrypto
  module Java
    class ASN1Object < Ccrypto::ASN1Object

      def to_bin
        @asn1.encoded
      end
    end
  end
end
