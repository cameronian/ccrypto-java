
require 'singleton'

module Ccrypto
  module Java
    
    class JCEProviderException < StandardError; end

    class JCEProvider
      include Singleton

      BCProv = org.bouncycastle.jce.provider.BouncyCastleProvider.new
      DEFProv = BCProv

      def add_provider(prov = nil)
        case prov
        when java.security.Provider
          java.security.Security.add_provider(prov) if not is_provider_registered?(prov)
        else
          java.security.Security.add_provider(DEFProv) if not is_provider_registered?(DEFProv)	
        end
      end

      def is_provider_registered?(prov)
        case prov
        when String
          java.security.Security.providers.to_a.map { |v| v.name }.include?(prov)
        when java.security.Provider
          java.security.Security.get_providers.to_a.include?(prov)
        else
          false
        end
      end

      def add_bc_provider
        add_provider
      end

      #def set_default_provider(prov)

      #  case prov
      #  when String
      #  when java.security.Provider
      #    add_provider(prov) if not is_provider_registered?(prov)
      #    @defProvider = prov
      #  end

      #end

    end
  end
end
