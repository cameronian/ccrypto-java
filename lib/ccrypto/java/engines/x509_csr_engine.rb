

module Ccrypto
  module Java
    
    class X509CSREngine
      include TR::CondUtils
      include TeLogger::TeLogHelper
      teLogger_tag :j_csr

      def initialize(csrProf)
        @csrProfile = csrProf
      end

      def generate(privKey, &block)

        cp = @csrProfile

        subject = to_cert_subject(cp)

        signHash = cp.hashAlgo
        raise X509CSREngineException, "Certificate hash algorithm '#{signHash}' is not supported" if not DigestEngine.is_digest_supported?(signHash)

        provider = block.call(:jce_provider) if block

        if provider.nil?
          teLogger.debug "Adding default provider"
          prov = Ccrypto::Java::JCEProvider::DEFProv
        else
          teLogger.debug "Adding provider #{provider.name}"
          prov = Ccrypto::Java::JCEProvider.add_provider(provider)
        end

        signHashVal = DigestEngine.find_digest_config(signHash).provider_config[:algo_name]
        signHashVal.gsub!("-","")

        signAlgo = nil
        gKey = privKey
        loop do
          case gKey
          when org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
            signAlgo = "#{signHashVal}WithECDSA"
            break
          when java.security.interfaces.RSAPrivateKey , org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
            signAlgo = "#{signHashVal}WithRSA"
            break
          when Ccrypto::PrivateKey
            teLogger.debug "Found Ccrypto::Private key #{gKey}."
            gKey = gKey.native_privKey
          else
            raise X509CSREngineException, "Unsupported signing key type '#{gKey}'"
          end
        end

        p10Builder = org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder.new(subject, cp.public_key)

        ext = []
        cp.email.each do |e|
          ext << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName.rfc822Name,e)
        end
        
        cp.dns_name.each do |dn|
          ext << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName.dNSName,dn)
        end

        cp.ip_addr.each do |ip|
          ext << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName.iPAddress,ip)
        end

        cp.uri.each do |u|
          ext << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier,u)
        end

        #cp.custom_extension.each do |k,v|
        #  val = v[:value]
        #  val = "" if is_empty?(val)
        #  ev = org.bouncycastle.asn1.x509.Extension.new(org.bouncycastle.asn1.DERObjectIdentifier.new(k), v[:critical], org.bouncycastle.asn1.DEROctetString.new(val.to_java.getBytes))
        #  ext << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName.otherName,ev)
        #end

        gn = org.bouncycastle.asn1.x509.GeneralNames.new(ext.to_java(org.bouncycastle.asn1.x509.GeneralName))
        eg = org.bouncycastle.asn1.x509.ExtensionsGenerator.new
        eg.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, gn)

        cp.custom_extension.each do |k,v|
          val = v[:value]
          val = "" if is_empty?(val)
          ev = org.bouncycastle.asn1.x509.Extension.new(org.bouncycastle.asn1.ASN1ObjectIdentifier.new(k), v[:critical], org.bouncycastle.asn1.DEROctetString.new(val.to_java.getBytes))
          eg.addExtension(ev)
        end


        p10Builder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, eg.generate)

        sign = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signAlgo).setProvider(prov).build(gKey)
        csr = p10Builder.build(sign)
        
        Ccrypto::X509CSR.new(csr)

      end


      private
      def to_cert_subject(cp)

        builder = org.bouncycastle.asn1.x500.X500NameBuilder.new
        builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::CN, cp.owner_name)

        builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::O, cp.org) if not_empty?(cp.org)

        cp.org_unit.each do |ou|
          builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::OU, ou)
        end

        e = cp.email.first
        if not_empty?(e)
          builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::EmailAddress, e) 
        end

        builder.build

      end

    end

  end
end
