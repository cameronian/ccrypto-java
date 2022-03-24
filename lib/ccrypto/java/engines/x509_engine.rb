
module Ccrypto
  module Java

    class X509Engine
      include TR::CondUtils

      def initialize(certProf)
        @certProfile = certProf
      end

      def generate(issuerKey, &block)

        cp = @certProfile

        prov = Ccrypto::Java::JCEProvider::DEFProv
        if block
          uprov = block.call(:jce_provider_name)
          prov if not_empty?(uprov)
        end

        validFrom = cp.not_before 
        validTo = cp.not_after

        extUtils = org.bouncycastle.cert.bc.BcX509ExtensionUtils.new

        if cp.serial.is_a?(java.math.BigInteger)
          serial = cp.serial
        else
          serial = java.math.BigInteger.new(cp.serial, 16)
        end

        iss = cp.issuer_cert
        if not_empty?(iss) 
          raise X509EngineException, "Issuer certificate must be X509 Certificate object (#{iss.class})" if not iss.is_a?(java.security.cert.Certificate)

          certGen = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(iss, serial, validFrom, validTo, to_cert_subject, cp.public_key)
          certGen.addExtension(org.bouncycastle.asn1.x509.Extension::authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(iss.getPublicKey.to_bin)))

        else

          name = to_cert_subject
          certGen = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(name, serial, validFrom, validTo, name, cp.public_key.native_pubKey)
          certGen.addExtension(org.bouncycastle.asn1.x509.Extension::authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(cp.public_key.to_bin)))
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints.new(true)) if cp.gen_issuer_cert?

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(to_keyusage))

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(to_extkeyusage))

        altName = []
        cp.email.each do |e|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,e)
        end

        cp.dns_name.each do |d|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,d)
        end

        cp.ip_addr.each do |d|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,d)
        end

        cp.uri.each do |u|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier,u)
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::subjectAlternativeName, false, org.bouncycastle.asn1.x509.GeneralNames.new(altName.to_java(org.bouncycastle.asn1.x509.GeneralName)) )

        if not_empty?(cp.crl_dist_point)
          crl = []
          cp.crl_dist_point.each do |c|
            crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(c));
          end
          gns = org.bouncycastle.asn1.x509.GeneralNames.new(crls.to_java(org.bouncycastle.asn1.x509.GeneralName));
          dpn = org.bouncycastle.asn1.x509.DistributionPointName.new(gns);
          dp =  org.bouncycastle.asn1.x509.DistributionPoint.new(dpn,nil,nil);
          certGen.addExtension(org.bouncycastle.asn1.x509.X509Extensions::CRLDistributionPoints,false,org.bouncycastle.asn1.DERSequence.new(dp));      
        end

        if not_empty?(cp.ocsp_url)
          # todo multiple ocsp
          ocspName = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier, cp.ocsp_url.first);
          authorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess.new(org.bouncycastle.asn1.x509.X509ObjectIdentifiers.ocspAccessMethod, ocspName);
          certGen.addExtension(org.bouncycastle.asn1.x509.X509Extensions::AuthorityInfoAccess, false, authorityInformationAccess);			  
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(cp.public_key.to_bin)))

        signAlgo = "SHA256WithECDSA"
        signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signAlgo).setProvider(prov).build(issuerKey.private_key)

        cert = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter.new().setProvider(prov).getCertificate(certGen.build(signer))
        cert

      end

      def to_cert_subject

        builder = org.bouncycastle.asn1.x500.X500NameBuilder.new
        builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::CN, @certProfile.owner_name)

        builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::O, @certProfile.org) if not_empty?(@certProfile.org)

        @certProfile.org_unit.each do |ou|
          builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::OU, ou)
        end

        #builder.addRDN(Java::OrgBouncycastleAsn1X500Style::BCStyle::SN, serial) if @serial != nil and not @serial.empty?

        e = @certProfile.email.first
        if not_empty?(e)
          builder.addRDN(org.bouncycastle.asn1.x500.style::BCStyle::EmailAddress, e) 
        end

        builder.build

      end

      def to_keyusage
        kur = 0
        @certProfile.key_usage.selected.each do |ku|
          case ku
          when :digitalSignature
            kur |= org.bouncycastle.asn1.x509::KeyUsage::digitalSignature
          when :nonRepudiation
            kur |= org.bouncycastle.asn1.x509::KeyUsage::nonRepudiation
          when :keyEncipherment
            kur |= org.bouncycastle.asn1.x509::KeyUsage::keyEncipherment
          when :dataEncipherment
            kur |= org.bouncycastle.asn1.x509::KeyUsage::dataEncipherment
          when :keyAgreement
            kur |= org.bouncycastle.asn1.x509::KeyUsage::keyAgreement
          when :keyCertSign
            kur |= org.bouncycastle.asn1.x509::KeyUsage::keyCertSign
          when :crlSign
            kur |= org.bouncycastle.asn1.x509::KeyUsage::cRLSign
          when :encipherOnly
            kur |= org.bouncycastle.asn1.x509::KeyUsage::encipherOnly
          when :decipherOnly
            kur |= org.bouncycastle.asn1.x509::KeyUsage::decipherOnly
          end
        end

        kur
      end

      def to_extkeyusage
        kur = java.util.Vector.new
        @certProfile.ext_key_usage.selected.each do |ku|
          case ku
          when :allPurpose
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::anyExtendedKeyUsage
          when :serverAuth
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_serverAuth
          when :clientAuth
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_clientAuth
          when :codeSigning
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_codeSigning
          when :emailProtection
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_emailProtection
          when :timestamping
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_timeStamping
          when :ocspSigning
            kur.add_element org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_OCSPSigning
          end
        end

        kur
      end

    end

  end
end