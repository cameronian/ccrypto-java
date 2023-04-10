
module Ccrypto
  module Java

    class X509Engine
      include TR::CondUtils

      include TeLogger::TeLogHelper

      teLogger_tag :j_x509

      def initialize(certProf)
        @certProfile = certProf
      end

      def generate(issuerKey, &block)
        if @certProfile.csr.nil?
          generate_from_cert_profile(@certProfile, issuerKey, &block)
        else
          generate_from_csr(@certProfile, issuerKey, &block)
        end
      end

      def generate_from_csr(cp, issuerKey, &block)

        csrObj = Ccrypto::X509CSR.new(cp.csr)
        csrCp = csrObj.csr_info

        #cp.dns_name = csrCp.dns_name
        #cp.ip_addr = csrCp.ip_addr
        #cp.uri = csrCp.uri

        raise X509EngineException, "Issuer key must be given" if issuerKey.nil?
        raise X509EngineException, "Issuer key must be a private key. Given #{issuerKey}" if not issuerKey.is_a?(Ccrypto::PrivateKey)

        prov = Ccrypto::Java::JCEProvider::DEFProv
        signHash = cp.hashAlgo
        signSpec = nil
        if block
          uprov = block.call(:jce_provider_name)
          prov if not_empty?(uprov)
          signSpec = block.call(:sign_spec)
          signHash = block.call(:sign_hash) if is_empty?(signHash)
        end

        signHash = :sha256 if is_empty?(signHash)
        raise X509EngineException, "Given digest algo '#{signHash}' is not suported" if not DigestEngine.is_digest_supported?(signHash)

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
          raise X509EngineException, "Issuer certificate must be Ccrypto::X509Cert object (#{iss.class})" if not iss.is_a?(Ccrypto::X509Cert) #iss.is_a?(java.security.cert.Certificate)

          certGen = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(Ccrypto::X509Cert.to_java_cert(iss), serial, validFrom, validTo, to_cert_subject(csrCp), csrCp.public_key)
          certGen.addExtension(org.bouncycastle.asn1.x509.Extension::authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(iss.getPublicKey.encoded)))

        else

          name = to_cert_subject(csrCp)
          certGen = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(name, serial, validFrom, validTo, name, csrCp.public_key.native_pubKey)
          certGen.addExtension(org.bouncycastle.asn1.x509.Extension::authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(csrCp.public_key.to_bin)))
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints.new(true)) if cp.gen_issuer_cert?

        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(to_keyusage))
        #criticalKu = 0
        #nonCriticalKu = 0
        kuv = 0
        criticalKu = false
        cp.key_usage.selected.each do |ku, critical|
          case ku
          when :digitalSignature
            kur = org.bouncycastle.asn1.x509::KeyUsage::digitalSignature
          when :nonRepudiation
            kur = org.bouncycastle.asn1.x509::KeyUsage::nonRepudiation
          when :keyEncipherment
            kur = org.bouncycastle.asn1.x509::KeyUsage::keyEncipherment
          when :dataEncipherment
            kur = org.bouncycastle.asn1.x509::KeyUsage::dataEncipherment
          when :keyAgreement
            kur = org.bouncycastle.asn1.x509::KeyUsage::keyAgreement
          when :keyCertSign
            kur = org.bouncycastle.asn1.x509::KeyUsage::keyCertSign
          when :crlSign
            kur = org.bouncycastle.asn1.x509::KeyUsage::cRLSign
          when :encipherOnly
            kur = org.bouncycastle.asn1.x509::KeyUsage::encipherOnly
          when :decipherOnly
            kur = org.bouncycastle.asn1.x509::KeyUsage::decipherOnly
          end

          criticalKu = critical if critical

          kuv |= kur

          #if critical
          #  criticalKu |= kur
          #else
          #  nonCriticalKu |= kur
          #end

        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, criticalKu, org.bouncycastle.asn1.x509.KeyUsage.new(kuv)) 
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, true, org.bouncycastle.asn1.x509.KeyUsage.new(criticalKu)) if criticalKu != 0
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(nonCriticalKu)) if nonCriticalKu != 0

        ekuCritical = false
        eku = java.util.Vector.new
        #ekuCritical = java.util.Vector.new
        #ekuNonCritical = java.util.Vector.new
        cp.ext_key_usage.selected.each do |ku,critical|
          case ku
          when :allPurpose
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::anyExtendedKeyUsage
          when :serverAuth
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_serverAuth
          when :clientAuth
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_clientAuth
          when :codeSigning
            kur =  org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_codeSigning
          when :emailProtection
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_emailProtection
          when :timeStamping
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_timeStamping
          when :ocspSigning
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_OCSPSigning
          end

          ekuCritical = critical if critical
          eku.add_element(kur)
          #if critical
          #  ekuCritical.add_element(kur)
          #else
          #  ekuNonCritical.add_element(kur)
          #end
        end

        #extKeyUsage = java.util.Vector.new
        cp.domain_key_usage.each do |dku, critical|
          #kur = org.bouncycastle.asn1.DERObjectIdentifier.new(dku)
          kur = org.bouncycastle.asn1.ASN1ObjectIdentifier.new(dku)

          ekuCritical = critical if critical
          eku.add_element(kur)
          #if critical
          #  ekuCritical.add_element(kur)
          #else
          #  ekuNonCritical.add_element(kur)
          #end
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, ekuCritical, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(eku)) if not_empty?(eku)
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, true, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(ekuCritical)) if not_empty?(ekuCritical)
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(ekuNonCritical)) if not_empty?(ekuNonCritical)
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(extKeyUsage)) if not extKeyUsage.is_empty?

        altName = []
        csrCp.email.uniq.each do |e|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::rfc822Name,e)
        end

        csrCp.dns_name.uniq.each do |d|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::dNSName,d)
        end

        csrCp.ip_addr.uniq.each do |d|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::iPAddress,d)
        end

        csrCp.uri.uniq.each do |u|
          altName << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier,u)
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::subjectAlternativeName, false, org.bouncycastle.asn1.x509.GeneralNames.new(altName.to_java(org.bouncycastle.asn1.x509.GeneralName)) )

        csrCp.custom_extension.each do |k, v|
          val = v[:value]
          val = "" if is_empty?(val)
          #ev = org.bouncycastle.asn1.x509.Extension.new(org.bouncycastle.asn1.DERObjectIdentifier.new(k), v[:critical], org.bouncycastle.asn1.DEROctetString.new(val.to_java.getBytes))
          ev = org.bouncycastle.asn1.x509.Extension.new(org.bouncycastle.asn1.ASN1ObjectIdentifier.new(k), v[:critical], org.bouncycastle.asn1.DEROctetString.new(val.to_java.getBytes))
          certGen.addExtension(ev)
        end


        if not_empty?(cp.crl_dist_point)
          crls = []
          cp.crl_dist_point.each do |c|
            crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(c))
          end
          gns = org.bouncycastle.asn1.x509.GeneralNames.new(crls.to_java(org.bouncycastle.asn1.x509.GeneralName))
          dpn = org.bouncycastle.asn1.x509.DistributionPointName.new(gns)
          dp =  org.bouncycastle.asn1.x509.DistributionPoint.new(dpn,nil,nil)
          certGen.addExtension(org.bouncycastle.asn1.x509.X509Extensions::CRLDistributionPoints,false,org.bouncycastle.asn1.DERSequence.new(dp))      
        end

        aia = []
        cp.ocsp_url.each do |o|
          ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(o))
          aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp, ov)
        end

        cp.issuer_url.each do |i|
          iv = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(i))
          aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers, iv)
        end

        if not_empty?(aia)
          authorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess.new(aia.to_java(org.bouncycastle.asn1.x509.AccessDescription))
          certGen.addExtension(org.bouncycastle.asn1.x509.X509Extensions::AuthorityInfoAccess, false, authorityInformationAccess)			  
        end


        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(csrCp.public_key.to_bin)))

        signAlgo = nil
        # alreacy check if digest algo exist or not at the entry of the method
        signHashVal = DigestEngine.find_digest_config(signHash).provider_config[:algo_name].gsub("-","")

        gKey = issuerKey
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
            raise X509EngineException, "Unsupported issuer key type '#{gKey}'"
          end
        end

        #signAlgo = "SHA256WithECDSA"
        #signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signAlgo).setProvider(prov).build(issuerKey.private_key)
        signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signAlgo).setProvider(prov).build(gKey)

        cert = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter.new().setProvider(prov).getCertificate(certGen.build(signer))
        cert

        Ccrypto::X509Cert.new(cert)

      end


      def generate_from_cert_profile(cp, issuerKey, &block)

        raise X509EngineException, "Issuer key must be given" if issuerKey.nil?
        raise X509EngineException, "Issuer key must be a private key. Given #{issuerKey}" if not issuerKey.is_a?(Ccrypto::PrivateKey)

        prov = Ccrypto::Java::JCEProvider::DEFProv
        signHash = cp.hashAlgo
        signSpec = nil
        if block
          uprov = block.call(:jce_provider_name)
          prov if not_empty?(uprov)
          signSpec = block.call(:sign_spec)
          signHash = block.call(:sign_hash) if is_empty?(signHash)
        end

        signHash = :sha256 if is_empty?(signHash)
        raise X509EngineException, "Given digest algo '#{signHash}' is not suported" if not DigestEngine.is_digest_supported?(signHash)

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
          raise X509EngineException, "Issuer certificate must be Ccrypto::X509Cert object (#{iss.class})" if not iss.is_a?(Ccrypto::X509Cert) #iss.is_a?(java.security.cert.Certificate)

          certGen = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(Ccrypto::X509Cert.to_java_cert(iss), serial, validFrom, validTo, to_cert_subject(cp), cp.public_key)
          certGen.addExtension(org.bouncycastle.asn1.x509.Extension::authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(iss.getPublicKey.encoded)))

        else

          name = to_cert_subject(cp)
          certGen = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder.new(name, serial, validFrom, validTo, name, cp.public_key.native_pubKey)
          certGen.addExtension(org.bouncycastle.asn1.x509.Extension::authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(cp.public_key.to_bin)))
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints.new(true)) if cp.gen_issuer_cert?

        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(to_keyusage))
        #criticalKu = 0
        #nonCriticalKu = 0
        kuv = 0
        criticalKu = false
        cp.key_usage.selected.each do |ku, critical|
          case ku
          when :digitalSignature
            kur = org.bouncycastle.asn1.x509::KeyUsage::digitalSignature
          when :nonRepudiation
            kur = org.bouncycastle.asn1.x509::KeyUsage::nonRepudiation
          when :keyEncipherment
            kur = org.bouncycastle.asn1.x509::KeyUsage::keyEncipherment
          when :dataEncipherment
            kur = org.bouncycastle.asn1.x509::KeyUsage::dataEncipherment
          when :keyAgreement
            kur = org.bouncycastle.asn1.x509::KeyUsage::keyAgreement
          when :keyCertSign
            kur = org.bouncycastle.asn1.x509::KeyUsage::keyCertSign
          when :crlSign
            kur = org.bouncycastle.asn1.x509::KeyUsage::cRLSign
          when :encipherOnly
            kur = org.bouncycastle.asn1.x509::KeyUsage::encipherOnly
          when :decipherOnly
            kur = org.bouncycastle.asn1.x509::KeyUsage::decipherOnly
          end

          criticalKu = critical if critical

          kuv |= kur

          #if critical
          #  criticalKu |= kur
          #else
          #  nonCriticalKu |= kur
          #end

        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, criticalKu, org.bouncycastle.asn1.x509.KeyUsage.new(kuv)) 
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, true, org.bouncycastle.asn1.x509.KeyUsage.new(criticalKu)) if criticalKu != 0
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::keyUsage, false, org.bouncycastle.asn1.x509.KeyUsage.new(nonCriticalKu)) if nonCriticalKu != 0

        ekuCritical = false
        eku = java.util.Vector.new
        #ekuCritical = java.util.Vector.new
        #ekuNonCritical = java.util.Vector.new
        cp.ext_key_usage.selected.each do |ku,critical|
          case ku
          when :allPurpose
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::anyExtendedKeyUsage
          when :serverAuth
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_serverAuth
          when :clientAuth
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_clientAuth
          when :codeSigning
            kur =  org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_codeSigning
          when :emailProtection
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_emailProtection
          when :timeStamping
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_timeStamping
          when :ocspSigning
            kur = org.bouncycastle.asn1.x509.KeyPurposeId::id_kp_OCSPSigning
          end

          ekuCritical = critical if critical
          eku.add_element(kur)
          #if critical
          #  ekuCritical.add_element(kur)
          #else
          #  ekuNonCritical.add_element(kur)
          #end
        end

        #extKeyUsage = java.util.Vector.new
        cp.domain_key_usage.each do |dku, critical|
          #kur = org.bouncycastle.asn1.DERObjectIdentifier.new(dku)
          kur = org.bouncycastle.asn1.ASN1ObjectIdentifier.new(dku)

          ekuCritical = critical if critical
          eku.add_element(kur)
          #if critical
          #  ekuCritical.add_element(kur)
          #else
          #  ekuNonCritical.add_element(kur)
          #end
        end

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, ekuCritical, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(eku)) if not_empty?(eku)
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, true, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(ekuCritical)) if not_empty?(ekuCritical)
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(ekuNonCritical)) if not_empty?(ekuNonCritical)
        #certGen.addExtension(org.bouncycastle.asn1.x509.Extension::extendedKeyUsage, false, org.bouncycastle.asn1.x509.ExtendedKeyUsage.new(extKeyUsage)) if not extKeyUsage.is_empty?

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

        cp.custom_extension.each do |k, v|
          val = v[:value]
          val = "" if is_empty?(val)
          #ev = org.bouncycastle.asn1.x509.Extension.new(org.bouncycastle.asn1.DERObjectIdentifier.new(k), v[:critical], org.bouncycastle.asn1.DEROctetString.new(val.to_java.getBytes))
          ev = org.bouncycastle.asn1.x509.Extension.new(org.bouncycastle.asn1.ASN1ObjectIdentifier.new(k), v[:critical], org.bouncycastle.asn1.DEROctetString.new(val.to_java.getBytes))
          certGen.addExtension(ev)
        end

        if not_empty?(cp.crl_dist_point)
          crls = []
          cp.crl_dist_point.each do |c|
            crls << org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(c))
          end
          gns = org.bouncycastle.asn1.x509.GeneralNames.new(crls.to_java(org.bouncycastle.asn1.x509.GeneralName))
          dpn = org.bouncycastle.asn1.x509.DistributionPointName.new(gns)
          dp =  org.bouncycastle.asn1.x509.DistributionPoint.new(dpn,nil,nil)
          certGen.addExtension(org.bouncycastle.asn1.x509.X509Extensions::CRLDistributionPoints,false,org.bouncycastle.asn1.DERSequence.new(dp))      
        end

        aia = []
        cp.ocsp_url.each do |o|
          ov = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(o))
          aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp, ov)
        end

        cp.issuer_url.each do |i|
          iv = org.bouncycastle.asn1.x509.GeneralName.new(org.bouncycastle.asn1.x509.GeneralName::uniformResourceIdentifier, org.bouncycastle.asn1.DERIA5String.new(i))
          aia << org.bouncycastle.asn1.x509.AccessDescription.new(org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers, iv)
        end

        if not_empty?(aia)
          authorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess.new(aia.to_java(org.bouncycastle.asn1.x509.AccessDescription))
          certGen.addExtension(org.bouncycastle.asn1.x509.X509Extensions::AuthorityInfoAccess, false, authorityInformationAccess)			  
        end


        certGen.addExtension(org.bouncycastle.asn1.x509.Extension::subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(cp.public_key.to_bin)))

        signAlgo = nil

        # alreacy check if digest algo exist or not at the entry of the method
        signHashVal = DigestEngine.find_digest_config(signHash).provider_config[:algo_name].gsub("-","")

        gKey = issuerKey
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
            raise X509EngineException, "Unsupported issuer key type '#{gKey}'"
          end
        end

        #signAlgo = "SHA256WithECDSA"
        #signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signAlgo).setProvider(prov).build(issuerKey.private_key)
        signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.new(signAlgo).setProvider(prov).build(gKey)

        cert = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter.new().setProvider(prov).getCertificate(certGen.build(signer))
        cert

        Ccrypto::X509Cert.new(cert)

      end

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

      #def to_keyusage
      #  kur = 0
      #  @certProfile.key_usage.selected.each do |ku|
      #    case ku
      #    when :digitalSignature
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::digitalSignature
      #    when :nonRepudiation
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::nonRepudiation
      #    when :keyEncipherment
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::keyEncipherment
      #    when :dataEncipherment
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::dataEncipherment
      #    when :keyAgreement
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::keyAgreement
      #    when :keyCertSign
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::keyCertSign
      #    when :crlSign
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::cRLSign
      #    when :encipherOnly
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::encipherOnly
      #    when :decipherOnly
      #      kur |= org.bouncycastle.asn1.x509::KeyUsage::decipherOnly
      #    end
      #  end

      #  kur
      #end

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
