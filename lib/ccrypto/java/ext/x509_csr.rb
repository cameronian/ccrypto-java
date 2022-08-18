

module Ccrypto
  class X509CSR
    include TR::CondUtils
    
    include TeLogger::TeLogHelper
    teLogger_tag :j_x509csr

    def initialize(csr)
      @nativeCSR = csr
    end

    def to_bin
      @nativeCSR.encoded
    end

    def to_pem

      baos = java.io.ByteArrayOutputStream.new

      writer = org.bouncycastle.openssl.jcajce.JcaPEMWriter.new(java.io.OutputStreamWriter.new(baos))

      begin
        writer.writeObject(@nativeCSR)
      ensure
        writer.flush
        writer.close  
      end 

      baos.toByteArray
      
    end

    def csr_info
      if @csrInfo.nil?
        @csrInfo = parseCSR(@nativeCSR)
      end
      @csrInfo
    end

    def parseCSR(csrBin)

      case csrBin
      when ::Java::byte[]
        csr = org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest.new(csrBin)
      when String
        # this assumed input is a PEM formatted content
        reader = org.bouncycastle.openssl.PEMParser.new(java.io.InputStreamReader.new(java.io.ByteArrayInputStream.new(csrBin)))
        csr = reader.readObject
      when Ccrypto::X509CSR
        csr = csrBin.nativeCSR
      else
        raise X509CSRException, "Unknown how to handle CSR of format #{csrBin.class}"
      end


      cvProv = org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder.new.build(csr.getSubjectPublicKeyInfo)
      raise X509CSRSignatureInvalid, "CSR signature is not valid" if not csr.isSignatureValid(cvProv)

      certProfile = Ccrypto::X509::CertProfile.new

      subj = csr.getSubject.to_s
      subj.split(",").each do |e|
        ee = e.split("=")
        case ee[0]
        when "CN"
          certProfile.owner_name = ee[1]
        when "O"
          certProfile.org = ee[1]
        when "OU"
          certProfile.org_unit = ee[1]
        when "E"
          certProfile.email = ee[1]
        end
      end


      pubKeyParam = org.bouncycastle.crypto.util.PublicKeyFactory.createKey(csr.subject_public_key_info)
      spec = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertToSpec(pubKeyParam.getParameters)
      point= org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertPoint(pubKeyParam.getQ)
      pubKeySpec = java.security.spec.ECPublicKeySpec.new(point, spec)
      certProfile.public_key = Ccrypto::Java::ECCPublicKey.new(java.security.KeyFactory.getInstance("EC").generatePublic(pubKeySpec))

      csr.attributes.each do |att|
     
        ext = org.bouncycastle.asn1.x509.Extensions.getInstance(att.getAttrValues.getObjectAt(0))

        gns = org.bouncycastle.asn1.x509.GeneralNames.fromExtensions(ext,org.bouncycastle.asn1.x509.Extension.subjectAlternativeName)
        gns.getNames.each do |n|
          #p n.getTagNo
          case n.getTagNo
          when org.bouncycastle.asn1.x509.GeneralName.dNSName
            certProfile.dns_name = n.getName.to_s
          when org.bouncycastle.asn1.x509.GeneralName.iPAddress
            val = org.bouncycastle.asn1.DEROctetString.getInstance(n.getName.toASN1Primitive).getOctets
            begin
              certProfile.ip_addr = java.net.InetAddress.getByAddress(val).getHostAddress
            rescue java.net.UnknownHostException => ex
              certProfile.ip_addr = "Error decoding IP address : #{ex.message}"
              teLogger.error "Failed to decode IP address from CSR"
              teLogger.error ex.message
              teLogger.error ex.backtrace.join("\n")
            end
          when org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier
            certProfile.uri = n.getName.to_s
          when org.bouncycastle.asn1.x509.GeneralName.rfc822Name
            certProfile.email = n.getName.to_s
          when org.bouncycastle.asn1.x509.GeneralName.otherName
            ext = org.bouncycastle.asn1.x509.Extension.getInstance(n.getName)
            certProfile.custom_extension[ext.extnId.to_s] = { value: ext.extnValue.octets.to_s, critical: ext.critical?, type: :string }
          else
            teLogger.debug "Unknown field tag no #{n.getTagNo}"
          end
        end

        ext.oids.each do |o|
          v = ext.getExtension(o)
          next if v.extnId.to_s == org.bouncycastle.asn1.x509.Extension.subjectAlternativeName.to_s

          certProfile.custom_extension[v.extnId.to_s] = { value: v.extnValue.octets.to_s, critical: v.critical?, type: :string }
        end

      
      end

      certProfile
      
    end

  end
end
