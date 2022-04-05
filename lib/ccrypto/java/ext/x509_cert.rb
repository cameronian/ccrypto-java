

module Ccrypto
  class X509Cert
    include TR::CondUtils
 
    def to_der
      @nativeX509.encoded
    end

    def method_missing(mtd, *args, &block)
      @nativeX509.send(mtd, *args, &block)
    end

    def equal?(cert)
      if cert.nil?
        if @nativeX509.nil?
          true
        else
          false
        end
      else

        tcert = self.class.to_java_cert(cert)
        lcert = self.class.to_java_cert(@nativeX509)

        tcert.encoded == @nativeX509.encoded
      end
    end

    def self.to_java_cert(cert)
      raise X509CertException, "Given certificate to convert to Java certificate object is empty" if is_empty?(cert) 

      #logger.debug "Given cert #{cert}"
      case cert
      when java.security.cert.Certificate
        cert
      when org.bouncycastle.cert.X509CertificateHolder
        cert.to_java_cert
      when Ccrypto::X509Cert
        to_java_cert(cert.nativeX509)
      else
        raise X509CertException, "Unknown certificate type #{cert} for conversion"
      end

    end

    def self.logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :x509Cert
      end
      @logger
    end
    def logger
      self.class.logger
    end

  end
end
