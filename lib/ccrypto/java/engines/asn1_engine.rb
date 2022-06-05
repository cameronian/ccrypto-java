
require 'java'

require_relative 'asn1_object'

require_relative '../data_conversion'

module Ccrypto
  module Java
    
    class ASN1Engine
      include TR::CondUtils
      extend DataConversion

      include TeLogger::TeLogHelper

      teLogger_tag :j_asn1

      def self.build(*args,&block)
        type = args.first
        val = args[1]
        case type
        when :oid
          ASN1Object.new(type,org.bouncycastle.asn1.ASN1ObjectIdentifier.new(val))

        when :seq
          v = org.bouncycastle.asn1.ASN1EncodableVector.new
          val.each do |vv|
            v.add(vv)
          end
          ASN1Object.new(type,org.bouncycastle.asn1.DERSequence.new(v))

        when :str, :utf8_str
          ASN1Object.new(type,org.bouncycastle.asn1.DERUTF8String.new(val.to_s))

        when :octet_str
          if val.is_a?(Array)
            val = val.pack("c*").to_java_bytes
          elsif val.respond_to?(:to_bin)
            val = val.to_bin
          end

          ASN1Object.new(type, val)

        when :int
          ASN1Object.new(type,org.bouncycastle.asn1.DERInteger.new(val))
          #Java::OrgBouncycastleAsn1::DERInteger.new(val)

        when :bin
          ASN1Object.new(type,org.bouncycastle.asn1.DERBitString.new(to_java_bytes(val)))
          #baos = java.io.ByteArrayOutputStream.new
          #aos = org.bouncycastle.asn1.ASN1OutputStream.new(baos)
          #aos.writeObject(org.bouncycastle.asn1.DERBitString.new(to_java_bytes(val)))
          #aos.flush
          #aos.close

          #baos

        when :date, :time, :generalize_time
          if val.is_a?(Time)
            val = val.to_java
          elsif not val.is_a?(java.util.Date)
            raise ASN1EngineException, "Unknown datetime objec to convert ['#{val.class}']"
          end
          
          #ASN1Object.new(type,org.bouncycastle.asn1.DERUTCTime.new(val))
          ASN1Object.new(type,org.bouncycastle.asn1.DERGeneralizedTime.new(val))

        else
          raise ASN1EngineException, "Unknown ASN1 Object type '#{type.class}'"
        end
      end


      def self.to_value(*args, &block)

        val = args.first
        #teLogger.debug "Received #{val}"

        expectedType = args[1]

        if val.is_a?(::Java::byte[])
          ais = org.bouncycastle.asn1.ASN1InputStream.new(val)
          tag = ais.readObject
        elsif val.is_a?(String)
          ais = org.bouncycastle.asn1.ASN1InputStream.new(val.to_java_bytes)
          tag = ais.readObject
        else
          tag = val
        end
        #raise ASN1EngineException, "Byte array is expected" if not val.is_a?(::Java::byte[])

        #teLogger.debug "Tag : #{tag} / #{tag.class}"

        case tag
        when org.bouncycastle.asn1.ASN1ObjectIdentifier
          tag.id

        when org.bouncycastle.asn1.DEROctetString
          tag.octets

        when org.bouncycastle.asn1.ASN1Integer
          #tag.int_value_exact
          tag.value

        when org.bouncycastle.asn1.DLSequence, org.bouncycastle.asn1.DERSequence
          tag.to_a

        when org.bouncycastle.asn1.DERUTF8String, org.bouncycastle.asn1.DERPrintableString, org.bouncycastle.asn1.DERVisibleString
          tag.to_s

        when org.bouncycastle.asn1.DERNumericString
          "#{tag.to_i}"

        when org.bouncycastle.asn1.DERUTCTime, org.bouncycastle.asn1.ASN1UTCTime, org.bouncycastle.asn1.ASN1GeneralizedTime
          tag.date

        when org.bouncycastle.asn1.DERBitString
          tag.bytes

        else
          raise ASN1EngineException, "Unknown type '#{tag}'"
        end



      end

      def self.asn1_length(*args, &block)
        val = args.first
        if not_empty?(val)
          if val.is_a?(ASN1Object)
            v = val.native_asn1
          elsif val.is_a?(String)
            v = val.to_java_bytes
          else
            v = val
          end

          totalLen = 0

          ais = org.bouncycastle.asn1.ASN1InputStream.new(v)
          res = ais.readObject
          totalLen = res.encoded.length

          totalLen

        else
          0
        end
      end
      

    end

  end
end
