
require_relative '../data_conversion'

module Ccrypto
  module Java
    class DigestEngine
      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper

      teLogger_tag :j_digest

      def self.supported
        if @supported.nil?
          @supported = {}
          probe = java.security.Security.getAlgorithms("MessageDigest").to_a.delete_if { |e| e.include?(".") }

          probe.each do |found|
            teLogger.debug "Found digest algo : #{found}"
            begin
              md = java.security.MessageDigest.getInstance(found, JCEProvider::BCProv)
              case found
              when "HARAKA-256"
                conf = { provider_config: { algo_name: found, jceProvider: JCEProvider::BCProv.name }, fixed_input_len_byte: 32 }
              when "HARAKA-512"
                conf = { provider_config: { algo_name: found, jceProvider: JCEProvider::BCProv.name }, fixed_input_len_byte: 64 }
              else
                conf = { provider_config: { algo_name: found, jceProvider: JCEProvider::BCProv.name } }
              end

              digConf = Ccrypto::DigestConfig.new(found, md.getDigestLength()*8, conf) 
              
              # only keep the key in symbol
              skey = found.downcase
              if skey =~ /-/
                key = skey.gsub("-","_").to_sym
                @supported[key] = digConf
                key2 = skey.gsub("-","").to_sym
                @supported[key2] = digConf
              else
                @supported[skey.to_sym] = digConf
              end

            rescue Exception => ex
              teLogger.error ex.message
            end
          end

        end
        @supported
      end

      def self.is_digest_supported?(key)
        (not find_digest_config(key).nil?)
      end

      def self.instance(conf, &block)

        case conf
        when String, Symbol
          digEng = find_digest_config(conf)
        when Ccrypto::DigestConfig
          digEng = conf
        else
          raise DigestEngineException, "Unsupported instance type '#{conf}'"
        end

        raise DigestEngineException, "Unsupported digest type '#{conf}'" if digEng.nil?

        prov = digEng.provider_config[:jceProvider]
        if not_empty?(prov)
          JCEProvider.instance.add_provider(prov) if not JCEProvider.instance.is_provider_registered?(prov)
          DigestEngine.new(digEng.provider_config[:algo_name], prov, &block)
        else
          DigestEngine.new(digEng.provider_config[:algo_name], &block)
        end

      end

      def self.find_digest_config(key)
        case key
        when String
          key.downcase.gsub("-","_").to_sym
        when Symbol
          key.to_s.downcase.to_sym
        end
        supported[key]
      end

      ##
      # Instance method
      ##
      def initialize(algo, prov = nil, &block)
        teLogger.debug "Algo : #{algo}"
        @algo =  algo #algo.to_s.gsub("_","-")
        begin
          if not_empty?(prov)
            @inst = java.security.MessageDigest.getInstance(@algo, prov)
          else
            @inst = java.security.MessageDigest.getInstance(@algo)
          end
        #rescue java.security.NoSuchAlgorithmException => ex
        rescue Exception => ex
          raise DigestEngineException, ex
        end
      end

      def digest(val, output = :binary)
        digest_final(val, output)
      end

      def digest_update(val)
        @inst.update(to_java_bytes(val))
      end

      def digest_final(val = nil, output = :binary)
        if not_empty?(val)
          @inst.update(to_java_bytes(val))
        end
        res = @inst.digest
        @inst.reset
        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end

      def reset
        @inst.reset
      end

    end
  end
end
