

module Ccrypto
  module Java
    class SecretKeyEngine
     
      def self.generate(*args, &block)
        config = args.first

        raise SecretKeyEngineException, "KeyConfig is expected" if not config.is_a?(Ccrypto::KeyConfig) 

        if block
          kgProv = block.call(:keygen_jceProvider)
          ranProv = block.call(:random_jceProvider)
        end

        if kgProv.nil?
          logger.debug "KeyGen using algo #{config.algo.to_s} with null provider"
          keyGen = javax.crypto.KeyGenerator.getInstance(config.algo.to_s)
        else
          logger.debug "KeyGen using algo #{config.algo.to_s} with provider #{kgProv.is_a?(String) ? kgProv : kgProv.name}"
          keyGen = javax.crypto.KeyGenerator.getInstance(config.algo.to_s, kgProv)
        end

        if ranProv.nil?
          logger.debug "Init KeyGen with keysize #{config.keysize.to_i}"
          keyGen.init(config.keysize.to_i)
        else
          logger.debug "Init KeyGen with keysize #{config.keysize.to_i} with provider #{ranProv.is_a?(String) ? ranProv : ranProv.name}"
          keyGen.init(config.keysize.to_i, ranProv)
        end

        key = keyGen.generateKey
        logger.debug "Secret key #{config} generated"
        Ccrypto::SecretKey.new(config.algo, key)

      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :sk_eng
        end
        @logger
      end

    end
  end
end
