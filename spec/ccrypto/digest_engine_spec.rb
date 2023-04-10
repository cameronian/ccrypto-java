

RSpec.describe "Digest Engine for Java" do

  it 'generates digest from supported list' do
   
    require 'ccrypto/java'

    s2 = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig)
    expect(s2).not_to be nil

    s2.supported.each do |k,d|
      puts "Testing algo #{k}"

      de = Ccrypto::AlgoFactory.engine(d)
      expect(de).not_to be nil

      data = "password"
      #if d.provider_config =~ /HARAKA/
      if d.has_fixed_input_len_byte?
        # haraka requires input to be same as output size
        data = SecureRandom.random_bytes(d.fixed_input_len_byte)
      end

      res = de.digest(data)
      expect(res.length == d.outBitLength/8).to be true

      #de.reset

      # test update
      suspectResetBug = ["TUPLEHASH128-256","TUPLEHASH256-512"]
      if not suspectResetBug.include?(d.provider_config[:algo_name]) 
        de.digest_update(data[0...data.length/2])
        res2 = de.digest_final(data[data.length/2..-1])
        expect(res2 == res).to be true

        hres = de.digest(data, :hex)
        de.reset
        de.digest_update(data[0...data.length/2])
        hres2 = de.digest_final(data[data.length/2..-1], :hex)
        expect(hres2 == hres).to be true

        de.reset
        bres = de.digest(data,:b64)
        de.reset
        de.digest_update(data[0...(data.length/2)-1])
        bres2 = de.digest_final(data[(data.length/2)-1..-1],:b64)
        expect(bres2 == bres).to be true
      end
    end

    #expect { Ccrypto::AlgoFactory.engine(Ccrypto::SHAKE128) }.to raise_exception(Ccrypto::DigestEngineException)

  end

end
