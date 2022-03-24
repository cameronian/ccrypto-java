

RSpec.describe "Secure random for Java" do

  it 'generates secure random no' do
    
    sr = Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig)
    expect(sr).not_to be nil

    out = sr.random_hex(10)
    expect(out).not_to be nil
    expect(out.length == 20).to be true

    bout = sr.random_b64(10)
    expect(bout).not_to be nil

    (0..20).each do |i|
      r = sr.random_number(10..20)
      expect(r >= 10 && r <= 20).to be true
    end

  end

end
