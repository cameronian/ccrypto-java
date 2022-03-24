

RSpec.describe "Secret Sharing on Java" do

  it 'split a secret into n number of share k' do
  
    ssc = Ccrypto::SecretSharingConfig.new
    ssc.split_into = 5
    ssc.required_parts = 3
    ss = Ccrypto::AlgoFactory.engine(ssc)
    expect(ss).not_to be nil

    sr = Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig)
    
    secret = sr.random_bytes(32)

    splits = ss.split(secret)
    expect(splits).not_to be nil
    expect(splits.length == ssc.split_into).to be true

    ssr = Ccrypto::AlgoFactory.engine(Ccrypto::SecretSharingConfig)

    cnt = 0
    loop do
      sel = splits.to_a.sample(3).to_h
      puts "Selected splits : #{sel.keys.join(", ")}"
      rec = ssr.combine(ssc.required_parts, sel)
      expect(rec == secret).to be true

      cnt += 1
      break if cnt >= 5
    end

    # create a fake share
    sel = splits.to_a.sample(2).to_h
    nonSelKeys = splits.keys - sel.keys

    sel[nonSelKeys.first] = sr.random_bytes(32)

    bad = ssr.combine(ssc.required_parts, sel)
    expect(bad != secret).to be true

  end

end
