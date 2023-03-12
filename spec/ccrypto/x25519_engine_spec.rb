
class DC
  extend Ccrypto::Java::DataConversion
end

RSpec.describe "X25519 engine spec" do

  it 'generates X25519 keypair and derives session key' do
   
    conf = Ccrypto::X25519Config.new
    eng = Ccrypto::AlgoFactory.engine(conf)
    kp1 = eng.generate_keypair
    kp2 = eng.generate_keypair
    expect(kp1).not_to be nil
    expect(kp2).not_to be nil

    sec1 = kp1.derive_dh_shared_secret(kp2.public_key)
    expect(sec1).not_to be nil
    sec2 = kp2.derive_dh_shared_secret(kp1.public_key)
    expect(sec2).not_to be nil

    expect(sec1 == sec2).to be true

    # dump the key into binary format
    res = kp1.to_storage

    seng = Ccrypto::AlgoFactory.engine(Ccrypto::X25519KeyBundle)
    # load the encoded binary key into system again
    rres = seng.from_storage(res)

    rkp1 = rres[:keypair]

    rsec1 = rkp1.derive_dh_shared_secret(kp2.public_key)
    expect(rsec1 == sec1).to be true

    #res2 = kp1.to_storage do |k,v|
    #  case k
    #  when :export_raw_private_key
    #    true
    #  when :export_raw_public_key
    #    true
    #  end
    #end

    #rres2 = seng.from_storage(res2)
    #rrkp1 = rres2[:keypair]

    #puts "Public : #{DC.to_hex(kp1.public_key.to_bin)}"
    #puts "R-Public : #{DC.to_hex(rrkp1.public_key.to_bin)}"

    #puts "Private : #{DC.to_hex(kp1.private_key.to_bin)}"
    #puts "R-Private : #{DC.to_hex(rrkp1.private_key.to_bin)}"

    #rrsec1 = rrkp1.derive_dh_shared_secret(kp2.public_key)
    #expect(rrsec1 == sec1).to be true

  end

end
