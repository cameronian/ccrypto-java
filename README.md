# Ccrypto::Java

This project is the Java implementation for the [Ccrypto](https://github.com/cameronian/ccrypto) Common Crypto API.

This collection of API is meant to normalize the differences between runtimes. 

Another notable implementation is [Ruby](https://github.com/cameronian/ccrypto-ruby).



## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ccrypto'
gem 'ccrypto-java'
```

Note that gem 'ccrypto' need to precede 'ccrypto-java'

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install ccrypto
    $ gem install ccrypto-java

## Usage

All operations is driven by the config object in [Ccrypto](https://github.com/cameronian/ccrypto).

The following are some common operations that can easily be initiated via the respective config object.

The value of [Ccrypto](https://github.com/cameronian/ccrypto) is the following codes should have same result when run with Ruby runtime using [ccrypto-ruby](https://github.com/cameronian/ccrypto-ruby) gem.


### Generate Secret Key

```ruby
# Ccrypto::KeyConfig is the object for secret key generation
keyConfig = Ccrypto::KeyConfig.new
keyConfig.algo = :aes
keyConfig.keysize = 256

# instantiate the key generator by giving the class of Ccrypto::KeyConfig
# There are two ways to instantiate: with class and with instance.
# There are some engine which provides class methods which can be call when passing in the class.
# Engine that provides instance method requires to pass in the instance to instantiate.

keyGen = Ccrypto::AlgoFactory.engine(Ccrypto::KeyConfig)
key = keyGen.generate(keyConfig)
# key is now the AES key in 256 bits

```

### Encrypt & Decrypt with Secret Key

```ruby

# generate key
keyConfig = Ccrypto::KeyConfig.new
keyConfig.algo = :aes
keyConfig.keysize = 256

keyGen = Ccrypto::AlgoFactory.engine(Ccrypto::KeyConfig)
key = keyGen.generate(keyConfig)

cipherConfig = Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :gcm, padding: :pkcs5, key: key })

cipherConfig.cipherOps = :encrypt

# library shall generate missing component such as IV if required
# and store it back into the passed in config object
cipher = Ccrypto::AlgoFactory.engine(cipherConfig)

output = []
output << cipher.update(data)
output << cipher.update(data)

output << cipher.final

res = output.join

# Encryption done!
# res now is the encrypted data

```


### Decrypt with Secret Key

```ruby

decConfig = Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :gcm, padding: :pkcs5, key: key, iv: cipherConfig.iv })

# GCM mode has this additional tag
decConfig.auth_tag = cipherConfig.auth_tag

deCipher = Ccrypto::AlgoFactory.engine(decConfig)

dres = []
dres << deCipher.update(res)
dres << deCipher.final

# decryption done!
# dres is the decrypted output

```


### Digest / Hashing

```ruby

digest = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig)

digest.digest_update("data to be digested")
res = digest.digest_final

# res is the digest output in String

hres = digest.digest_final(:hex)
# hres is the digest output converted to hex

b64res = digest.digest_final(:b64)
# b64res is the digest output converted to Base64

```


### ECC key generation

```ruby
# set the required curve name
eccConfig = CCrypto::ECCConfig.new("secp256k1")
ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig)
eccKey = ecc.generate_keypair

# eccKey shall be a ECC keypair

```


Refers to spec inside spec/ccrypto/xxx\_spec.rb



