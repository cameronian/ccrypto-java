# frozen_string_literal: true

require 'ccrypto'
require 'tlogger'
require 'toolrack'

Dir.glob(File.join(File.dirname(__FILE__),"..","..","jars","*.jar")).each do |f|
  require f
  #puts "Loaded #{f}"
end

require_relative 'java/jce_provider'
Ccrypto::Java::JCEProvider.instance.add_bc_provider

require_relative "java/version"

require_relative 'provider'

require_relative 'java/ext/secret_key'
require_relative 'java/ext/x509_cert'

module Ccrypto
  module Java
    class Error < StandardError; end
    # Your code goes here...
  end
end

Ccrypto::Provider.instance.register(Ccrypto::Java::Provider)

