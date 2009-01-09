require 'openssl'
require 'base64'
require File.dirname(__FILE__) + '/version'

class SignedParams
  
  class NoKey < RuntimeError; end
  class Tampered < RuntimeError; end
  
  DEFAULT_DIGEST_PROC = Proc.new do | signer, payload |
    raise NoKey, "Please define a salt with SignedParams.salt = something" unless signer.salt
    digest_type = 'SHA1'
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new(digest_type), signer.salt, payload)
  end
  
  CLEAR_OPTIONS = %w(sig controller action)
  
  module ControllerInstanceMethods
    protected
    # Returns the same result as the one url_for does but also signs the parameters
    def signed_url_for(options)
      canonical_options = rewrite_options(options)
      canonical_options[:controller] ||= controller_path
      SignedParams.sign!(canonical_options)
      url_for(canonical_options)
    end
  end
  
  module ControllerClassMethods
    # A class call to define a filter that checks for the signed parameters
    #  require_signed_parameters :only => [:send_confidential_email]
    def require_signed_parameters(*filter_options)
      before_filter(*filter_options) do | c |
        begin
          SignedParams.verify!(c.params)
        rescue SignedParams::Tampered
          c.logger.error "Request parameters possibly tampered!"
          c.send(:render, :status => 404, :text => "No such page")
          false
        end
      end
    end
  end
  
  ActionController::Base.send(:include, ControllerInstanceMethods)
  ActionController::Base.send(:extend, ControllerClassMethods)
  ActionController::Base.send(:helper_method, :signed_url_for)
  
  class << self
    attr_accessor :salt, :digest
    
    # Should return the proc used for digest generation
    def digest
      @digest ||= DEFAULT_DIGEST_PROC
    end
    
    # Compute the checksum of the hash and save it into the :sig slot. The signature also gets returned.
    def sign!(ha)
      ha[:sig] = compute_checksum(ha)
    end

    # Check a signed hash for authenticity
    def verify!(ha)
      passed_signature = ha[:sig] || ha["sig"]
      raise Tampered, "No signature given" unless passed_signature
      raise Tampered, "Checksum differs" unless compute_checksum(ha) == passed_signature.to_s
      true
    end
  
    private
      # Compute the cheksum of a hash in such a way that the checksum of it's options
      # in textual form stays the same independently of where the hash came from.
      # Considering that the keys in Ruby hashes are unordered this is non-trivial to guarantee
      def compute_checksum(h)
        begin
          signed_h = h.dup.with_indifferent_access
          CLEAR_OPTIONS.map{|o| signed_h.delete(o) }
          marshaled = ActionController::Routing::Route.new.build_query_string(signed_h)
          marshaled = marshaled.gsub(/^\?/, '').split(/&/).sort.join('&')
          digest.call(self, Base64.encode64(marshaled.to_s.reverse)).to_s
        ensure
        end
      end
  end # SignedParams
end