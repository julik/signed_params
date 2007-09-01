require 'rubygems'

require 'test/unit'
require 'flexmock'
require 'flexmock/test_unit'
require 'stringio'

require 'action_controller'
require 'action_controller/test_process'
require File.dirname(__FILE__)  + '/../init'

ActionController::Routing::Routes.draw do |map|
  map.connect ':controller/:action/:id'
end

class SignedParamsDigestingTest < Test::Unit::TestCase
  def setup
    SignedParams.salt = "_zis_is_mai_sikret"
  end
  
  def test_existence
    assert_nothing_raised { SignedParams; SignedParams::ControllerClassMethods; SignedParams::ControllerInstanceMethods }
  end

  def test_modules_mixed
    assert ActionController::Base.ancestors.include?(SignedParams::ControllerInstanceMethods)
    assert ActionController::Base.instance_methods.include?("signed_url_for")
  end
  
  def test_raises_with_no_salt
    SignedParams.salt = nil
    assert_raise(SignedParams::NoKey) do
      SignedParams.sign!({})
    end
  end
  
  def test_bypass_without_keys
    @data = {:foo => 1, :bar => 2, :baz => [1,2,3] }
    
    SignedParams.sign!(@data)
    assert @data.has_key?(:sig), "Now it is signed"
    
    @other_data = {:bar => 2, :baz => [1,2,3], :foo => 1 }
    
    SignedParams.sign!(@other_data)
    assert @other_data.has_key?(:sig), "Now it is signed"

    ref_digest = "10a72e7e0a1893ca36622bbbd21412d5d699d5c3"
    assert_equal ref_digest, SignedParams.send(:compute_checksum, @other_data), "The proper digest should be generated"
    assert_equal ref_digest, SignedParams.send(:compute_checksum, @data), "The proper digest should be generated"
    
    assert SignedParams.verify!(@other_data)
    assert SignedParams.verify!(@data)
  end
  
  def test_digest_equivalency_for_key_value_formats_and_hash_orders
    stringed_as_in_params = {"foo" => "2", "baz" => "true"}
    rubyfied_as_in_code = {:foo => 2, :baz => true}
    assert_equal SignedParams.sign!(stringed_as_in_params), SignedParams.sign!(rubyfied_as_in_code),
      "Digest should use the string representation of the hash typical for the params"
  end
  
  def test_digest_does_not_ignore_id
    data1, data2 = {:id => 4, :foo => "bar"}, {:foo => "bar"}
    assert_not_equal SignedParams.sign!(data1), SignedParams.sign!(data2)
  end
  
  def test_signing_calls_upon_query_string_generation
    sample_hash = {"this_is" => "not important"}
    mocked_rewrite = flexmock()
    mocked_rewrite.should_receive(:build_query_string).at_least.once.with(sample_hash).and_return("?foo=bar")
    flexmock(ActionController::Routing::Route).should_receive(:new).at_least.once.and_return(mocked_rewrite)
    SignedParams.sign!(sample_hash)
  end
  
  def test_salt_affects_signatures
    example = {:foo => "dadidam", :x => [1,2,3]}
    digest_first = SignedParams.sign!(example)
    
    SignedParams.salt = "anozer sikret"
    digest_second = SignedParams.sign!(example)
    
    assert_not_equal digest_second, digest_first, "The digest should depend on salt"
  end
  
  def test_bigvalues
    @data = {:long_text_field => ("abrvalg" * 230) }
    assert_nothing_raised do
      SignedParams.sign!(@data)
    end
  end
  
  def test_tamper_proofness
    @data = {:a => 12, :b => 145}
    SignedParams.sign!(@data)
    assert_not_nil @data.delete(:sig)
    assert_raise(SignedParams::Tampered) { SignedParams.verify!(@data) }
    
    @data = {:a => 12, :b => 145}
    SignedParams.sign!(@data)
    assert SignedParams.verify!(@data)
    assert !@data.has_key?(:sig), "After verification the signature has to be removed from the hash"
    
    SignedParams.sign!(@data)
    
    saved  = @data[:sig]
    @data[:sig] = "welcome folks"
    assert_raise(SignedParams::Tampered) { SignedParams.verify!(@data) }
    
    @data[:sig] = 123
    assert_raise(SignedParams::Tampered) { SignedParams.verify!(@data) }
    
    @data.delete(:sig)
    assert_raise(SignedParams::Tampered) { SignedParams.verify!(@data) }
    
    @data[:sig] = saved
    assert SignedParams.verify!(@data)
  end
  
  def test_signature_invalidated_on_salt_change
    @data = {:a => 12, :b => [1,2,4]}
    SignedParams.sign!(@data)
    assert SignedParams.verify!(@data)
    
    SignedParams.salt = "Another secret"
    assert_raise(SignedParams::Tampered, "Secret change should invalidate the signature") { SignedParams.verify!(@data) }
  end
end

class BogusController < ActionController::Base
  def checked_action
    render :nothing => true
  end
  
  def unchecked_action
    render :nothing => true
  end
  def rescue_action(e); raise e; end
  
end

class SignedParamsControllerIntegrationTest < Test::Unit::TestCase
  def setup
    SignedParams.salt = "foo bastard"
    @controller = BogusController.new
    @controller.logger = Logger.new(StringIO.new)
    @request = ActionController::TestRequest.new
    @response = ActionController::TestResponse.new
  end

  def test_filter_enables_protection
    params = {:foo => "baz"}
    canonical_params = {"action"=>"checked_action", "controller"=>"bogus", "foo"=>"baz"}
    
    get :checked_action, params
    assert_response :success
    assert_equal( canonical_params, @controller.params)
    
    assert_nothing_raised do
      BogusController.require_signed_parameters :only => :checked_action
    end
    
    get :unchecked_action, params
    assert_response 200
    
    flexmock(@controller.logger).should_receive(:error).at_least.once.with("Request parameters possibly tampered!")
    get :checked_action, :foo => "baz"
    assert_response 404
    
    signed = canonical_params.dup
    SignedParams.sign!(signed)
    
    signed.delete("controller")
    signed.delete("action")
    
    get :checked_action, signed
    assert_response 200
    assert_equal( canonical_params, @controller.params)
    
    signed[:sig] = "foobarbazdo"
    
    get :checked_action, signed
    assert_response 404
    
  end
end