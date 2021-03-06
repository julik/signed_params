== SignedParams

Implements simple signing of query strings and URLs. When a set of parameters
is generated with signed_url_for a special key, :sig (signature) gets appended
to the the hash. The signature contains the digest of all keys and values of the passed
hash. When this URL gets called, the controller can use SignedParams to verify if the
request parameters have been deliberately changed. 

== What for

This is useful in situations where
you might want to perform operations via URLs which should not, under any circumstances,
be user-generated (such as making thumbnails on request - the original need for this
arose from that)

== What if

Well you gotta have inspiration. http://aaugh.com/imageabuse.html

== How to

First define a salt in your environment
  
  SignedParams.salt = "This is something NOBODY must know"
  
To build a signed URL, call

  signed_url_for :id => "bla"

To make the controller check the signature in params on specific actions

  class FeedsController < ApplicationController
    require_signed_parameters  :only => [:get_private_feed]
  end
  
Questions? me@julik.nl