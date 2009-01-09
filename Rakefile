require 'rubygems'
require 'hoe'
require './lib/version.rb'

Hoe::RUBY_FLAGS.replace ENV['RUBY_FLAGS'] || "-I#{%w(lib ext bin test).join(File::PATH_SEPARATOR)}" +
  (Hoe::RUBY_DEBUG ? " #{RUBY_DEBUG}" : '')
  
Hoe.new('SignedParams', SignedParams::VERSION) do |p|
  p.developer('Julik', 'me@julik.nl')
  p.description = 'Sign your URLs for extra security'
  p.extra_deps << 'flexmock'
end

begin
  require 'load_multi_rails_rake_tasks'
rescue LoadError
end
