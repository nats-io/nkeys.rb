#!/usr/bin/env rake

require 'rspec/core'
require 'rspec/core/rake_task'

desc 'Run spec'

RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.pattern = FileList['spec/**/*_spec.rb']
  opts = ["--format", "documentation", "--colour"]
  spec.rspec_opts = opts.flatten
end

task :default => :spec
