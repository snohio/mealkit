#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Main entrypoint for running the remediation profile
#
require 'optparse'
require 'yaml'

options = {}
OptionParser.new do |opts|
  opts.banner = 'Usage: runner.rb [options]'
  opts.on('-aATTRIBUTESFILE', '--attributes=ATTRIBUTESFILE', 'Path to profile attributes file') do |a|
    options[:attributes] = a
  end
  opts.on('-oOUTPUTPATH', '--output-path=OUTPUTPATH', 'Directory path for remediation outputs to be stored.') do |o|
    options[:outputpath] = o
  end
end.parse!

abort('Remediation runner - attributes file must be provided!') unless options[:attributes]
abort("Remediation runner - attributes file #{options[:attributes]} must exist!") unless File.exist? options[:attributes]
report_path = __dir__
if options[:outputpath]
  abort("Remediation runner - log path #{options[:outputpath]} must exist!") unless Dir.exist? options[:outputpath]
  report_path = options[:outputpath]
end

# will need attribute file validation some time soon ...
attributes = YAML.load_file(options[:attributes])
abort('Could not read attributes file!') if attributes.nil?
puts "=> Remediation runner - #{attributes['provider']} #{attributes['benchmark']} #{attributes['provider_version']} #{attributes['benchmark_platform']}"

# will need to support various formats etc. - just use json for POC
report_outputs = attributes.dup
report_outputs['results'] = {}
report_outputs['exceptions'] = {}
global_environment = attributes['global_environment'] || []
attributes['controls'].each do |control|
  control_environment = {}
  global_environment.each do |global_env|
    abort "Environment variable must have a name property: #{global_env}" unless global_env.key?('name')
    if global_env.key?('value')
      if !global_env['value'].nil? && global_env['value'] != ''
        control_environment[global_env['name']] = global_env['value'].to_s
      end
    elsif global_env.key?('default') && !global_env['default'].nil? && global_env['default'] != ''
      control_environment[global_env['name']] = global_env['default'].to_s
    end
  end
  control['environment']&.each do |control_env|
    abort "Environment variable must have a name property: #{control_env}" unless control_env.key?('name')
    if control_env.key?('value')
      if !control_env['value'].nil? && control_env['value'] != ''
        control_environment[control_env['name']] = control_env['value'].to_s
      end
    elsif control_env.key?('default') && !control_env['default'].nil? && control_env['default'] != ''
      control_environment[control_env['name']] = control_env['default'].to_s
    end
  end
  # by convention we expect a file with the expected name to exist after generation
  begin
    require_relative (control['id']).to_s
    control_instance = Object.const_get(control['id']).new
    control_instance.dry_run = attributes['dry_run'] if attributes['dry_run']
    control_instance.enabled = control['enabled'] if control['enabled']
    control_instance.overlay_commands(control['overlay_commands']) if control['overlay_commands']
    control_instance.waiver = control['waiver'] if control['waiver']
    control_instance.environment = control_environment
    control_instance.manual = control['manual'] if control['manual']
    control_instance.run
    report_outputs['results'][control['id']] = control_instance.report.to_hash
  rescue SyntaxError => e
    msg = "EXCEPTION for #{control['id']}: #{e.backtrace.join('\n')}"
    puts msg
    report_outputs['exceptions'][control['id']] = msg
    report_outputs['results'][control['id']] = { 'state' => 'EXCEPTION' }
  end
  report_outputs['summary'] = report_outputs['results'].values.each_with_object(Hash.new(0)) { |k, v| v[k['state']] += 1 }
end
report_file = File.join(report_path, 'remediation_outputs.yaml')
puts "=> Execution complete, saving results to #{report_file}"
File.open(report_file, 'w') do |f|
  f.write(report_outputs.to_yaml)
end

if report_outputs.dig('summary', 'FAILED')
  exit 101
else
  exit 100
end