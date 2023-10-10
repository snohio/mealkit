# frozen_string_literal: true

require 'train'
require 'rbconfig'

class CISRemediation
  attr_reader :id, :report
  attr_writer :manual
  attr_accessor :dry_run, :enabled, :waiver, :environment

  def initialize(id)
    @id = id
    @identifier = ''
    @enabled = false
    @dry_run = false
    @commands = []
    @overlay = false
    @title = ''
    @scored = true
    @level = 1
    @failed = false
    @report = { 'commands' => [], 'state' => 'SUCCESS' }
    @script_directory = File.join(__dir__, 'scripts')
    @waiver = {}
    @waived = false
    @overlay_contents = {}
    @environment = {}
    @manual = false
  end

  def run
    # have a boolean for dry-run
    # check for linux/windows/cloud/etc. and set up correct train stuff
    puts "--> #{@identifier} - #{@title}"
    @report['provider_id'] = @identifier
    @report['title'] = @title
    @report['description'] = @description
    @report['scored'] = @scored
    @report['level'] = @level
    @report['overlay'] = @overlay
    @report['dry_run'] = @dry_run if @dry_run
    @report['environment'] = @environment
    @report['manual'] = @manual if @manual
    check_waiver_status
    puts "----> #{@identifier} is disabled by flag (enabled=false)" if !@enabled
    @commands.each_with_index do |command, i|
      command_report = command.dup
      command_report['order'] = "#{i + 1} / #{@commands.count}"
      command.each do |script_type, comm|
        # assume linux, windows, aws, azure, gcp, ...
        # hard coded to local for now. This was always local anyway.
        conn = Train.create('local').connection
        result = { 'exit_status' => '', 'stdout' => '', 'stderr' => '', 'executed' => true }
        # script contents is tricky because there can be commands, a single schema script or multiple overlays at runtime...
        result['script_contents'] = report_script_contents(comm)
        if @dry_run
          result['executed'] = false
          puts "=> dry-run enabled, would execute '#{comm}' on local"
          @report['state'] = 'DRYRUN'
        elsif !@enabled
          result['executed'] = false
          @report['state'] = 'DISABLED'
        elsif @failed
          result['executed'] = false
        elsif @waived
          result['executed'] = false
          puts "=>  Applying waiver for '#{comm}'"
          @report['state'] = 'WAIVED'
        else
          comm = find_ruby_path(comm) if /^ruby/.match?(comm)
          # Handle special case of pwsh on not-Windows
          comm = comm.gsub(/^PowerShell/, 'pwsh') if script_type == 'script_ps1' && !Gem.win_platform?

          comm = prepend_environment(comm)

          # update command_report with command including any env vars
          command_report[script_type] = comm
          puts "Running '#{comm}'"
          train_command = conn.run_command(comm)
          result['stdout'] = train_command.stdout.to_s
          result['stderr'] = train_command.stderr.to_s
          result['exit_status'] = train_command.exit_status
          @failed = true if train_command.exit_status != 0
        end
        command_report.update(result)
        @report['state'] = 'FAILED' if @failed
        @report['commands'] += [command_report]
        conn.close if Gem.win_platform?
      end
    end
    # update report on status to track failures etc.
  end

  def find_ruby_path(comm)
    return "$env:PATH += \"; #{RbConfig::CONFIG['bindir']}\"; #{comm}" if Gem.win_platform?
    "export PATH=#{RbConfig::CONFIG['bindir']}:$PATH;#{comm}"
  end

  def prepend_environment(comm)
    return comm if @environment.empty?
    if Gem.win_platform?
      vars = @environment.map { |env, val| "$env:#{env}='#{val}'" }
    else
      vars = @environment.map { |env, val| "export #{env}='#{val}'" }
    end
    "#{vars.join('; ')}; #{comm}"
  end

  def report_script_contents(current_cmd)
    return current_cmd if @script_file.empty? && !@overlay
    return @overlay_contents[current_cmd] if @overlay
    File.read(File.join(@script_directory, @script_file))
  end

  def check_waiver_status
    return if @waiver.empty?
    # the outcome of this method will be setting @waived to true or false based on the provided waiver properties
    start_date_utc = @waiver['start_date_utc']
    end_date_utc = @waiver['expiration_date_utc']
    current_time = Time.now.utc
    if start_date_utc.nil? # can't do anything without a start date
      puts 'Ignoring waiver with empty start_date_utc.'
      return
    end
    start_date_utc = YAML.load(start_date_utc)
    if !start_date_utc.is_a?(Time)
      puts 'Ignoring waiver with invalid start_date_utc.'
      return
    end
    @waived = true if current_time > start_date_utc
    return if end_date_utc.nil? # the end date is optional
    # however, if specified, let's assume it has to be valid
    end_date_utc = YAML.load(end_date_utc)
    if !end_date_utc.is_a?(Time)
      @waived = false
      puts 'Ignoring waiver with valid start_date_utc but invalid end_date_utc.'
      return
    end
    if current_time > end_date_utc
      @waived = false
      puts "Waiver found but has now expired - #{current_time} > #{end_date_utc}."
    end
  end

  def overlay_commands(commands_list)
    @commands = []
    @overlay = true
    # the overlay commands can potentially be local, script_ruby, script_bash or script_ps1
    # we must create and execute the script in a similar way to the generation
    commands_list.each.with_index(1) do |commands, index|
      overlay = {}
      commands.each do |script_type, cmd|
        script_type, overlay_script_cmd = get_overlay_commands(script_type, cmd, index)
        overlay[script_type] = overlay_script_cmd
      end
      @commands += [overlay]
    end
  end

  def get_overlay_commands(script_type, script_raw, order)
    if script_type == 'local'
      script_cmd = script_raw
    elsif script_type == 'script_bash'
      write_script(File.join(@script_directory, "#{@id}_overlay_#{order}.sh"), "#!/bin/bash\n#{script_raw}")
      script_cmd = "bash #{@script_directory}#{File::SEPARATOR}#{@id}_overlay_#{order}.sh"
    elsif script_type == 'script_ruby'
      write_script(File.join(@script_directory, "#{@id}_overlay_#{order}.rb"), "#!/usr/bin/env ruby\n#{script_raw}")
      script_cmd = "ruby #{@script_directory}#{File::SEPARATOR}#{@id}_overlay_#{order}.rb"
    elsif script_type == 'script_ps1' && Gem.win_platform?
      write_script(File.join(@script_directory, "#{@id}_overlay_#{order}.ps1"), "# powershell script\n#{script_raw}")
      script_cmd = "PowerShell -File #{@script_directory}#{File::SEPARATOR}#{@id}_overlay_#{order}.ps1"
    elsif script_type == 'script_ps1' && !Gem.win_platform?
      write_script(File.join(@script_directory, "#{@id}_overlay_#{order}.ps1"), "# powershell script\n#{script_raw}")
      script_cmd = "pwsh -File #{@script_directory}#{File::SEPARATOR}#{@id}_overlay_#{order}.ps1"
    else
      script_cmd = if Gem.win_platform?
                     "echo \"Supplied script #{script_type} is not one of script_ruby, script_bash or script_ps1, exiting with non-zero status.\"; PowerShell -Command \"exit 1\""
                   else
                     "echo \"Supplied script #{script_type} is not one of script_ruby, script_bash or script_ps1, exiting with non-zero status.\"; exit 1"
                   end
    end
    # there can be multiple overlays that replace any schema script
    @overlay_contents[script_cmd] = script_raw
    [script_type, script_cmd]
  end

  def write_script(fname, contents)
    File.open(fname, 'w') do |f|
      f.write(contents.to_s)
    end
  end
end
