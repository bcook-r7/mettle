# -*- coding:binary -*-

unless defined? MetasploitPayloads::Mettle::VERSION
  require 'metasploit_payloads/mettle/version'
end

#
# This module dispenses Mettle payload binary files
#
module MetasploitPayloads
  class Mettle

    #
    # Config is a hash. Valid keys are:
    #  :uri to connect to
    #  :uuid of the payload
    #  :debug to enable
    #  :log_file to log to places other than stderr
    #
    attr_accessor :config

    def initialize(triple, config={})
      @platform = triple.clone
      @config = config.clone
    end

    #
    # Available formats are :process_image and :exec
    #
    def to_binary(format=:process_image)
      bin = self.class.read(@platform, format)
      params = generate_argv
      add_args(bin, params)
    end

    private

    def generate_argv
      cmd_line = 'mettle '
      @config.each do |opt, val|
        cmd_line << "-#{short_opt(opt)} \"#{val}\" "
      end
      if cmd_line.length > 264
        fail RuntimeError, 'mettle argument list too big', caller
      end

      cmd_line + "\x00" * (264 - cmd_line.length)
    end

    def short_opt(opt)
      case opt
      when :uri
        'u'
      when :uuid
        'U'
      when :background
        'b'
      when :debug
        'd'
      when :log_file
        'o'
      else
        fail RuntimeError, "unknown mettle option #{opt}", caller
      end
    end

    def add_args(bin, params)
      if params[8] != "\x00"
        bin.sub('DEFAULT_OPTS' +  ' ' * 252, params)
      else
        bin
      end
    end

    def self.readable_path(gem_path, msf_path)
      # Try the MSF path first to see if the file exists, allowing the MSF data
      # folder to override what is in the gem. This is very helpful for
      # testing/development without having to move the binaries to the gem folder
      # each time. We only do this is MSF is installed.
      if ::File.readable? msf_path
        warn_local_path(msf_path) if ::File.readable? gem_path
        msf_path
      elsif ::File.readable? gem_path
        gem_path
      end
    end

    #
    # Get the contents of any file packaged in this gem by local path and name.
    #
    def self.read(triple, format)
      file =
          case format
          when :process_image
            'mettle.bin'
          when :exec
            'mettle'
          else
            fail RuntimeError, "unknown mettle format #{format}", caller
          end
      file_path = path("#{triple}", 'bin', file)
      if file_path.nil?
        full_path = ::File.join([triple, file])
        fail RuntimeError, "#{full_path} not found", caller
      end

      ::File.binread(file_path)
    end

    #
    # Get the full path to any file packaged in this gem by local path and name.
    #
    def self.path(*path_parts)
      gem_path = expand(data_directory, ::File.join(path_parts))
      msf_path = 'thisisnotthefileyouarelookingfor'
      if metasploit_installed?
        msf_path = expand(Msf::Config.data_directory, ::File.join('mettle', path_parts))
      end
      readable_path(gem_path, msf_path)
    end

    #
    # Full path to the local gem folder containing the base data
    #
    def self.data_directory
      ::File.realpath(::File.join(::File.dirname(__FILE__), '..', '..', 'build'))
    end

    #
    # Determine if MSF has been installed and is being used.
    #
    def self.metasploit_installed?
      defined? Msf::Config
    end

    #
    # Expand the given root path and file name into a full file location.
    #
    def self.expand(root_dir, file_name)
      ::File.expand_path(::File.join(root_dir, file_name))
    end

    @local_paths = []

    def self.warn_local_path(path)
      unless @local_paths.include?(path)
        STDERR.puts("WARNING: Local file #{path} is being used")
        if @local_paths.empty?
          STDERR.puts('WARNING: Local files may be incompatible Metasploit framework')
        end
        @local_paths << path
      end
    end
  end
end
