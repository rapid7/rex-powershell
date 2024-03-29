# -*- coding:binary -*-
require 'spec_helper'

def decompress(code)
  if code =~ /powershell.exe.*(?:-c|-Command)\s(.*)$/
    code = Regexp.last_match(1).gsub("''", "'")
  end

  Rex::Powershell::Script.new(code).decompress_code
end

RSpec.describe Rex::Powershell::Command do
  let(:example_script) do
    File.join('spec', 'file_fixtures', 'powerdump.ps1')
  end

  let(:payload) do
    Rex::Text.rand_text_alpha(120)
  end

  let(:arch) do
    'x86'
  end

  describe "::encode_script" do
    it 'should read and encode a sample script file' do
      script = subject.encode_script(example_script)
      expect(script).to be
      expect(script.length).to be > 0
    end
  end

  describe "::compress_script" do
    context 'with default options' do
      it 'should create a compressed script' do
        script = File.read(example_script)
        compressed = subject.compress_script(script)
        expect(compressed.length).to be < script.length
        expect(compressed.include?('IO.Compression')).to be_truthy
      end

      it 'should create a compressed script with eof' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, 'end_of_file')
        expect(compressed.include?('end_of_file')).to be_truthy
      end
    end

    context 'when strip_comments is true' do
      it 'should strip comments' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: true)
        expect(compressed.length).to be < script.length
      end
    end
    context 'when strip_comment is false' do
      it 'shouldnt strip comments' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: false)
        expect(compressed.length).to be < script.length
      end
    end

    context 'when strip_whitespace is true' do
      it 'should strip whitespace' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: false, strip_whitespace: true)
        expect(decompress(compressed).length).to be < script.length
      end
    end

    context 'when strip_whitespace is false' do
      it 'shouldnt strip whitespace' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, strip_comments: false, strip_whitespace: false)
        expect(decompress(compressed).length).to eq(script.length)
      end
    end

    context 'when sub_vars is true' do
      it 'should substitute variables' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_vars: true)
        expect(decompress(compressed).include?('$hashes')).to be_falsey
      end
    end

    context 'when sub_vars is false' do
      it 'shouldnt substitute variables' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_vars: false)
        expect(decompress(compressed).include?('$hashes')).to be_truthy
      end
    end

    context 'when sub_funcs is true' do
      it 'should substitute functions' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_funcs: true)
        expect(decompress(compressed).include?('DumpHashes')).to be_falsey
      end
    end

    context 'when sub_funcs is false' do
      it 'shouldnt substitute variables' do
        script = File.read(example_script)
        compressed = subject.compress_script(script, nil, sub_funcs: false)
        expect(decompress(compressed).include?('DumpHashes')).to be_truthy
      end
    end
  end

  describe "::run_hidden_psh" do
    let(:encoded) do
      false
    end

    context 'when x86 payload' do
      it 'should generate code' do
        code = subject.run_hidden_psh(payload, arch, encoded)
        expect(code.include?('syswow64')).to be_truthy
      end
    end

    context 'when x64 payload' do
      it 'should generate code'  do
        code = subject.run_hidden_psh(payload, 'x86_64', encoded)
        expect(code.include?('sysnative')).to be_truthy
      end
    end

    context 'when encoded' do
      it 'should generate a code including an encoded command' do
        code = subject.run_hidden_psh(payload, arch, true)
        expect(code.include?('-nop -w hidden -e ')).to be_truthy
      end
    end

    context 'when command' do
      it 'should generate code including a -c command' do
        code = subject.run_hidden_psh(payload, arch, encoded)
        expect(code.include?('-nop -w hidden -c ')).to be_truthy
      end
    end

    context 'when old' do
      it 'should generate a code including unshorted args' do
        code = subject.run_hidden_psh(payload, arch, encoded, method: 'old')
        expect(code.include?('-NoProfile -WindowStyle hidden -NoExit -Command ')).to be_truthy
      end
    end
  end

  describe "::cmd_psh_payload" do
    let(:template_path) do
      Rex::Powershell::Templates::TEMPLATE_DIR
    end

    let(:psh_method) do
      'reflection'
    end

    context 'when payload is huge' do
      it 'should raise an exception' do
        expect { subject.cmd_psh_payload(Rex::Text.rand_text_alpha(12000), arch, template_path, method: psh_method) }.to raise_error(Rex::Powershell::Exceptions::PowershellCommandLengthError)
      end
    end

    context 'when persist is true' do
      it 'should add a persistence loop' do
        code = subject.cmd_psh_payload(payload, arch, template_path, persist: true, method: psh_method)
        expect(decompress(code).include?('while(1){Start-Sleep -s ')).to be_truthy
      end
    end

    context 'when persist is false' do
      it 'should not add a persistence loop' do
        code = subject.cmd_psh_payload(payload, arch, template_path, persist: false, method: psh_method)
        expect(decompress(code).include?('while(1){Start-Sleep -s ')).to be_falsey
      end
    end

    context 'when prepend_sleep is set' do
      it 'should prepend sleep' do
        code = subject.cmd_psh_payload(payload, arch, template_path, prepend_sleep: 5, method: psh_method)
        expect(decompress(code).include?('Start-Sleep -s ')).to be_truthy
      end
    end

    context 'when prepend_sleep isnt set' do
      it 'shouldnt prepend sleep' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: psh_method)
        expect(decompress(code).include?('Start-Sleep -s ')).to be_falsey
      end
    end

    context 'when prepend_sleep is 0' do
      it 'shouldnt prepend sleep' do
        code = subject.cmd_psh_payload(payload, arch, template_path, prepend_sleep: 0, method: psh_method)
        expect(decompress(code).include?('Start-Sleep -s ')).to be_falsey
      end
    end

    context 'when method is old' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'old')
        expect(decompress(code).include?('-namespace Win32Functions')).to be_truthy
      end
      it 'shouldnt shorten args' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'old')
        expect(code.include?('-NoProfile -WindowStyle hidden -Command')).to be_truthy
      end
      it 'should include -NoExit' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'old')
        expect(code.include?('-NoProfile -WindowStyle hidden -NoExit -Command')).to be_truthy
      end
    end

    context 'when method is net' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'net')
        expect(decompress(code).include?('System.Runtime.InteropServices;')).to be_truthy
      end
    end

    context 'when method is reflection' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'reflection')
        expect(decompress(code).include?('GlobalAssemblyCache')).to be_truthy
      end
    end

    context 'when method is msil' do
      it 'should generate a command line' do
        code = subject.cmd_psh_payload(payload, arch, template_path, method: 'msil')
        expect(decompress(code).include?('System.Reflection.MethodInfo')).to be_truthy
      end
    end

    context 'when method is unknown' do
      it 'should raise an exception' do
        except = false
        begin
          subject.cmd_psh_payload(payload, arch, template_path, method: 'blah')
        rescue RuntimeError
          except = true
        end
        expect(except).to be_truthy
      end
    end

    context 'when encode_inner_payload' do
      it 'should contain an inner payload with -e' do
          code = subject.cmd_psh_payload(payload, arch, template_path, encode_inner_payload: true, method: psh_method)
          expect(code.include?(' -e ')).to be_truthy
      end

      context 'when no_equals is true' do
        it 'should raise an exception' do
          except = false
          begin
            code = subject.cmd_psh_payload(payload, arch, template_path, encode_inner_payload: true, no_equals: true, method: psh_method)
          rescue RuntimeError
            except = true
          end
          expect(except).to be_truthy
        end
      end
    end

    context 'when encode_final_payload' do
      context 'when no_equals is false' do
        it 'should contain a final payload with -e' do
          code = subject.cmd_psh_payload(payload, arch, template_path, encode_final_payload: true, no_equals: false, method: psh_method)
          expect(code.include?(' -e ')).to be_truthy
          expect(code.include?(' -c ')).to be_falsey
        end
      end
      context 'when no_equals is true' do
        it 'should contain a final payload with -e' do
          code = subject.cmd_psh_payload(payload, arch, template_path, encode_final_payload: true, no_equals: true, method: psh_method)
          expect(code.include?(' -e ')).to be_truthy
          expect(code.include?(' -c ')).to be_falsey
          expect(code.include?('=')).to be_falsey
        end
      end
      context 'when encode_inner_payload is true' do
        it 'should raise an exception' do
          except = false
          begin
            subject.cmd_psh_payload(payload, arch, template_path, encode_final_payload: true, encode_inner_payload: true, method: psh_method)
          rescue RuntimeError
            except = true
          end
          expect(except).to be_truthy
        end
      end
    end

    context 'when remove_comspec' do
      it 'shouldnt contain %COMSPEC%' do
        code = subject.cmd_psh_payload(payload, arch, template_path, remove_comspec: true, method: psh_method)
        expect(code.include?('%COMSPEC%')).to be_falsey
      end
    end

    context 'when wrap double quotes' do
      it 'should wrap in double quotes' do
        code = subject.cmd_psh_payload(payload, arch, template_path, wrap_double_quotes: true, method: psh_method)
        expect(code.include?(' -c "')).to be_truthy
      end
    end
  end

  describe "::generate_psh_command_line" do
    it 'should contain no full stop when :no_full_stop' do
      opts = {:no_full_stop => true}
      command = subject.generate_psh_command_line(opts)
      expect(command.include?("powershell ")).to be_truthy
    end

    it 'should contain full stop unless :no_full_stop' do
      opts = {}
      command = subject.generate_psh_command_line(opts)
      expect(command.include?("powershell.exe ")).to be_truthy

      opts = {:no_full_stop => false}
      command = subject.generate_psh_command_line(opts)
      expect(command.include?("powershell.exe ")).to be_truthy
    end

    it 'should ensure the path should always ends with \\' do
      opts = {:path => "test"}
      command = subject.generate_psh_command_line(opts)
      expect(command.include?("test\\powershell.exe ")).to be_truthy

      opts = {:path => "test\\"}
      command = subject.generate_psh_command_line(opts)
      expect(command.include?("test\\powershell.exe ")).to be_truthy
    end
  end

  describe "::generate_psh_args" do
    it 'should return empty string for nil opts' do
      expect(subject.generate_psh_args(nil)).to eql ""
    end

    command_args = [[:encodedcommand, "parp"],
                    [:executionpolicy, "bypass"],
                    [:inputformat, "xml"],
                    [:file, "x"],
                    [:noexit, true],
                    [:nologo, true],
                    [:noninteractive, true],
                    [:mta, true],
                    [:outputformat, 'xml'],
                    [:sta, true],
                    [:noprofile, true],
                    [:windowstyle, "hidden"],
                    [:version, "2.0"],
                    [:command, "Z"],
                    [:wrap_double_quotes, true]
    ]

    permutations = (0..command_args.length).to_a.combination(2).map{|i,j| command_args[i...j]}

    permutations.each do |perms|
      opts = {}
      perms.each do |k,v|
        opts[k] = v
        it "should generate correct arguments for #{opts}" do
          opts[:shorten] = true
          short_args = subject.generate_psh_args(opts)
          opts[:shorten] = false
          long_args = subject.generate_psh_args(opts)

          # EncodedCommand and Command are mutually exclusive, shorten and wrap_double_quotes are external
          opt_length = opts.length - 1 # shorten
          opt_length = opt_length - 1 if opts.keys.include?(:wrap_double_quotes)
          opt_length = opt_length - 1 if opts.keys.include?(:encodedcommand && :command)

          expect(short_args).not_to be_nil
          expect(long_args).not_to be_nil
          expect(short_args[0]).not_to eql " "
          expect(long_args[0]).not_to eql " "
          expect(short_args[-1]).not_to eql " "
          expect(long_args[-1]).not_to eql " "

          if opts[:command]
            if opts[:wrap_double_quotes]
              expect(long_args[-12..-1]).to eql "-Command \"Z\""
              expect(short_args[-6..-1]).to eql "-c \"Z\""
            else
              expect(long_args[-10..-1]).to eql "-Command Z"
              expect(short_args[-4..-1]).to eql "-c Z"
            end
          end
       end
      end
    end
  end

end

