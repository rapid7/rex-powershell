# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Powershell::Payload do
  let(:payload) { Rex::Text.rand_text_alpha(120) }
  let(:template_path) { File.expand_path('../../../data/templates', __dir__) }

  describe 'shellcode templates' do
    {
      dotnet: :to_win32pe_psh_net,
      reflection: :to_win32pe_psh_reflection,
      old: :to_win32pe_psh
    }.each do |name, method|
      it "flushes the instruction cache before executing the #{name} payload" do
        script = described_class.public_send(method, template_path, payload)
        copy_index = script.index('[System.Runtime.InteropServices.Marshal]::Copy')
        flush_index = script.rindex('FlushInstructionCache')
        execute_index = script.rindex('CreateThread')

        expect(copy_index).to be < flush_index
        expect(flush_index).to be < execute_index
      end
    end

    it 'uses an aarch64 trampoline and flushes the patched MSIL method' do
      script = described_class.to_win32pe_psh_msil(template_path, payload)
      flush_method = script[/^\s*(\$\w+) = \$\w+\.DefinePInvokeMethod/m, 1]
      trampoline = script[/PROCESSOR_ARCHITECTURE -eq 'ARM64'\) \{\s+\$\w+ = \[Byte\[\]\] @\(([^)]*)\)/, 1]
      trampoline_bytes = trampoline.split(',').map { |byte| Integer(byte, 0) }
      expected_trampoline = [
        0xf3, 0x53, 0xba, 0xa9, # stp x19, x20, [sp, #-96]!
        0xf5, 0x5b, 0x01, 0xa9, # stp x21, x22, [sp, #16]
        0xf7, 0x63, 0x02, 0xa9, # stp x23, x24, [sp, #32]
        0xf9, 0x6b, 0x03, 0xa9, # stp x25, x26, [sp, #48]
        0xfb, 0x73, 0x04, 0xa9, # stp x27, x28, [sp, #64]
        0xfd, 0x7b, 0x05, 0xa9, # stp x29, x30, [sp, #80]
        0x09, 0x00, 0x00, 0x94, # bl payload
        0xfd, 0x7b, 0x45, 0xa9, # ldp x29, x30, [sp, #80]
        0xfb, 0x73, 0x44, 0xa9, # ldp x27, x28, [sp, #64]
        0xf9, 0x6b, 0x43, 0xa9, # ldp x25, x26, [sp, #48]
        0xf7, 0x63, 0x42, 0xa9, # ldp x23, x24, [sp, #32]
        0xf5, 0x5b, 0x41, 0xa9, # ldp x21, x22, [sp, #16]
        0xf3, 0x53, 0xc6, 0xa8, # ldp x19, x20, [sp], #96
        0x00, 0x00, 0x80, 0xd2, # mov x0, #0
        0xc0, 0x03, 0x5f, 0xd6  # ret
      ]

      expect(trampoline_bytes).to eq(expected_trampoline)
      expect(script).to include("'kernel32.dll', 'FlushInstructionCache'")
      expect(flush_method).not_to be_nil
      expect(script.index("#{flush_method}.Invoke")).to be < script.rindex('.Invoke($null, @(0x11112222))')
    end

    it 'only defines and invokes the MSIL cache flush on ARM64' do
      script = described_class.to_win32pe_psh_msil(template_path, payload)
      arm64_block_pattern = /if \(\$env:PROCESSOR_ARCHITECTURE -eq 'ARM64'\) \{([^}]+)\}/m
      arm64_blocks = script.scan(arm64_block_pattern).flatten
      non_arm64_code = script.gsub(arm64_block_pattern, '')

      expect(arm64_blocks.any? { |block| block.include?('DefinePInvokeMethod') }).to be(true)
      expect(arm64_blocks.any? { |block| block.include?('[IntPtr](-1)') }).to be(true)
      expect(non_arm64_code).not_to include('DefinePInvokeMethod')
      expect(non_arm64_code).not_to include('[IntPtr](-1)')
    end
  end
end
