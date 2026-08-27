# third_party/

Dependências externas **não commitadas** no repo (ver `.gitignore`).

## minhook/

Vendorizada localmente pra compilar `affbypass.dll`. BSD-2-Clause.

**Baixe com** (uma vez no host):

```powershell
$dest = "$PSScriptRoot\minhook"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$zip = "$env:TEMP\minhook.zip"
Invoke-WebRequest -Uri "https://github.com/TsudaKageyu/minhook/archive/refs/tags/v1.3.3.zip" -OutFile $zip
Expand-Archive -Force -Path $zip -DestinationPath $env:TEMP
Copy-Item -Recurse -Force "$env:TEMP\minhook-1.3.3\*" $dest
```

Sem isso, o build do `affbypass.vcxproj` falha com erro de include em `MinHook.h`.
