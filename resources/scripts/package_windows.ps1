cargo build --release --bin quincy-client-gui --bin quincy-client-daemon

Invoke-WebRequest https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile $env:TEMP\wintun.zip
Expand-Archive $env:TEMP\wintun.zip -DestinationPath $env:TEMP\wintun -Force
Copy-Item $env:TEMP\wintun\wintun\bin\amd64\wintun.dll -Destination target\release\wintun.dll
