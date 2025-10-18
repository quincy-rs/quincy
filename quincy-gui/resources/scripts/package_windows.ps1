cargo build --release

Invoke-WebRequest https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile target\release\wintun.zip
Expand-Archive target\tmp\wintun.zip -DestinationPath target\release\
Copy-Item target\release\wintun\bin\amd64\wintun.dll -Destination target\release\wintun.dll
