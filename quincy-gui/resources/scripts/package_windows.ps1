cargo build --release

Invoke-WebRequest https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile target\tmp\wintun.zip
Expand-Archive target\tmp\wintun.zip -DestinationPath target\tmp\
Copy-Item target\tmp\wintun\bin\amd64\wintun.dll -Destination target\tmp\wintun.dll
