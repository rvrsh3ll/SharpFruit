# SharpFruit

SharpFruit is a c# port of [Find-Fruit.ps1](https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Find-Fruit.ps1)

SharpFruit is intended to aid Penetration Testers in finding juicy targets on internal networks without nmap scanning.

As an example, one could execute SharpFruit.exe through Cobalt Strike's Beacon "execute-assembly" module.
#### Example usage
beacon>execute-assembly /root/SharpFruit/SharpFruit.exe --cidr 10.10.1.0/24 --port 8080
##### OR an example using SSL
beacon>execute-assembly /root/SharpFruit/SharpFruit.exe --cidr 10.10.1.0/24 --port 9443 --ssl+ --useragent "GoogleBotIsInsideYourNetwork"
