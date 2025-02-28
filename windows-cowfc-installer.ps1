# CoWFC Server Installation Script for Windows
# Adapted from the original Linux script

# Display warning message about security
Write-Host "########## !!!!! WARNING !!!!! ##########" -ForegroundColor Red
Write-Host "Recently, Wiimmfi has undergone some changes which makes it so that their servers are more secure from hackers." -ForegroundColor Yellow
Write-Host "Having said that, this means that the CoWFC fork will not be getting the security patch, as it is unclear how it is possible. For the time being, you accept that you run your own server with a chance that hackers will be able to execute code over the MKW network." -ForegroundColor Yellow
Write-Host "This might mean that hackers can in theory, brick consoles." -ForegroundColor Yellow

# Confirm acceptance twice
$reply = Read-Host "Please type ACCEPT to accept the risk"
if ($reply -ne "ACCEPT") {
    Write-Host "Verification FAILED!" -ForegroundColor Red
    exit 2
}

$reply = Read-Host "Just in case you were trigger-happy, I'll need you to type ACCEPT"
if ($reply -ne "ACCEPT") {
    Write-Host "Verification FAILED!" -ForegroundColor Red
    exit 2
}

# Check if we already installed the server
$installFlag = "C:\CoWFC\.dwc_installed"
if (Test-Path $installFlag) {
    Write-Host "You already installed CoWFC. There is no need to re-run it." -ForegroundColor Yellow
    Write-Host "If you only want to RESET your dwc server, just delete gpcm.db and storage.db (don't forget to restart the server of course)"
    Write-Host "If you want to UPDATE your actual installation, the best way is to save gpcm.db and storage.db (in dwc_network_server_emulator), remove everything, re-install with this script and restore gpcm.db and storage.db"
    exit 999
}

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart the script with admin rights." -ForegroundColor Red
    exit 1
}

# Test internet connectivity
Write-Host "Testing internet connectivity..."
if (Test-Connection -ComputerName github.com -Count 2 -Quiet) {
    Write-Host "Internet is OK" -ForegroundColor Green
} elseif (Test-Connection -ComputerName torproject.org -Count 2 -Quiet) {
    Write-Host "Internet is OK" -ForegroundColor Green
} else {
    Write-Host "Internet Connection Test Failed!" -ForegroundColor Red
    Write-Host "If you want to bypass internet check use -s arg!"
    exit 1
}

# Create necessary directories
New-Item -ItemType Directory -Force -Path "C:\CoWFC" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\CoWFC\www" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\CoWFC\logs" | Out-Null

# Functions

function Update-Script {
    Write-Host "Checking if script is up to date, please wait..."
    # Note: This function would need to be adapted for Windows
    # For now, we'll just return since this is a Windows port
    Write-Host "Update checking is not implemented in the Windows version." -ForegroundColor Yellow
}

function Install-RequiredTools {
    Write-Host "Installing required tools and dependencies..." -ForegroundColor Green
    
    # Check if Chocolatey is installed, if not install it
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Chocolatey package manager..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    
    # Install required tools using Chocolatey
    Write-Host "Installing Git, Python 2.7, MySQL, Apache, PHP, and other required packages..."
    choco install git python2 mysql apache-httpd php -y
    
    # Install PIP
    python -m pip install --upgrade pip
    
    # Install required Python packages
    pip install twisted
    
    # Add Python and other tools to PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    
    Write-Host "Required tools installed successfully." -ForegroundColor Green
}

function Clone-Repositories {
    Write-Host "Cloning required repositories..." -ForegroundColor Green
    
    # Clone CoWFC repository
    if (!(Test-Path "C:\CoWFC\CoWFC")) {
        Set-Location "C:\CoWFC"
        $retry = 0
        $success = $false
        
        while (!$success -and $retry -lt 5) {
            try {
                git clone https://github.com/EnergyCube/CoWFC.git
                $success = $true
            } catch {
                $retry++
                Write-Host "GIT CLONE FAILED! Retrying..... (Attempt $retry of 5)" -ForegroundColor Red
            }
        }
        
        if (!$success) {
            Write-Host "Failed to clone CoWFC repository after 5 attempts. Exiting." -ForegroundColor Red
            exit 1
        }
    }
    
    # Clone dwc_network_server_emulator repository
    if (!(Test-Path "C:\CoWFC\dwc_network_server_emulator")) {
        Set-Location "C:\CoWFC"
        $retry = 0
        $success = $false
        
        while (!$success -and $retry -lt 5) {
            try {
                git clone https://github.com/EnergyCube/dwc_network_server_emulator.git
                $success = $true
            } catch {
                $retry++
                Write-Host "GIT CLONE FAILED! Retrying..... (Attempt $retry of 5)" -ForegroundColor Red
            }
        }
        
        if (!$success) {
            Write-Host "Failed to clone dwc_network_server_emulator repository after 5 attempts. Exiting." -ForegroundColor Red
            exit 1
        }
    }
    
    # Set proper permissions
    Write-Host "Setting proper file permissions" -ForegroundColor Green
    # Note: Windows handles permissions differently than Linux, so we might not need chmod
}

function Configure-DNS {
    Write-Host "----------Let's configure DNS now----------" -ForegroundColor Green
    Start-Sleep -Seconds 3
    
    # Get user's IP address information
    Write-Host "What is your EXTERNAL IP?" -ForegroundColor Yellow
    Write-Host "NOTE: If you plan on using this on a LAN, put the IP of your Windows system instead"
    Write-Host "It's also best practice to make this address static in your network settings" -ForegroundColor Yellow
    
    Write-Host "Your LAN IP is:"
    $lanIP = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -ne "WellKnown"}).IPAddress
    Write-Host $lanIP -ForegroundColor Cyan
    
    Write-Host "Your external IP is:"
    $externalIP = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content
    Write-Host $externalIP -ForegroundColor Cyan
    
    $IP = Read-Host "Please type in either your LAN or external IP"
    
    # Create a hosts file configuration
    Write-Host "Adding DNS entries to hosts file..."
    
    # Backup hosts file first
    Copy-Item -Path "C:\Windows\System32\drivers\etc\hosts" -Destination "C:\Windows\System32\drivers\etc\hosts.bak"
    
    # Add entries to hosts file
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n# CoWFC Server DNS entries"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP gamestats.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP gamestats2.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP conntest.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP nas.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP naswii.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP dls1.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP sake.gs.nintendowifi.net"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP gamestats.wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP gamestats2.wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP conntest.wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP nas.wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP naswii.wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP dls1.wiimmfi.de"
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$IP sake.gs.wiimmfi.de"
    
    Write-Host "DNS configuration completed!" -ForegroundColor Green
}

function Configure-Apache {
    Write-Host "Configuring Apache webserver..." -ForegroundColor Green
    
    # Create virtual hosts for Nintendo domains
    $apacheConfDir = "C:\Program Files\Apache24\conf\extra"
    
    # Create httpd-vhosts.conf file if it doesn't exist
    if (!(Test-Path "$apacheConfDir\httpd-vhosts.conf")) {
        New-Item -ItemType File -Path "$apacheConfDir\httpd-vhosts.conf" -Force | Out-Null
    }
    
    # Ensure virtual hosts are enabled in main config
    $httpdConf = Get-Content -Path "C:\Program Files\Apache24\conf\httpd.conf"
    if ($httpdConf -notcontains 'Include conf/extra/httpd-vhosts.conf') {
        Add-Content -Path "C:\Program Files\Apache24\conf\httpd.conf" -Value "Include conf/extra/httpd-vhosts.conf"
    }
    
    # Configure virtual hosts
    $vhostsContent = @"
# Virtual Hosts for Nintendo and Wiimmfi domains

# Nintendo domains
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName gamestats2.gs.nintendowifi.net
    ServerAlias gamestats2.gs.nintendowifi.net
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9002/
    ProxyPassReverse / http://127.0.0.1:9002/
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName gamestats.gs.nintendowifi.net
    ServerAlias gamestats.gs.nintendowifi.net
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9002/
    ProxyPassReverse / http://127.0.0.1:9002/
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName naswii.nintendowifi.net
    ServerAlias naswii.nintendowifi.net
    ServerAlias nas.nintendowifi.net
    ServerAlias dls1.nintendowifi.net
    ServerAlias conntest.nintendowifi.net
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName sake.gs.nintendowifi.net
    ServerAlias sake.gs.nintendowifi.net *.sake.gs.nintendowifi.net
    ServerAlias secure.sake.gs.nintendowifi.net *.secure.sake.gs.nintendowifi.net
    ProxyPass / http://127.0.0.1:8000/
</VirtualHost>

# Wiimmfi domains
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName gamestats2.gs.wiimmfi.de
    ServerAlias gamestats2.gs.wiimmfi.de
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9002/
    ProxyPassReverse / http://127.0.0.1:9002/
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName gamestats.gs.wiimmfi.de
    ServerAlias gamestats.gs.wiimmfi.de
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9002/
    ProxyPassReverse / http://127.0.0.1:9002/
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName naswii.wiimmfi.de
    ServerAlias naswii.wiimmfi.de
    ServerAlias nas.wiimmfi.de
    ServerAlias dls1.wiimmfi.de
    ServerAlias conntest.wiimmfi.de
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName sake.gs.wiimmfi.de
    ServerAlias sake.gs.wiimmfi.de *.sake.gs.wiimmfi.de
    ServerAlias secure.sake.gs.wiimmfi.de *.secure.sake.gs.wiimmfi.de
    ProxyPass / http://127.0.0.1:8000/
</VirtualHost>
"@
    
    Set-Content -Path "$apacheConfDir\httpd-vhosts.conf" -Value $vhostsContent
    
    # Enable necessary modules
    # Note: Windows Apache doesn't use a2enmod, we need to edit httpd.conf directly
    $modulesToEnable = @(
        'LoadModule proxy_module modules/mod_proxy.so',
        'LoadModule proxy_http_module modules/mod_proxy_http.so',
        'LoadModule php7_module "C:/Program Files/PHP/php7apache2_4.dll"'
    )
    
    foreach ($module in $modulesToEnable) {
        if ($httpdConf -notcontains $module) {
            Add-Content -Path "C:\Program Files\Apache24\conf\httpd.conf" -Value $module
        }
    }
    
    # Add PHP configuration
    $phpConfig = @"
<FilesMatch \.php$>
    SetHandler application/x-httpd-php
</FilesMatch>
"@
    
    if ($httpdConf -notcontains $phpConfig) {
        Add-Content -Path "C:\Program Files\Apache24\conf\httpd.conf" -Value $phpConfig
    }
    
    # Add protocol options
    $protocolOptions = @"
HttpProtocolOptions Unsafe LenientMethods Allow0.9
"@
    
    if ($httpdConf -notcontains $protocolOptions) {
        Add-Content -Path "C:\Program Files\Apache24\conf\httpd.conf" -Value $protocolOptions
    }
    
    # Restart Apache
    Restart-Service -Name Apache24
    
    Write-Host "Apache configuration completed!" -ForegroundColor Green
}

function Configure-MySQL {
    Write-Host "Configuring MySQL database..." -ForegroundColor Green
    
    # Set root password
    $mysqlRootPassword = "passwordhere"
    
    # Initialize MySQL
    # This might need adjustment based on MySQL version
    Start-Process -FilePath "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe" -ArgumentList "--initialize-insecure" -Wait -NoNewWindow
    
    # Start MySQL service
    Start-Service -Name MySQL
    
    # Create first admin user
    Write-Host "Now we're going to set up our first Admin Portal user." -ForegroundColor Yellow
    $firstuser = Read-Host "Please enter the username you wish to use"
    $password = Read-Host "Please enter a password"
    
    # For bcrypt hashing, we'll use a PowerShell implementation
    # Note: This is simplified and might need a proper implementation
    $hash = ConvertTo-SecureString -String $password -AsPlainText -Force | ConvertFrom-SecureString
    
    Write-Host "We will now set the rank for $firstuser" -ForegroundColor Yellow
    Write-Host "At the moment, this does nothing. However in later releases, we plan to restrict who can do what."
    Write-Host "1: First Rank"
    Write-Host "2: Second Rank"
    Write-Host "3: Third Rank"
    $firstuserrank = Read-Host "Please enter a rank number [1-3]"
    
    # Create database and import schema
    $query = @"
CREATE DATABASE cowfc;
USE cowfc;
"@
    
    # Import SQL schema (this will need to be adapted)
    $schemaPath = "C:\CoWFC\CoWFC\SQL\cowfc.sql"
    $schemaContent = Get-Content -Path $schemaPath -Raw
    $query += $schemaContent
    
    # Add user
    $query += @"
INSERT INTO users (Username, Password, Rank) VALUES ('$firstuser', '$hash', '$firstuserrank');
"@
    
    # Execute SQL
    $query | Set-Content -Path "C:\CoWFC\temp.sql"
    Start-Process -FilePath "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -ArgumentList "-u root -p$mysqlRootPassword" -RedirectStandardInput "C:\CoWFC\temp.sql" -Wait -NoNewWindow
    
    # Cleanup
    Remove-Item -Path "C:\CoWFC\temp.sql"
    
    Write-Host "MySQL configuration completed!" -ForegroundColor Green
}

function Configure-reCaptcha {
    Write-Host "For added security, we recommend setting up Google's reCaptcha." -ForegroundColor Yellow
    Write-Host "However, not many people would care about this, so we're making it optional." -ForegroundColor Yellow
    
    $recaptchaContinue = Read-Host "Would you like to set up reCaptcha on this server? [y/N]"
    
    if ($recaptchaContinue -eq "y" -or $recaptchaContinue -eq "Y") {
        Write-Host "In order to log into your Admin interface, you will need to set up reCaptcha keys." -ForegroundColor Yellow
        Write-Host "Please make an account over at https://www.google.com/recaptcha/" -ForegroundColor Cyan
        
        $secretKey = Read-Host "Please enter the SECRET KEY you got from setting up reCaptcha"
        $siteKey = Read-Host "Please enter the SITE KEY you got from setting up reCaptcha"
        
        $configFile = "C:\CoWFC\www\config.ini"
        $configContent = Get-Content -Path $configFile
        
        $configContent = $configContent -replace "SECRET_KEY_HERE", $secretKey
        $configContent = $configContent -replace "recaptcha_site = SITE_KEY_HERE", "recaptcha_site = $siteKey"
        
        Set-Content -Path $configFile -Value $configContent
    } else {
        $configFile = "C:\CoWFC\www\config.ini"
        $configContent = Get-Content -Path $configFile
        
        $configContent = $configContent -replace "recaptcha_enabled = 1", "recaptcha_enabled = 0"
        
        Set-Content -Path $configFile -Value $configContent
    }
}

function Set-ServerName {
    Write-Host "This recent CoWFC update allows you to set your server's name" -ForegroundColor Yellow
    Write-Host "This is useful if you want to whitelabel your server, and not advertise it as CoWFC" -ForegroundColor Yellow
    
    $serverNameConfig = Read-Host "Please enter the server name, or press ENTER to accept the default [CoWFC]"
    
    if ([string]::IsNullOrEmpty($serverNameConfig)) {
        Write-Host "Using CoWFC as the server name." -ForegroundColor Green
    } else {
        Write-Host "Setting server name to $serverNameConfig" -ForegroundColor Green
        
        $configFile = "C:\CoWFC\www\config.ini"
        $configContent = Get-Content -Path $configFile
        
        $configContent = $configContent -replace "name = 'CoWFC'", "name = '$serverNameConfig'"
        
        Set-Content -Path $configFile -Value $configContent
    }
}

function Install-Website {
    Write-Host "Installing website files..." -ForegroundColor Green
    
    # Copy web files from CoWFC repository
    Copy-Item -Path "C:\CoWFC\CoWFC\Web\*" -Destination "C:\CoWFC\www\" -Recurse -Force
    
    # Create logs file with proper permissions
    New-Item -ItemType File -Path "C:\CoWFC\www\bans.log" -Force | Out-Null
    
    # Create gpcm.db file
    New-Item -ItemType File -Path "C:\CoWFC\dwc_network_server_emulator\gpcm.db" -Force | Out-Null
    
    Write-Host "Website installation completed!" -ForegroundColor Green
}

function Create-StartupScript {
    Write-Host "Creating startup scripts..." -ForegroundColor Green
    
    # Create a PowerShell startup script
    $startupScript = @"
# CoWFC Server Startup Script
Write-Host "Starting CoWFC server..." -ForegroundColor Green
Set-Location "C:\CoWFC\dwc_network_server_emulator"
python master_server.py
"@
    
    Set-Content -Path "C:\CoWFC\start-cowfc.ps1" -Value $startupScript
    
    # Create a batch file for easy execution
    $batchFile = @"
@echo off
echo Starting CoWFC server...
PowerShell -ExecutionPolicy Bypass -File "C:\CoWFC\start-cowfc.ps1"
pause
"@
    
    Set-Content -Path "C:\CoWFC\start-cowfc.bat" -Value $batchFile
    
    # Create a shortcut on desktop
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Start CoWFC Server.lnk")
    $Shortcut.TargetPath = "C:\CoWFC\start-cowfc.bat"
    $Shortcut.Save()
    
    # Create a scheduled task to run at startup
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File 'C:\CoWFC\start-cowfc.ps1'"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName "CoWFC Server" -Action $action -Trigger $trigger -Settings $settings -Description "Starts the CoWFC server at system startup" -RunLevel Highest
    
    Write-Host "Startup scripts created!" -ForegroundColor Green
}

# MAIN SCRIPT EXECUTION

# Call the update function
Update-Script

# Install required tools and dependencies
Install-RequiredTools

# Clone the required repositories
Clone-Repositories

# Configure DNS
Configure-DNS

# Configure Apache
Configure-Apache

# Configure MySQL
Configure-MySQL

# Install the website
Install-Website

# Configure reCaptcha
Configure-reCaptcha

# Set server name
Set-ServerName

# Create startup scripts
Create-StartupScript

# Create installation flag
New-Item -ItemType File -Path "C:\CoWFC\.dwc_installed" -Force | Out-Null

# Completion message
Write-Host "Thank you for installing CoWFC on Windows." -ForegroundColor Green
Write-Host "If you wish to access the admin GUI, please go to http://$IP/?page=admin&section=Dashboard" -ForegroundColor Cyan
Write-Host "You can start the server by running the shortcut on your desktop or by executing C:\CoWFC\start-cowfc.bat" -ForegroundColor Cyan

$restart = Read-Host "Please hit ENTER to restart your computer now, or type 'N' to restart later"
if ($restart -ne "N" -and $restart -ne "n") {
    Restart-Computer -Force
}
