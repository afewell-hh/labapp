#!/bin/bash
# 04.5-install-desktop.sh
# Install XFCE desktop environment, remote access (RDP/VNC), and VS Code
# Part of Hedgehog Lab Appliance build pipeline (Issue #86)

set -euo pipefail

echo "=================================================="
echo "Installing Desktop Environment and Remote Access..."
echo "=================================================="

# Update package lists
echo "Updating package lists..."
apt-get update

# Install XFCE desktop environment (lightweight)
echo "Installing XFCE desktop environment..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    xfce4 \
    xfce4-goodies \
    xfce4-terminal \
    lightdm \
    dbus-x11 \
    x11-xserver-utils

# Configure LightDM to auto-start
echo "Configuring LightDM display manager..."
systemctl set-default graphical.target
systemctl enable lightdm

# Install xRDP for RDP access
echo "Installing xRDP for RDP access..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    xrdp \
    xorgxrdp

# Configure xRDP
echo "Configuring xRDP..."
# Add xrdp user to ssl-cert group for certificate access
adduser xrdp ssl-cert

# Create xRDP startup script for XFCE
cat > /etc/xrdp/startxfce.sh <<'EOF'
#!/bin/sh
# xrdp XFCE session startup script
export XDG_SESSION_DESKTOP=xfce
export XDG_DATA_DIRS=/usr/share/xfce4:/usr/local/share:/usr/share:/var/lib/snapd/desktop
export XDG_CONFIG_DIRS=/etc/xdg/xfce4:/etc/xdg:/usr/share/upstart/xdg
exec startxfce4
EOF

chmod +x /etc/xrdp/startxfce.sh

# Configure xRDP to use XFCE
# Replace the default Xsession exec with our XFCE startup script
sed -i 's|^test -x /etc/X11/Xsession|#test -x /etc/X11/Xsession|' /etc/xrdp/startwm.sh
sed -i 's|^exec /bin/sh /etc/X11/Xsession|exec /etc/xrdp/startxfce.sh|' /etc/xrdp/startwm.sh

# Enable and start xRDP service
systemctl enable xrdp
systemctl enable xrdp-sesman

# Install TigerVNC server for VNC access
echo "Installing TigerVNC server..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tigervnc-standalone-server \
    tigervnc-common

# Configure VNC for user hhlab
echo "Configuring VNC server for hhlab user..."

# Create VNC directory and set ownership first
mkdir -p /home/hhlab/.vnc
chown -R hhlab:hhlab /home/hhlab/.vnc

# Set VNC password using vncpasswd non-interactive mode
# Note: Password is 'hhlab' - for lab/demo use only
# Use full path to vncpasswd as it may not be in PATH immediately after install
echo 'hhlab' | /usr/bin/vncpasswd -f | sudo -u hhlab tee /home/hhlab/.vnc/passwd > /dev/null
sudo -u hhlab chmod 600 /home/hhlab/.vnc/passwd

# Create VNC xstartup script
cat > /home/hhlab/.vnc/xstartup <<'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
EOF

chmod +x /home/hhlab/.vnc/xstartup
chown hhlab:hhlab /home/hhlab/.vnc/xstartup

# Create systemd service for VNC
cat > /etc/systemd/system/vncserver@.service <<'EOF'
[Unit]
Description=Start TigerVNC server at startup
After=syslog.target network.target

[Service]
Type=forking
User=hhlab
Group=hhlab
WorkingDirectory=/home/hhlab

ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill :%i > /dev/null 2>&1 || :'
ExecStart=/usr/bin/vncserver :%i -geometry 1920x1080 -depth 24 -localhost no
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
EOF

# Enable VNC server on display :1
systemctl daemon-reload
systemctl enable vncserver@1.service

# Install VS Code
echo "Installing Visual Studio Code..."

# Install gnupg for key management (required on minimal Ubuntu images)
DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg

# Add Microsoft GPG key and repository
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /usr/share/keyrings/packages.microsoft.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list

# Update and install VS Code
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y code

# Install useful VS Code dependencies and tools
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    fonts-firacode \
    fonts-liberation \
    fonts-noto \
    firefox

# Create desktop shortcuts for hhlab user
echo "Creating desktop shortcuts..."
mkdir -p /home/hhlab/Desktop

# VS Code desktop shortcut
cat > /home/hhlab/Desktop/code.desktop <<'EOF'
[Desktop Entry]
Name=Visual Studio Code
Comment=Code Editing. Redefined.
GenericName=Text Editor
Exec=/usr/bin/code --no-sandbox --user-data-dir=/home/hhlab/.vscode
Icon=code
Type=Application
StartupNotify=false
Categories=Development;IDE;
MimeType=text/plain;inode/directory;
EOF

chmod +x /home/hhlab/Desktop/code.desktop

# Terminal desktop shortcut
cat > /home/hhlab/Desktop/terminal.desktop <<'EOF'
[Desktop Entry]
Name=Terminal
Comment=Terminal Emulator
GenericName=Terminal
Exec=xfce4-terminal
Icon=utilities-terminal
Type=Application
Categories=System;TerminalEmulator;
EOF

chmod +x /home/hhlab/Desktop/terminal.desktop

# Firefox desktop shortcut
cat > /home/hhlab/Desktop/firefox.desktop <<'EOF'
[Desktop Entry]
Name=Firefox Web Browser
Comment=Browse the World Wide Web
GenericName=Web Browser
Exec=firefox %u
Icon=firefox
Type=Application
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;
EOF

chmod +x /home/hhlab/Desktop/firefox.desktop

# Set ownership
chown -R hhlab:hhlab /home/hhlab/Desktop

# Configure auto-login for hhlab user (optional - commented out for security)
# echo "Configuring auto-login..."
# cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf <<'EOF'
# [Seat:*]
# autologin-user=hhlab
# autologin-user-timeout=0
# EOF

# Create a welcome message/README on desktop
cat > /home/hhlab/Desktop/README.txt <<'EOF'
Hedgehog Lab Appliance - Desktop Access

Welcome to the Hedgehog Lab Appliance!

Remote Access:
--------------
RDP: Connect using any RDP client to this VM's IP address on port 3389
     Username: hhlab
     Password: hhlab

VNC: Connect using any VNC client to this VM's IP address on port 5901
     Password: hhlab

Tools Installed:
----------------
- Visual Studio Code: Modern code editor
- Firefox: Web browser
- Terminal: Command-line access

Getting Started:
----------------
1. Open Terminal from the desktop
2. Run 'hh-lab status' to check lab environment status
3. Access Hedgehog dashboards via Firefox

For more information, see the documentation in /home/hhlab/

Note: Default credentials (hhlab/hhlab) are for lab use only.
      Change passwords in production environments.
EOF

chown hhlab:hhlab /home/hhlab/Desktop/README.txt

# Configure firewall rules for RDP and VNC (if ufw is active)
if systemctl is-active --quiet ufw; then
    echo "Configuring firewall rules..."
    ufw allow 3389/tcp comment 'RDP access'
    ufw allow 5901/tcp comment 'VNC access'
fi

echo "=================================================="
echo "Desktop environment installation complete!"
echo ""
echo "Installed components:"
echo "  - XFCE desktop environment"
echo "  - xRDP server (RDP access on port 3389)"
echo "  - TigerVNC server (VNC access on port 5901)"
echo "  - Visual Studio Code"
echo "  - Firefox web browser"
echo ""
echo "Default credentials: hhlab / hhlab"
echo "=================================================="
