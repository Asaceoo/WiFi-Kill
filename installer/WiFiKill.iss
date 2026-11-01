; WiFiKill 安装脚本（Inno Setup 6）
; 构建时由 build.py 传入 /DAppVersion=x.y.z

#define AppName "WiFiKill"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppPublisher "WiFiKill Project"
#define AppExe "WiFiKill.exe"

[Setup]
AppId={{9C2B41A7-5F3D-4E6B-8A21-7D4F0C5E9B13}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={localappdata}\Programs\WiFiKill
DefaultGroupName=WiFiKill
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=WiFiKill-v{#AppVersion}-setup
SetupIconFile=..\wifikill.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
AllowNoIcons=yes
CloseApplications=yes

[Languages]
Name: "zh"; MessagesFile: "ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
Source: "..\dist\WiFiKill.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\USER_MANUAL.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\TECH_MANUAL.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\WiFiKill"; Filename: "{app}\{#AppExe}"
Name: "{group}\用户手册"; Filename: "{app}\docs\USER_MANUAL.md"
Name: "{group}\卸载 WiFiKill"; Filename: "{uninstallexe}"
Name: "{autodesktop}\WiFiKill"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "https://npcap.com/#download"; Description: "打开 Npcap 下载页（必需驱动）"; Flags: shellexec nowait postinstall
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,WiFiKill}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\.wifikill-state.json"
Type: files; Name: "{app}\whitelist.txt"
