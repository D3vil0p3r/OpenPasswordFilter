# OpenPasswordFilter
An open source custom password filter DLL and user-space service for Active Directory domain passwords.

## Introduction

The original [OpenPasswordFilter](https://github.com/jephthai/OpenPasswordFilter) has been redesigned to work with the latest .NET libraries.

The genesis of this idea comes from conducting many penetration tests where organizations have users who choose common passwords and the ultimate difficulty of controlling this behavior. The fact is that any domain of size will have some user who chose `Password1` or `Summer2015` or `Company123` as their password.  Any intruder or low-privilege user who can guess or obtain usernames for the domain can easily run through these very common passwords and start expanding the level of access in the domain.

Microsoft provides a wonderful feature in Active Directory, which is the ability to create a custom password filter DLL. This DLL is loaded by LSASS on boot (if configured), and will be queried for each new password users attempt to set.  The DLL simply replies with a `TRUE` or `FALSE`, as appropriate, to indicate that the password passes or fails the test.

There are some commercial options, but they are usually in the "call for pricing" category, and that makes it a little prohibitive for some organizations to implement truly effective preventive controls for this class of very common bad passwords.

This is where OpenPasswordFilter (OPF) comes in: an open source solution to add basic dictionary-based rejection of common passwords.

OPF is comprised of two main parts:
   1. **OpenPasswordFilter.dll:** a custom password filter DLL that can be loaded by LSASS to vet incoming password changes;
   2. **OPFService.exe:** a C#-based service binary that provides a local user-space service for maintaining the dictionary and servicing requests.

The DLL communicates with the service on the loopback network interface to check passwords against the configured database of forbidden values. This architecture is selected because it is difficult to reload the DLL after boot, and administrators are likely loathe to reboot their Domain Controllers when they want to add another forbidden password to the list. Just bear in mind how this architecture works so you understand what's going on.

## Prerequisites

* .NET 4.8
* [Microsoft Visual Studio Installer Projects 2022 Extension](https://marketplace.visualstudio.com/items?itemName=VisualStudioClient.MicrosoftVisualStudio2022InstallerProjects)

## Installation

### Auto

Download the [latest release](https://github.com/D3vil0p3r/OpenPasswordFilter/releases/latest) and run the installer in all the Domain Controllers.

Be sure that files are installed inside the SYSVOL directory.

### Manual

You will want to configure the DLL so that Windows will load it for filtering passwords. Note that you will have to do this on all domain controllers, as any of them may end up servicing a password change request. Read the Microsoft's documentation for [setting up a password filter](https://learn.microsoft.com/en-us/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll).

The bottom line is this:
  1. Copy `OpenPasswordFilter.dll` to `%WINDIR%\System32`;
  2. Configure the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` registry key with the DLL name.

Note, you do not include the `.dll` extension in the registry key, just `OpenPasswordFilter`.

Next, you will want to configure the OPF service. You can do so as follows:
```
> sc create OPF binPath= "<full path to exe>\opfservice.exe" start= boot
```

### Configuration 

Create the dictionary files you need inside the SYSVOL directory. OPF supports the following dictionary files to be created:
* **opfmatch.txt:** all passwords full matching a string will be rejected
* **opfcont.txt:** all passwords partial matching a string inside the file will be rejected
* **opfregex.txt:** all passwords matching the specified regex patterns inside the file will be rejected
* **opfnoregex.txt:** all passwords not matching the specified regex patterns inside the file will be rejected

Furthermore, you can create also **opfgroups.txt** where to insert only domain users the password filter will be applied to.

For example, `opfmatch.txt` could contain one forbidden string per line, such as:
```
Password1
Password2
Company123
Summer15
Summer2015
...
```
I recommend constructing a list of bad seeds, then using hashcat rules to build `opfcont.txt` with the sort of leet mangling users are likely to try, like so:
```
hashcat -r /usr/share/hashcat/rules/Incisive-leetspeak.rule --stdout seedwordlist | tr A-Z a-z | sort | uniq > opfcont.txt
```
Bear in mind that if you use a Unix-like system to create your wordlists, the line terminators will need changing to Windows format:
```
unix2dos opfcont.txt
```
If the service fails to start, it's likely an error ingesting the wordlists, and the line number of the problem entry will be written to the Application event log.

If all has gone well, reboot your Domain Controller and test by using the normal GUI password reset function to choose a password that is on your forbidden list.
