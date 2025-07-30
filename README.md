# Semaine 3 – État d’avancement

---

🎯 Sujet : *Automated Hardening of VMs Windows & Linux sur VMware & Nutanix*

---

[Références](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md)

## 1.2 Package Management

| Rule ID | Description | Verification | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 1.2.1.1 | Ensure GPG keys are configured |  `apt-key list` | Verify GPG keys are configured correctly for your package manager:
 |  |
| 1.2.1.2 | Ensure package manager repositories are configured  | `apt-cache policy` | verify package repositories are configured correctly |  |
| 1.2.2.1 | Ensure updates, patches, and additional security software
are installed | `apt update`
`apt -s upgrade` 
Verify there are no updates or patches to install |  `apt update
 apt upgrade`
- OR -
 `apt dist-upgrade`

[**** (1) see more info***](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) |  |

---

## 1.3 Mandatory Access Control

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 1.3.1.1 | Ensure AppArmor is installed | `dpkg-query -s apparmor &>/dev/null && echo "apparmor is installed”`
———————
`dpkg-query -s apparmor-utils &>/dev/null && echo "apparmor-utils is
installed"`   [****(2)***](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Install AppArmor.
`apt install apparmor apparmor-utils` |  |
| 1.3.1.2 | Ensure AppArmor is enabled in the bootloader configuration | `grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"`
Nothing should be returned
`grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor"`
Nothing should be returned | Edit ***/etc/default/grub*** and add the apparmor=1 and security=apparmor parameters to
the `GRUB_CMDLINE_LINUX= line
GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"`
Run the following command to update the grub2 configuration:
 `update-grub` |  |
| 1.3.1.3 | Ensure all AppArmor profiles are in enforce or complain mode 
[*(3) see more infos](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following command and verify that profiles are loaded, and are in either enforce
or complain mode:
`apparmor_status | grep profiles`
————————-
Run the following command and verify no processes are unconfined :
 `apparmor_status | grep processes` | Run the following command to set all profiles to ***enforce mode:*** 
`aa-enforce /etc/apparmor.d/*`
OR
Run the following command to set all profiles to ***complain mode:***
 `aa-complain /etc/apparmor.d/*` |  |
| 1.3.1.4 | Ensure All AppArmor profiles are enforcing | same as 1.3.1.3 | Set all profiles to ***enforce mode  :*** 
`aa-enforce /etc/apparmor.d/*` |  |

---

***5. Access Control :***

# 5.1. Configure SSH Server

[*(4) see more infos](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md)

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.1.1 | Ensure permissions on /etc/ssh/sshd_config are configured
**————————————**
The file `/etc/ssh/sshd_config`, and files ending in .conf in the /etc/ssh/sshd_config.d
directory, contain configuration specifications for sshd.
configuration specifications for sshd need to be protected from unauthorized changes by
non-privileged users.
—> This script verifies that **SSH configuration files** (including any `.conf` files inside `sshd_config.d`) meet **secure permissions and ownership**: | Run the following script and verify /etc/ssh/sshd_config and files ending in .conf in
the /etc/ssh/sshd_config.d directory are:
• Mode 0600 or more restrictive
• Owned by the root user
• Group owned by the group root.

[*(5) to see the command](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following script to set ownership and permissions on /etc/ssh/sshd_config
and files ending in .conf in the /etc/ssh/sshd_config.d directory:

`#!/usr/bin/env bash
{
chmod u-x,og-rwx /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
while IFS= read -r -d $'\0' l_file; do
if [ -e "$l_file" ]; then
chmod u-x,og-rwx "$l_file"
chown root:root "$l_file"
fi
done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
}`
 |  |
| 5.1.4 | Ensure sshd access is configured
→ Restricting which users can remotely access the system via SSH will help ensure that
only authorized users access the system
[*(6) see more](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following command and verify the output:
 `sshd -T | grep -Pi -- '^\h*(allow|deny)(users|groups)\h+\H+’`
————————
Verify that the output matches at least one of the following lines:
`allowusers <userlist>
-ORallowgroups <grouplist>
-ORdenyusers <userlist>
-ORdenygroups <grouplist>` | Edit the /etc/ssh/sshd_config file to set one or more of the parameters above any
Include and Match set statements as follows:
`AllowUsers <userlist>
- AND/OR -
AllowGroups <grouplist>` |  |
| 5.1.7 | Ensure sshd ClientAliveInterval and ClientAliveCountMax
are configured
[*(7) see more](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following command and verify ClientAliveInterval and ClientAliveCountMax
are greater than zero:
 `sshd -T | grep -Pi -- '(clientaliveinterval|clientalivecountmax)'`
 | Edit the /etc/ssh/sshd_config file to set the ClientAliveInterval and
ClientAliveCountMax parameters above any Include and Match entries according to
site policy.
Example:
`ClientAliveInterval 15
ClientAliveCountMax 3` |  |
| 5.1.10 | Ensure sshd HostbasedAuthentication is disabled
—————————
[*(8) see more infos](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following command to verify HostbasedAuthentication is set to no:
 `sshd -T | grep hostbasedauthentication`
hostbasedauthentication no | Edit the `/etc/ssh/sshd_config` file to set the HostbasedAuthentication parameter to no
above any Include and Match entries as follows:
HostbasedAuthentication no |  |
| 5.1.11 |  Ensure sshd IgnoreRhosts is enabled 

Setting this parameter forces users to enter a password when authenticating with SSH

→ The `IgnoreRhosts` parameter tells the SSH server **not to use `.rhosts` or `.shosts` files** for authentication — these are **very old files** used to **trust other machines/users without a password**. | Run the following command to verify IgnoreRhosts is set to yes:
 `sshd -T | grep ignorerhosts
ignorerhosts yes` | Edit the /etc/ssh/sshd_config file to set the IgnoreRhosts parameter to yes above any
Include and Match entries as follows:
`IgnoreRhosts yes` |  |
| 5.1.14 | Ensure sshd LogLevel is configured
(Default Value:
LogLevel INFO)
—————————-
[*(9) see more details](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following command and verify that output matches loglevel VERBOSE or
loglevel INFO:
`sshd -T | grep loglevel`
 | Edit the /etc/ssh/sshd_config file to set the LogLevel parameter to VERBOSE or INFO
above any Include and Match entries as follows:
`LogLevel VERBOSE
- OR -
LogLevel INFO` |  |
| 5.1.19 | Ensure sshd PermitEmptyPasswords is disabled
—————————-
The PermitEmptyPasswords parameter specifies if the SSH server allows login to
accounts with empty password strings
→ *Disallowing remote shell access to accounts that have an empty password reduces the
probability of unauthorized access to the system* | Run the following command to verify PermitEmptyPasswords is set to no:
 `sshd -T | grep permitemptypasswords`

----------------------
output :
permitemptypasswords no | Edit /etc/ssh/sshd_config and set the PermitEmptyPasswords parameter to no above
any Include and Match entries as follows:
PermitEmptyPasswords no |  |
| 5.1.20 | Ensure sshd PermitRootLogin is disabled
——————
The PermitRootLogin parameter specifies if the root user can log in using SSH. The
default is prohibit-password.
—> 
Disallowing root logins over SSH requires system admins to authenticate using their
own individual account, then escalating to root. This limits opportunity for nonrepudiation and provides a clear audit trail in the event of a security incident.
[*(10) see more](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md)  | Run the following command to verify PermitEmptyPasswords is set to no:
 `sshd -T | grep permitemptypasswords` | Edit /etc/ssh/sshd_config and set the PermitEmptyPasswords parameter to no above
any Include and Match entries as follows:
PermitEmptyPasswords no |  |
| 5.1.22 |  Ensure sshd UsePAM is enabled
[*(11) see more details](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Run the following command to verify UsePAM is set to yes:
`sshd -T | grep -i usepam
usepam yes`
 | Edit the /etc/ssh/sshd_config file to set the UsePAM parameter to yes above any
Include entries as follows:
UsePAM yes |  |

---

# 5.3 Pluggable Authentication Modules

[*(12) see more infos](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md)

## **5.3.1  Configure PAM software packages**

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.3.1.1 | Ensure latest version of pam is installed
———————————
To ensure the system has full functionality and access to the options covered by this
Benchmark the latest version of libpam-runtime should be installed on the system | Run the following command to verify the version of libpam-runtime on the system: `dpkg-query -s libpam-runtime | grep -P -- '^(Status|Version)\b'`
→ The output should be similar to:
Status: install ok installed
Version: 1.4.0-9
 | **IF -** the version of libpam-runtime on the system is less that version 1.5.2-6:
Run the following command to update to the latest version of PAM:
`apt upgrade libpam-runtime`
 |  |
| 5.3.1.2 | Ensure libpam-modules is installed 
————————-
Pluggable Authentication Modules for PAM
 | Run the following command to verify libpam-modules is installed and version 1.5.2-6 or
later:
`dpkg-query -s libpam-modules | grep -P -- '^(Status|Version)\b'`
→ The output should be similar to:
Status: install ok installed
Version: 1.4.0-9
 | **IF -** is less that version 1.5.2-6

`apt upgrade libpam-modules` |  |
| 5.3.1.3 | Ensure libpam-pwquality is installed
————————-
Strong passwords reduce the risk of systems being hacked through brute force
methods
→
It’s a **PAM module** that checks the **strength and complexity** of passwords during user creation or password changes. | Run the following command to verify libpam-pwquality is installed:
`dpkg-query -s libpam-pwquality | grep -P -- '^(Status|Version)\b'`
→ The output should be similar to:
Status: install ok installed
Version: 1.4.4-1 | Run the following command to install libpam-pwquality:
`apt install libpam-pwquality` |  |

## **5.3.2  Configure pam-auth-update profiles**

[*(13) see more details :](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) 

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.3.2.1 | Ensure **pam_unix** module is enabled 
———————————
**pam_unix** is the standard Unix authentication module. It uses standard calls from the
system's libraries to retrieve and set account information as well as authentication.
Usually this is obtained from the /etc/passwd and if shadow is enabled, the /etc/shadow
file as well. | Run the following command to verify that pam_unix is enabled:
`grep -P -- '\bpam_unix\.so\b' /etc/pam.d/common-
{account,session,auth,password}` | Run the following command to enable the pam_unix module:
`pam-auth-update --enable unix` |  |
| 5.3.2.2 | Ensure **pam_faillock** module is enabled 
—————————-
This module protects against brute-force login attacks by **locking** accounts after repeated failed attempts | Run the following commands to verify that pam_faillock is enabled:
 `grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/common-{auth,account}`

[*(15) see the exepected output](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | we will **create two configuration profiles** in `/usr/share/pam-configs/`, and then enable them using `pam-auth-update`

[*(16) see the steps here](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) |  |
| 5.3.2.3 |  Ensure pam_pwquality module is enabled 
————————-
`pam_pwquality.so` makes sure users choose **strong passwords** | Run the following command to verify that pam_pwhistory is enabled:
 `grep -P -- '\bpam_pwquality\.so\b' /etc/pam.d/common-password`
→ Output should be similar to:
password requisite pam_pwquality.so retry=3 | we check first if a profile is present , if  yes we enable it
if NOT we create one manually like we already did for 5.3.2.2

[*(17) see the steps here](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) |  |
| 5.3.2.4 | Ensure **pam_pwhistory** module is enabled
—————————
It’s a **PAM module** used to **remember a user's previous passwords**.This prevents users from reusing old passwords for example, alternating between `Password1` and `Password2` every time they’re required to change it. | Run the following command to verify that pam_pwhistory is enabled:
 `grep -P -- '\bpam_pwhistory\.so\b' /etc/pam.d/common-password`
→ Output should be similar to:
password requisite pam_pwhistory.so remember=24 enforce_for_root
try_first_pass use_authtok
 | same as we did in 5.3.2.3

[go check *(18) for the steps](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md)
 |  |

---

## **5.3.3  Configure PAM Arguments :**

### ****5.3.3.1 Configure pam_faillock module

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.3.3.1.1 | Ensure **password failed attempts lockout** is configured 
———————————-
The **deny=<n>** option will deny access if the number of consecutive authentication
failures for this user during the recent interval exceeds .
prevents brute force attacks
 | 1. Run the following command to verify that Number of failed logon attempts before the
account is locked is no greater than 5 and meets local site policy:
`grep -Pi -- '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf` 
——————————
2.Run the following command to verify that the deny argument has not been set, or 5 or
less and meets local site policy:
 `grep -Pi --
'^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h
+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth`
→ Nothing should be returned | Create or edit the following line in /etc/security/faillock.conf setting the deny option
to 5 or less:
**deny = 5**
Run the following command:
`grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?deny\b' /usr/share/pamconfigs/*`
**Edit any returned files and remove the deny=<N> arguments from the pam_faillock.so
line(s)**
 |  |
| 5.3.3.1.2 | Ensure password **unlock time** is configured 
—————————
It controls **how long a user remains locked** after reaching the limit of failed login attempts (controlled by `deny=`). | 1. To check the global unlock time:
`grep -Pi -- '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf`  
→ Should return something like `unlock_time = 900`
2. To check if `unlock_time` is set inside `pam.d` configs (which is not recommended):`bashCopyEditgrep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so.*unlock_time=' /etc/pam.d/common-auth` 
→ Should return **nothing** if properly configured (unlock_time should be in `faillock.conf`, not directly in PAM files). | **1. Set the proper unlock time** in `/etc/security/faillock.conf`:`bashCopyEditunlock_time = 900`  

**2. Remove any unlock_time settings** from `/etc/pam.d/common-auth`:
run 
`grep -Pl -- '\bpam_faillock\.so.*unlock_time\b' /usr/share/pam-configs/*` 

Then edit any returned files to remove the `unlock_time=<n>` part. |  |
| 5.3.3.1.3 | Ensure password failed attempts lockout includes **root**
account
—————————
Use of unlock_time=0 or root_unlock_time=0 may allow an attacker to cause denial of
service to legitimate users.
 | 1. **Audit Step 1: Check faillock.conf**
`grep -Pi -- '^\h*(even_deny_root|root_unlock_time\h*=\h*\d+)\b' /etc/security/faillock.conf`

**2.Audit Step 2: Check if root_unlock_time < 60 (bad)**
`grep -Pi -- '^\h*root_unlock_time\h*=\h*([1-9]|[1-5][0-9])\b' /etc/security/faillock.conf`
****Good result = **no output 

3.** Check if root_unlock_time is hardcoded in /etc/pam.d/common-auth :
`grep -Pi -- '^\h*auth\h+([^#\n\r]+\h+)pam_faillock\.so\h+([^#\n\r]+\h+)?root_unlock_time\h*=\h*([1-9]|[1-5][0-9])\b' /etc/pam.d/common-auth`
Good result = **no output** | 1. **Edit /etc/security/faillock.conf:** `even_deny_root
root_unlock_time = 600`  

2.**Prevent hardcoding in PAM profiles:**
Run:
`grep -Pl '\bpam_faillock\.so\h+([^#\n\r]+\h+)?(even_deny_root|root_unlock_time)' /usr/share/pam-configs/*` 
→ This checks if **any PAM profile** (in `/usr/share/pam-configs/`) is trying to hardcode those options. Then for each file it shows, **remove the `root_unlock_time` or `even_deny_root` arguments** from the line that contains `pam_faillock.so`

3. Then regenerate PAM configs: `pam-auth-update` |  |

### 5.3.3.2 Configure pam_pwquality module

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.3.3.2.1 | Ensure password number of changed characters is
configured
———————
`difok` It defines the **minimum number of characters that must be different between the new password and the old one** | 1. Check if `difok` is properly set in configuration files:
`grep -Psi -- '^\h*difok\h*=\h*([2-9]|[1-9][0-9]+)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf` 
→ This should return something like: **/etc/security/pwquality.conf.d/50-pwdifok.conf:difok = 2

2.** Make sure it’s NOT set in PAM files:
`grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?difok\h*=\h*([0-1])\b' /etc/pam.d/common-password` 
→This should return nothing. We **don’t want** difok defined directly here. | 1. Create or modify a file ending in .conf in the /etc/security/pwquality.conf.d/
directory or the file /etc/security/pwquality.conf and add or modify the following line
to set difok to 2 or more. Ensure setting conforms to local site policy:
`#!/usr/bin/env bash
{
sed -ri 's/^\s*difok\s*=/# &/' /etc/security/pwquality.conf
[ ! -d /etc/security/pwquality.conf.d/ ] && mkdir
/etc/security/pwquality.conf.d/
printf '\n%s' "difok = 2" > /etc/security/pwquality.conf.d/50-pwdifok.conf
}` 
———————————
2. Edit any returned files and remove the difok argument from the pam_pwquality.so
line(s):
 `grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?difok\b' /usr/share/pamconfigs/*`

 |  |
| 5.3.3.2.2 | Ensure minimum password length is configured (**minlen**)
————————
Ensure **passwords have a minimum length** (e.g., 12 or more characters) to improve resistance against brute-force or dictionary attacks. | 1. Check `pwquality.conf` and `pwquality.conf.d/*.conf` 

`grep -Psi -- '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' \
/etc/security/pwquality.conf/etc/security/pwquality.conf.d/*.conf`
→ If **no output**, it means no `minlen >= 14` was found → ❌ not compliant.

2. Ensure there’s NO low-value `minlen` hardcoded in PAM config
`grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\h*=\h*([0-9]|1[0-3])\b' \
/etc/pam.d/system-auth /etc/pam.d/common-password`
**→ Nothing should be returned** | 1. Create or modify a file ending in .conf in the `/etc/security/pwquality.conf.d/`
directory or the file `/etc/security/pwquality.conf` and add or modify the following line
to set password length of **14** or more characters. Ensure that password length conforms
to local site policy:
***Example:***
`#!/usr/bin/env bash
{
sed -ri 's/^\s*minlen\s*=/# &/' /etc/security/pwquality.conf
[ ! -d /etc/security/pwquality.conf.d/ ] && mkdir
/etc/security/pwquality.conf.d/
printf '\n%s' "minlen = 14" > /etc/security/pwquality.conf.d/50-
pwlength.conf
}`

2. Edit any returned files and remove the minlen argument from the pam_pwquality.so
line(s):
 `grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\b' /usr/share/pamconfigs/*`
 |  |
| 5.3.3.2.3 | Ensure password complexity is configured
[*(20) for more details](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | 1. Check the actual complexity settings
`grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass=\d*|[dulo]credit=-?\d*)\b' /etc/pam.d/common-password`

2. Ensure that **NO complexity settings are hardcoded** in `/etc/pam.d/common-password` 

`grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass=\d*|[dulo]credit=-?\d*)\b' /etc/pam.d/common-password`
 | 1. Find and clean up pam_pwquality.so config lines
`grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass|[dulo]credit)\b' /usr/share/pam-configs/*`

2. Backup & Comment Out Old Settings in `pwquality.conf` 

`sed -ri 's/^\s*minclass\s*=/# &/' /etc/security/pwquality.conf
sed -ri 's/^\s*[dulo]credit\s*=/# &/' /etc/security/pwquality.conf`

3. Create `/etc/security/pwquality.conf.d/` directory if missing

`[ ! -d /etc/security/pwquality.conf.d/ ] && mkdir /etc/security/pwquality.conf.d/`

4. Write your new complexity policy to a custom config file
**example :** 
`printf '%s\n' "dcredit = -1" "ucredit = -1" "lcredit = -1" > /etc/security/pwquality.conf.d/50-pwcomplexity.conf` |  |
| 5.3.3.2.4 | Ensure password same consecutive characters is
configured

————————

The pwquality **maxrepeat** option sets the maximum number of allowed same
consecutive characters in a new password | 1. Run the following command to verify that the maxrepeat option is set to 3 or less, not 0,
and follows local site policy:
`grep -Psi -- '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.conf` 

2. **Ensure** there’s NO low-value `maxrepeat`hardcoded in PAM config 
`grep -Psi --
'^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\
r]+\h+)?maxrepeat\h*=\h*(0|[4-9]|[1-9][0-9]+)\b' /etc/pam.d/common-password`
**→ Nothing should be returned** | 1.  set maxrepeat to 3 or less and not 0 :
**Example:**
`#!/usr/bin/env bash
{
sed -ri 's/^\s*maxrepeat\s*=/# &/' /etc/security/pwquality.conf
[ ! -d /etc/security/pwquality.conf.d/ ] && mkdir
/etc/security/pwquality.conf.d/
printf '\n%s' "maxrepeat = 3" > /etc/security/pwquality.conf.d/50-
pwrepeat.conf
}` 

2.  Edit any returned files and remove the maxrepeat argument from the pam_pwquality.so
line(s):
`grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?maxrepeat\b'
/usr/share/pam-configs/*`
 |  |
| 5.3.3.2.5 | Ensure password maximum sequential characters is
configured

———————-

The `maxsequence` option **limits the length of monotonic character sequences** in a password.

A monotonic sequence is a sequence of characters where each character is either:
-**Increasing** (e.g. `abcde`, `1234`, `qwerty`)
- **Decreasing** (e.g. `fedcba`, `4321`, `zyx`) | 1. Run the following command to verify that the maxsequence option is set to 3 or less, not
0 : 
 `grep -Psi -- '^\h*maxsequence\h*=\h*[1-3]\b' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.conf`

2. **Ensure** there’s NO low-value `maxsequence` hardcoded in PAM config 
`grep -Psi --
'^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\
r]+\h+)?maxsequence\h*=\h*(0|[4-9]|[1-9][0-9]+)\b' /etc/pam.d/common-password`
**→ Nothing should be returned** | 1.  set maxsequence to 3 or less and not 0 : 
**Example:**
`#!/usr/bin/env bash
{
sed -ri 's/^\s*maxsequence\s*=/# &/' /etc/security/pwquality.conf
[ ! -d /etc/security/pwquality.conf.d/ ] && mkdir
/etc/security/pwquality.conf.d/
printf '\n%s' "maxsequence = 3" > /etc/security/pwquality.conf.d/50-
pwmaxsequence.conf
}`

2.  Edit any returned files and remove the maxsequence argument from the pam_pwquality.so
line(s):
`grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?maxsequence\b' 
/usr/share/pam-configs/*` |  |
| 5.3.3.2.6 | Ensure password dictionary check is enabled

———————-

If `dictcheck=1`, the system will **reject passwords that contain words from the dictionary** (like `password`, `hello`, `admin`, `qwerty`, etc.).This check uses the **cracklib dictionary**, which is a list of commonly used or weak passwords/words. | 1. Run the following command to verify that the dictcheck option is not set to 0 (disabled)
in a pwquality configuration file:
`grep -Psi -- '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.conf`
**→ Nothing should be returned**

2. Run the following command to verify that the dictcheck option is not set to 0 (disabled)
as a module argument in a PAM file: 
`grep -Psi --
'^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\
r]+\h+)?dictcheck\h*=\h*0\b' /etc/pam.d/common-password`
**→ Nothing should be returned**
 | 1. Edit any file ending in .conf in the /etc/security/pwquality.conf.d/ directory and/or
the file /etc/security/pwquality.conf and comment out or remove any instance of
dictcheck = 0:
`sed -ri 's/^\s*dictcheck\s*=/# &/' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.conf` 

2. Edit any returned files and remove the dictcheck argument from the pam_pwquality.so
line(s) :
 `grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\b'
/usr/share/pam-configs/*` |  |
| 5.3.3.2.7 |  Ensure password quality checking is enforced
————————

`enforcing=0` (or unset):
Only **warn** the user about weak passwords, but allow the password anyway.
`enforcing=1` (or any non-zero value):**Reject** the password if it fails the checks. The user must choose a stronger password. | 1. Run the following command to verify that enforcing=0 has not been set in a pwquality
configuration file:
 `grep -PHsi -- '^\h*enforcing\h*=\h*0\b' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.con` 
**→ Nothing should be returned**
2. Run the following command to verify that the enforcing=0 argument has not been set
on the pam_pwquality module :
 `grep -PHsi --
'^\h*password\h+[^#\n\r]+\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b'
/etc/pam.d/common-password` 
**→ Nothing should be returned** | 1. Edit /etc/security/pwquality.conf and all files ending in .conf in the
/etc/security/pwquality.conf.d/ directory and remove or comment out any line
containing the enforcing = 0 argument:
**Example :** 
 `sed -ri 's/^\s*enforcing\s*=\s*0/# &/' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.conf` 

2. Edit any returned files and remove the enforcing=0 argument from the
pam_pwquality.so line(s) :
`grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b'
/usr/share/pam-configs/*` |  |
| 5.3.3.2.8 | Ensure password quality is enforced for the **root** user
————————

**Remarque :** 
Root is **not prompted** for their old password when changing it.So options like `difok` (difference from old password) don't apply to root.But with `enforce_for_root`, **everything else (minlen, complexity, etc.) is enforced**. | Run the following command to verify that the enforce_for_root option is enabled in a
pwquality configuration file:
`grep -Psi -- '^\h*enforce_for_root\b' /etc/security/pwquality.conf
/etc/security/pwquality.conf.d/*.conf`
**→ output :**  /etc/security/pwquality.conf.d/50-pwroot.conf:enforce_for_root
 | Edit or add the following line in a *.conf file in /etc/security/pwquality.conf.d or in
/etc/security/pwquality.conf:
**Example:** 
`#!/urs/bin/env bash
{
[ ! -d /etc/security/pwquality.conf.d/ ] && mkdir
/etc/security/pwquality.conf.d/
printf '\n%s\n' "enforce_for_root" > /etc/security/pwquality.conf.d/50-
pwroot.conf
}` |  |

---

---

### 5.3.3.3  Configure pam_pwhistory module

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.3.3.3.1 | Ensure password history remember is configured

 | `grep -Psi --
'^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\d+\b
' /etc/pam.d/common-password` 
→ **verify**:
• The pwhistory line in /etc/pam.d/common-password includes remember=<N>
• The value of <N> is 24 or more | 1. Search for the PAM config files using:
`awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*`

2. Edit the files that appear and **make sure they include: `remember=24`** 

3. After editing, apply the changes with: 
`pam-auth-update --enable pwhistory`
pwhistory <=> FILENAME |  |
| 5.3.3.3.2 | Ensure password history is enforced for the **root** user | Run the following command to verify that the enforce_for_root argument is exists on
the pwhistory line in /etc/pam.d/common-password : 
`grep -Psi --
'^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?enforce_for_ro
ot\b' /etc/pam.d/common-password` | 1. Search for the PAM config files using 
`awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if
(/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*` 

2. Edit any returned files and add the enforce_for_root argument to the pam_pwhistory
line in the Password section

3. After editing, apply the changes with: 
`pam-auth-update --enable pwhistory`
pwhistory <=> FILENAME |  |
| 5.3.3.3.3 | Ensure pam_pwhistory includes use_authtok
———————-
authtok : It **reuses the new password** already entered by the user (or by a previous PAM module) rather than prompting again. | `grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password`

→ If `use_authtok` is **missing**, proceed to the remediation. | 1. Check which profile defines `pam_pwhistory`

`awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*`

2. Edit that file, add authtok

3. Update PAM configuration : 
`sudo pam-auth-update --enable pwhistory`
 |  |

---

---

### 5.3.3.4 Configure pam_unix module

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.3.3.4.1 | Ensure pam_unix does **not include** `nullok`
———————-
The **`nullok`** argument allows users with **blank passwords** (empty password field) to log in. | Run the following command to verify that the nullok argument is not set on the
pam_unix.so module:

 `grep -PH -- '^\h*^\h*[^#\n\r]+\h+pam_unix\.so\b' /etc/pam.d/common-
{password,auth,account,session,session-noninteractive} | grep -Pv --
'\bnullok\b’` | 1. Run the following command:
`grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b'
/usr/share/pam-configs/*`
**Edit** any files returned and remove the nullok argument for the pam_unix lines
2. Run the following command to update the files in the /etc/pam.d/ directory:
`pam-auth-update --enable <EDITED_PROFILE_NAME>`
 |  |
| 5.3.3.4.2 | Ensure pam_unix does not include remember

 | Run the following command to verify that the remember argument is not set on the
pam_unix.so module:

`grep -PH -- '^\h*^\h*[^#\n\r]+\h+pam_unix\.so\b' /etc/pam.d/common-
{password,auth,account,session,session-noninteractive} | grep -Pv --
'\bremember=\d+\b’` | 1. Find where the `remember` argument is set inside PAM config snippets:
`grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?remember\b' /usr/share/pam-configs/*`

2. **Edit** the files returned by the above command to **remove** the `remember=<N>` argument from lines with `pam_unix.so`.

3. Run the following command to update the files in the /etc/pam.d/ directory:
`pam-auth-update --enable <EDITED_PROFILE_NAME>` |  |
| 5.3.3.4.3 | Ensure pam_unix includes a strong password hashing
algorithm
————————
A **cryptographic hash function** takes an input (your password) and converts it into a fixed-length string, called a **hash**.This is a **one-way** transformation — you cannot reverse the hash back to the original password. | Run the following command to verify that a strong password hashing algorithm is set on
the pam_unix.so module:
`grep -PH --
'^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)
\b' /etc/pam.d/common-password` 

**→ Verify that the line(s) include either sha512 - OR - yescrypt** | 1. 1. **Find PAM configuration files using `pam_unix.so` in the Password section**
`awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if
(/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/*` 

2.. **Edit** the files returned by the above command to **add** the `sha512` or `yescrypt`.

3. Run the following command to update the files in the /etc/pam.d/ directory:
`pam-auth-update --enable <EDITED_PROFILE_NAM` |  |
| 5.3.3.4.4 |  Ensure pam_unix includes `use_authtok` |  `grep -PH --
'^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' 
/etc/pam.d/common-password`

→ If `use_authtok` is **missing**, proceed to the remediation. | 1. **Find** the PAM config files that contain `pam_unix.so` by running:
`awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/*`

2. **Edit** any returned file(s). In the **Password** section, add `use_authtok` to the `pam_unix.so` line if it’s missing.

3. **Run** the following command to update the files in the /etc/pam.d/ directory:
`pam-auth-update --enable <EDITED_PROFILE_NAME>` |  |

---

---

# **5.4  User Accounts and Environment:**

## 5.4.1 Configure shadow password suite parameters :

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.4.1.1 | Ensure password **expiration** is configured | 1. Check global default in `/etc/login.defs`
 `grep -Pi -- '^\h*PASS_MAX_DAYS\h+\d+\b' /etc/login.defs`

**Example output:**
PASS_MAX_DAYS 365

2. **Check individual user settings in /etc/shadow**

`awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print "User: " $1 " PASS_MAX_DAYS: " $5}' /etc/shadow`
Expected: **No output** (i.e., all values must be between 1 and 365) | 1. Update `/etc/login.defs` default setting
Edit or add this line: `PASS_MAX_DAYS 365`

2. Run this command to update all **existing users** with a password set, where the current `PASS_MAX_DAYS` is **invalid** (less than 1 or greater than 365):
`awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1) system("chage --maxdays 365 " $1)}' /etc/shadow`
 |  |
| 5.4.1.2 | Ensure **minimum password age** is configured
———————-
This control makes sure users **can’t change their password too soon** after setting it. | 1.  Check the global setting in `/etc/login.defs`:

`grep -Pi -- '^\h*PASS_MIN_DAYS\h+\d+\b' /etc/login.def`

2. Check individual user settings in `/etc/shadow`:

`awk -F: '($2~/^\$.+\$/) {if($4 < 1)print "User: " $1 " PASS_MIN_DAYS: " $4}' /etc/shadow` | 1. 1. Set the global policy (for new users and defaults):
`sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs || echo 'PASS_MIN_DAYS 1' >> /etc/login.defs`

2. Fix all current users who have `PASS_MIN_DAYS` < 1:

`awk -F: '($2~/^\$.+\$/) {if($4 < 1)system ("chage --mindays 1 " $1)}' /etc/shadow` |  |
| 5.4.1.3 | Ensure password **expiration warning days** is configured

`PASS_WARN_AGE 7` | 1. Check global setting in **/etc/login.defs** and verify PASS_WARN_AGE is 7 or more

`grep -Pi -- '^\h*PASS_WARN_AGE\h+\d+\b' /etc/login.defs` 

2. Run the following command to verify all passwords have a PASS_WARN_AGE of 7 or more:

`awk -F: '($2~/^\$.+\$/) {if($6 < 7)print "User: " $1 " PASS_WARN_AGE: "
$6}' /etc/shadow`

**→ Nothing should be returned** | 1. 1. Update `/etc/login.defs` default setting
Edit or add this line: `PASS_WARN_AGE 7`

2. **Fix all existing users with a warning < 7 days**:
Run:
`awk -F: '($2~/^\$.+\$/) {if($6 < 7)system ("chage --warndays 7 " $1)}' /etc/shadow` |  |
| 5.4.1.4 | Ensure strong password hashing algorithm is configured
 `ENCRYPT_METHOD` | Run the following command to verify the hashing algorithm is sha512 or yescrypt in
/etc/login.defs:
`grep -Pi -- '^\h*ENCRYPT_METHOD\h+(SHA512|yescrypt)\b' /etc/login.defs` 
**Example output:**
ENCRYPT_METHOD SHA512
- OR -
ENCRYPT_METHOD YESCRYPT | Edit /etc/login.defs and set the E**NCRYPT_METHOD** to **SHA512** or **YESCRYPT**:

`ENCRYPT_METHOD <HASHING_ALGORITHM>`
**Example:**
`ENCRYPT_METHOD YESCRYPT` |  |
| 5.4.1.5 | Ensure **inactive password lock** is configured 
———————-
The **inactive password lock** refers to automatically disabling user accounts **after a certain period of inactivity** *following password expiration.* | 1. Run the following command and verify INACTIVE conforms to site policy (no more than
45 days):

`useradd -D | grep INACTIVE`

2. Run the following command and Review list of users and INACTIVE to
verify that all users **INACTIVE** conforms to site policy (no more than 45 days):
 `awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print "User: " $1 " INACTIVE:
" $7}' /etc/shadow`
**→ Nothing should be returned** | 1. Set default inactivity period to 45 days (or your policy limit):
`useradd -D -f 45` 

2. update all user accounts with incorrect inactivity period:

`awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0) system("chage --inactive 45 " $1)}' /etc/shadow`
 |  |
| 5.4.1.6 | Ensure all users last password change date is in the past | Run the following command and **verify nothing is returned**
`{
while IFS= read -r l_user; do
l_change=$(date -d "$(chage --list $l_user | grep '^Last password
change' | cut -d: -f2 | grep -v 'never$')" +%s)
if [[ "$l_change" -gt "$(date +%s)" ]]; then
echo "User: \"$l_user\" last password change was \"$(chage --list
$l_user | grep '^Last password change' | cut -d: -f2)\""
fi
done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)
}` | If you find any users like this, you can:
1.  **Lock the account** 
`passwd -l username`

**2. Force password expiration** 
`chage -d 0 username`

**3. Reset the password manually** 
`passwd username` |  |

## 5.4.2 Configure root and system accounts and environment

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.4.2.1 | Ensure root is the only UID 0 account  | Run the following command and verify that only "root" is returned:
`awk -F: '($3 == 0) { print $1 }' /etc/passwd` 
**→ root** | 1. Run the following command to change the root account UID to 0 :
`usermod -u 0 root`

2. Modify any users other than root with UID 0 and assign them a new UID |  |
| 5.4.2.2 |  Ensure root is the only GID 0 account | Run the following command to verify the root user's primary GID is 0, and no other
user's have GID 0 as their primary GID:
 `awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print
$1":"$4}' /etc/passwd`
**→ root:0** | 1. Run the following command to set the root user's GID to 0:
`usermod -g 0 root`

2. Run the following command to set the root group's GID to 0:
 `groupmod -g 0 root`

3. Remove any users other than the root user with GID 0 or assign them a new GID if appropriate |  |
| 5.4.2.3 | Ensure group root is the only GID 0 group | Run the following command to verify no group other than root is assigned GID 0:
`awk -F: '$3=="0"{print $1":"$3}' /etc/group`
**→ root:0** | 1. Run the following command to set the root group's GID to 0:
`groupmod -g 0 root` 

2. Remove any groups other than the root group with GID 0 or assign them a new GID if appropriate.
 |  |
| 5.4.2.4 | Ensure root password is set | Run the following command to verify the root user's password is set:
 `passwd -S root | awk '$2 ~ /^P/ {print "User: \"" $1 "\" Password is set"}'`
**→ User: "root" Password is set** | Run the following command to set a password for the root user:
`passwd root` |  |
| 5.4.2.5 |  Ensure root path integrity | Run the following script to verify root's path does not include:
• Locations that are not directories
• An empty directory (::)
• A trailing (:)
• Current working directory (.)
• Non root owned directories
• Directories that less restrictive than mode 0755

[*(21) see the script](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | Correct or justify any:
• Locations that are not directories
• Empty directories (::)
• Trailing (:)
• Current working directory (.)
• Non root owned directories
• Directories that less restrictive than mode 0755 |  |
| 5.4.2.6 | Ensure root user **umask** is configured

Where is umask set for root?

`/root/.bash_profile` – executed for **login shells**

`/root/.bashrc` – executed for **interactive, non-login shells**

If `umask` is defined in both files, `.bash_profile` takes precedence.

 | `grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc`

**Expected:** The command should return **nothing**, meaning umask is **not set to an insecure value**. | Edit /root/.bash_profile and /root/.bashrc and remove, comment out, or update any
line with umask to be 0027 or more restrictive.
**Example :**

`sed -i '/umask/s/^/# /' /root/.bash_profile
sed -i '/umask/s/^/# /' /root/.bashrc

echo 'umask 0027' >> /root/.bash_profile
echo 'umask 0027' >> /root/.bashrc`
**** |  |
| 5.4.2.7 | Ensure system accounts do not have a valid login shell | Run the following command to verify system accounts, except for root, halt, sync,
shutdown or nfsnobody, do not have a valid login shell:
`#!/usr/bin/env bash
{
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed
-rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
awk -v pat="$l_valid_shells" -F:
'($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$(awk
'/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) && $(NF) ~ pat)
{print "Service account: \"" $1 "\" has a valid shell: " $7}' /etc/passwd
}`
**→ Nothing should be returned** | Run the following command to set the shell for any service accounts returned by the
audit to nologin: 

`#!/usr/bin/env bash
# Get all login shells except "nologin"
l_valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\/,g;p}' | paste -s -d '|' -))$"

# Loop through accounts and update them
awk -v pat="$l_valid_shells" -F: '
($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ &&
($3 < '"$(awk "/^\s*UID_MIN/ {print \$2}" /etc/login.defs)"' || $3 == 65534) &&
$NF ~ pat) {
printf("Changing shell for user %s to nologin\n", $1);
system("usermod -s $(command -v nologin) " $1)
}' /etc/passwd`
 |  |
| 5.4.2.8 | Ensure accounts without a valid login shell are locked  | Run the following script to verify all non-root accounts without a valid login shell are
locked.
`#!/usr/bin/env bash
{
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed
-rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
while IFS= read -r l_user; do
passwd -S "$l_user" | awk '$2 !~ /^L/ {print "Account: \"" $1 "\" does
not have a valid login shell and is not locked"}'
done < <(awk -v pat="$l_valid_shells" -F: '($1 != "root" && $(NF) !~ pat)
{print $1}' /etc/passwd)
}`
**→ Nothing should be returned** | Run the following command to lock any non-root accounts without a valid login shell
returned by the audit:
`#!/usr/bin/env bash
{
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed
-rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
while IFS= read -r l_user; do
passwd -S "$l_user" | awk '$2 !~ /^L/ {system ("usermod -L " $1)}'
done < <(awk -v pat="$l_valid_shells" -F: '($1 != "root" && $(NF) !~ pat)
{print $1}' /etc/passwd)
}` |  |

## 5.4.3 Configure user default environment

| Rule ID | Description | Audit | Remediation: | Done? |
| --- | --- | --- | --- | --- |
| 5.4.3.1 | Ensure nologin is not listed in **/etc/shells** | `grep '/nologin\b' /etc/shells` 

→ If it returns **nothing**,  good ✅

→ If it shows a line with `/sbin/nologin` or similar → ❌ not secure | Edit `/etc/shells` and remove any lines that include nologin
 |  |
| 5.4.3.2 | Ensure default user shell timeout is configured

**WHY?** If a user leaves their terminal open and goes for coffee, someone else might hijack it. This config **auto-kills idle sessions**. | Run the following script to verify that TMOUT is configured to: include a timeout of no
more than 900 seconds, to be readonly, to be exported, and is not being changed to a longer timeout.

[*(22) see the script](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | # Set TMOUT in a dedicated file in /etc/profile.d
`cat << 'EOF' > /etc/profile.d/99-tmout.sh
TMOUT=900
readonly TMOUT
export TMOUT
EOF`

# Ensure proper permissions (readable by all, writable only by root)
`chmod 644 /etc/profile.d/99-tmout.sh
chown root:root /etc/profile.d/99-tmout.sh`
 |  |
| 5.4.3.3 | Ensure default user umask is configured | [*(23) check the audit script here](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) | [*(24) check for the remediation script](Re%CC%81fe%CC%81rences%20237b712c243580a8be1cee0170adfe82.md) |  |
