# practice

## Description
Practical workshop for methodology and results of the research paper.
- Install CAPEV2 on the host within Docker image of Ubuntu 24.04 LTS.
- CAPEV2 mentions that the guest should have Windows 10 21H2, but publically available minimal version of Windows 10 nowadays is only 22H2 from https://www.microsoft.com/en-us/software-download/windows10ISO. Other versions and their description with system requirements are mentioned in https://en.wikipedia.org/wiki/Windows_10_version_history and https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions.

uv sync
uv venv
source .venv/bin/activate
`ansible-config generate default`
`/guest` - ansible configuration for the guest
configure static IP to host - https://www.virtualbox.org/manual/ch06.html
run script `configure-ssh.ps1` as administrator within the guest
ansible win10_guest -i ./inventory.ini -m win_ping
ansible-playbook -i ./inventory.ini ./playbook.yml


## TODO
1. Reconfigure ansible lint
1. Try to create test cases by changing ansible_os_family: "Linux" (and other cases when url is bad, no fallback mechanism, etc.) for example (https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable)
1. Structure setup according to https://docs.ansible.com/projects/ansible/latest/tips_tricks/sample_setup.html and proper ansible.cfg
1. Extend part of checking if python is installed:
    - Can be multiple Python versions installed on the target?
    - We can also parse PATH from gathered facts in ansible_facts (ansible_facts['env']['Path'])
    - Check product_id via ansible.windows.win_package
    - https://stackoverflow.com/questions/647515/how-can-i-find-where-python-is-installed-on-windows
    - other approach to check if version is correct "python_version.stdout.split(' ')[1] is version(required_version, '==')"
    - check for unexpected issues during installation then fail
    - check if python is really installed after installation again
1. Variable is_internet_available: bool, it is true than try to install from the target machine itself but in other case install everything from the host by trasferring files
    - "4.1.4. Installing Without Downloading" for python installer
1. Variable for printing some debug information or -v is already enough?
1. Passwordless authentication with SSH keys (https://gist.github.com/letajmal/0ac50ead52a4e80d96b52ef22c391666#3-setting-up-passwordless-authentication)
1. Optionally use Chocolatey to download software for the guest within playbook.yml
1. Description of machines, networks, and all versions in SBOM-like files.
1. Multiple issues with environment variables (especially %PATH% variable - when just using utiliity in CLI like python):
    - They are not updating during single ansible connection session to SSH or WinRM
    - It is required to even restart e.g. sshd on the instance (or reboot whole instance) to update environment variables after changes it applied by installation of some software
    - Therefore, it is easier to operate with own proper environment variables instead of on the machine side
    - Due to issues with PATH refereshing in OpenSSH, we need utility scripts from chocolatey: https://forum.ansible.com/t/trouble-with-win-chocolatey-and-openssh/34350/, https://github.com/chocolatey/chocolatey-ansible/issues/22
    - https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_environment.html
1. Cleaning temporary directory after job is done?
1. Setup static IP if possible for VM within VirtualBox network
1. Disabled UAC (User Account Control) via configuring active directory group policy or powershell or within ansible
1. Task to update openssh https://github.com/PowerShell/openssh-portable
1. Disable anti-virus
1. Install other prerequisites and additional software such as browsers, PDF readers, office suites, etc
1. Disabled the "Auto Update" or "Check For Updates" feature of any additional software that you install. And disable auto updates from Windows.
1. return values, variable, conditionals, and other special features
1. Disable path limit in windows https://stackoverflow.com/questions/51624449/python-setup-disabling-path-length-limit-pros-and-cons
1. Decompose to multiple ansible roles and playbooks
1. Maybe try different OS (windows versions like LTSC, and linux distributions, android, and so on)
1. Configure permissions for executables, files, and directories
1. .env file for inventory
