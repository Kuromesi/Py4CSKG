import sys, os
def generate(rootPath):
    '''
    Generate CVE impact type train data, refer to https://github.com/CSIRT-MU/VulnerabilityCategorization.
    '''

    code_exec = [
        "execute arbitrary code as root",
        "execute arbitrary code with root privileges",
        "execute arbitrary code as the root user",
        "execute arbitrary code as a root user",
        "execute arbitrary code as LocalSystem",
        "execute arbitrary code as SYSTEM",
        "execute arbitrary code as Local System"
        "execute arbitrary code with SYSTEM privileges",
        "execute arbitrary code with LocalSystem privileges",
        "execute dangerous commands as root",
        "execute shell commands as the root user",
        "execute arbitrary commands as root",
        "execute arbitrary commands with root privileges",
        "execute arbitrary commands with root-level privileges",
        "execute commands as root",
        "execute root commands",
        "execute arbitrary os commands as root",
        "execute arbitrary shell commands as root",
        "execute arbitrary commands as SYSTEM",
        "execute arbitrary commands with SYSTEM privileges",
        "run commands as root",
        "run arbitrary commands as root",
        "run arbitrary commands as the root user",
        "execute code with root privileges",
        "run commands as root",
        "load malicious firmware",
        "succeed in uploading malicious Firmware",
        "executed under the SYSTEM account",
        "include and execute arbitrary local php files",
        "execute arbitrary code",
        "command injection",
        "execute files",
        "run arbitrary code",
        "execute a malicious file",
        "execution of arbitrary code",
        "remote execution of arbitrary php code",
        "execute code",
        "code injection vulnerability",
        "execute any code",
        "malicious file could be then executed on the affected system",
        "inject arbitrary commands",
        "execute arbitrary files",
        "inject arbitrary sql code",
        "run the setuid executable",
        "vbscript injection",
        "execute administrative operations",
        "performs arbitrary actions",
        "submit arbitrary requests to an affected device",
        "perform arbitrary actions on an affected device",
        "executes an arbitrary program",
        "attacker can upload a malicious payload",
        "execute malicious code",
        "modify sql commands to the portal server",
        "execute arbitrary os commands",
        "execute arbitrary code with administrator privileges",
        "execute administrator commands",
        "executed with administrator privileges",
        "remote procedure calls on the affected system",
        "run a specially crafted application on a targeted system",
        "execute arbitrary code in a privileged context",
        "execute arbitrary code with super-user privileges",
        "run processes in an elevated context",
    ]
    
    privilege_escalation = [
        "gain root privilege",
        "obtain root privilege",
        "leading to root privilege",
        "gains root privilege",
        "gain SYSTEM privilege",
        "obtain SYSTEM privilege",
        "gain LocalSystem privilege",
        "obtain LocalSystem privilege",
        "gain full privilege",
        "gain root access",
        "gain root rights",
        "gain root privileges",
        "gain system level access to a remote shell session",
        "gain administrator or system privileges",
        "leading to root privileges",
        "obtain the root password",
        "take complete control of the device",
        "take full control of the target system",
        "account could be granted root- or system-level privileges",
        "find the root credentials",
        "backdoor root account",
        "elevate the privileges to root",
        "leading to remote root",
        "take control of the affected device",
        "gain complete control",
        "gain full access to the affected system",
        "obtain full access",
        "gain complete control of the system",
        "SYSTEM",
        "elevate privileges to the root user",
        "obtain full control",
        "gain super-user privileges",
        "gain elevated privileges on the system",
        "with the knowledge of the default password may login to the system",
        "log in as an admin user of the affected device",
        "log in as an admin or oper user of the affected device",
        "log in to the affected device using default credentials",
        "log in to an affected system as the admin user",
        "log in to the device with the privileges of a limited user",
        "devices have a hardcoded-key vulnerability",
        "privilege escalation",
        "escalation of privilege"
    ]
    
    system_confidentiality = [
        "devices allow remote attackers to read arbitrary files",
        "compromise the systems confidentiality",
        "read any file on the camera's linux filesystem",
        "gain read-write access to system settings",
        "all system settings can be read",
        "leak information about any clients connected to it",
        "read sensitive files on the system",
        "access arbitrary files on an affected device",
        "access system files",
        "gain unauthorized read access to files on the host",
        "obtain sensitive system information",
        "obtain sensitive information from kernel memory",
        "obtain privileged file system access",
        "routers allow directory traversal sequences",
        "packets can contain fragments of system memory",
        "obtain kernel memory",
        "read kernel memory",
        "read system memory",
        "reading system memory",
        "read device memory",
        "read host memory",
        "access kernel memory",
        "access sensitive kernel memory",
        "access shared memory",
        "host arbitrary files",
        "enumerate user accounts",
        "compromise an affected system",
    ]
    
    system_integrity = [
        "compromise the systems confidentiality or integrity",
        "gain read-write access to system settings",
        "all system settings can be read and changed",
        "create arbitrary directories on the affected system",
        "on ismartalarm cube devices, there is incorrect access control",
        "bypass url filters that have been configured for an affected device",
        "bypass configured filters on the device",
        "modification of system files",
        "obtain privileged file system access",
        "change configuration settings",
        "compromise the affected system",
        "overwrite arbitrary kernel memory",
        "modify kernel memory",
        "overwrite kernel memory",
        "modifying kernel memory",
        "overwriting kernel memory",
        "corrupt kernel memory",
        "corrupt user memory",
        "upload firmware changes",
        "configuration parameter changes",
        "obtain sensitive information from kernel memory",
        "change the device's settings",
        "configuration changes",
        "modification of system states",
        "host arbitrary files"
    ]
    
    system_availability = [
        "an extended denial of service condition for the device",
        "exhaust the memory resources of the machine",
        "denial of service (dos) condition on an affected device",
        "crash systemui",
        "denial of service (dos) condition on the affected appliance",
        "cause the device to hang or unexpectedly reload",
        "denial of service (use-after-free) via a crafted application",
        "cause an affected device to reload",
        "cause an affected system to stop"
    ]
    
    data_class = [code_exec, privilege_escalation, system_availability, system_confidentiality, system_integrity]
    class_name = ["code_exec", "privilege_escalation", "system_availability", "system_confidentiality", "system_integrity"]
    path = os.path.join(rootPath, 'classification.labels')
    with open(path, 'w') as f:
        for name in class_name:
            f.writelines("%s\n"%name)
    path = os.path.join(rootPath, 'impact.train')
    with open(path, 'w', encoding='utf-8') as f:
        for i in range(len(data_class)):
            label = i
            for phrase in data_class[i]:
                f.writelines("%d , %s\n"%(label, phrase))
                
if __name__ == '__main__':
    path = './myData/learning/CVEImpact'
    generate(path)