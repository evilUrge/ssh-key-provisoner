# SSH Key provisioner  
---  
Simple python tool for provisioning ssh keys.
##### Now with DigitalOcean droplets and Vultr VC2 support!

## How to install and start?  
---  
    pip install -r requirements.txt
    python run.py --help
  
### Arguments  
---  
1. ```-i``` _OR_ ```--identity_file``` - Location of the machine identity file(private key).  
2. ```-k``` _OR_ ```--keys_file``` - Set the location for the key json file(default in the same folder).  
3. ```-H``` _OR_ ```--hosts_file``` - Set the location for the hosts json file(default in the same folder).
4. ```-d``` _OR_ ```--digitalocean``` - Add DigitalOcean token for provision ssh-keys to all DigitalOcean account droplets.
4. ```-V``` _OR_ ```--vultr``` - Add Vultr token for provision ssh-keys to all Vultr account vc2 instances.


#### COMING SOON
---
 - Providing password instead of the user private key.
 - Convert to CLI tool with adding servers as bash aliases

---

> _disclaimer: I know that you can use Ansible to provision ssh keys; this is just a fast simpler way_

