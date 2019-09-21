
## Getting Started

This project contains the code for automatic actions for the FortiEMS solution. The actions available are:

- getemsinfo: Gets the FortiEMS serial number information.
- getuserinfo: Gets relevant user info stored in FortiEMS.
- quarantine: Puts in quarantine specific ip.
- unquarantine: Puts out of quarantine specific ip.
- outofdate: List endpoints without last signature.


### Prerequisites

- The scripts have been developed using FortiEMS v6.2.1. Older versions are not supported.


## Running the tests

Instruction for use:

. Mandatory arguments:
```
      -i FortiEMS ip address or DNS name
      -u FortiEMS admin user
      -p FortiEMS password
      -a actions available: getemsinfo | getuserinfo | quarantine | unquarantine | outofdate

```
. Optional arguments:
```
      -e IP address of endpoint. Needed for actions regarding endpoint.
      -o Options for outofdate search. Options avaiable: Antivirus | Sandbox | Firewall | Webfilter | Vulnerability | VulnerabilityCritHigh | AntiVirusUnprotected | SoftwareOOD | SignatureOOD | OOS | Quarantined

```

## Examples

```
python fortiems.py -i 1.1.1.1 -u admin -p admin -a getemsinfo
python fortiems.py -i 1.1.1.1 -u admin -p admin -e 1.1.1.1 -a getuserinfo
python fortiems.py -i 1.1.1.1 -u admin -p admin -e 1.1.1.1 -a quarantine
python fortiems.py -i 1.1.1.1 -u admin -p admin -e 1.1.1.1 -a unquarantine
python fortiems.py -i 1.1.1.1 -u admin -p admin -e 1.1.1.1 -a outofdate -o Antivirus
```

## Help menu

```
python fortiems.py -h
usage: fortiems.py [-h] -i IP -u USERNAME -p PASSWORD -a ACTION [-e ENDPOINT] [-o OPTION]

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        EMS ip address or DNS name
  -u USERNAME, --username USERNAME
                        EMS admin user
  -p PASSWORD, --password PASSWORD
                        EMS Password
  -a ACTION, --action ACTION
                        Actions available: getemsinfo, getuserinfo, quarantine, unquarantine or outofdate
  -e ENDPOINT, --endpoint ENDPOINT
                        Endpoint ip address
  -o OPTION, --option OPTION
                        Options: Antivirus, Sandbox, Firewall, Webfilter,
                        Vulnerability, VulnerabilityCritHigh,
                        AntiVirusUnprotected, SoftwareOOD, SignatureOOD, OOS,
                        Quarantined
 ```         
  
## Authors

* **FortiXpert SE team**
