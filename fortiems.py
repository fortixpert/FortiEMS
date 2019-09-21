#!/usr/bin/python

###################################################################
#
#       fortiems.py aims at simplyfing the automation
#       of actions in FortiEMS solution.
#
###################################################################

import requests, json, argparse, sys

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="EMS ip address or DNS name",required=True)
parser.add_argument("-u", "--username", help="EMS admin user",required=True)
parser.add_argument("-p", "--password", help="EMS Password",required=True)	
parser.add_argument("-a", "--action", help="Actions available: getemsinfo, getuserinfo, outofdate, quarantine and unquarantine",required=True)
parser.add_argument("-e", "--endpoint", help="Endpoint ip address",required=False)
parser.add_argument("-o", "--option", help="Options: Antivirus, Sandbox, Firewall, Webfilter, Vulnerability, VulnerabilityCritHigh, AntiVirusUnprotected, SoftwareOOD, SignatureOOD, OOS, Quarantined",required=False)

args = parser.parse_args()

#Global parameters
url_ems = "https://%s/api/v1/" %(args.ip)

def gettoken (args):
	#Get Token for authorization
	payload = "name=" + args.username + "&password=" + args.password
	headers = {'Content-Type': "application/x-www-form-urlencoded"}

	emsapiconnection = requests.request("POST", url = url_ems + "auth/signin", data=payload, verify=False, headers=headers)

	checkemsconnection (emsapiconnection)

	csrftoken = emsapiconnection.cookies['csrftoken']
	sessionid = emsapiconnection.cookies['sessionid']

	return csrftoken, sessionid 


def getserialnumber (args):
	#Do get systems status
	headers = {'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid}
	emsapiconnection = requests.request("GET",url = url_ems + "system/serial_number", headers=headers, verify=False)

	checkemsconnection (emsapiconnection)

	json_data = json.loads(emsapiconnection.text)
	sn_ems = json_data['data']
	print ("")
	print ("EMS Serial number: " + sn_ems)
	print ("")


def outofdate (args):
	#Check endpoint out of date signatures    
	option_list = ['Antivirus', 'Sandbox', 'Firewall', 'Webfilter', 'Vulnerability', 'VulnerabilityCritHigh', 'AntiVirusUnprotected', 'SoftwareOOD', 'SignatureOOD', 'OOS', 'Quarantined']
	
	if args.option not in option_list:
		print ("")
		print ("Please select a valid option. Check --help to list available options.")
		print ("")
		
	else:
		params = {'event_type': args.option}
		headers = {'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid}
		emsapiconnection = requests.request("GET", url = url_ems + "endpoints/get/compact/event", headers=headers, params=params, verify=False)
		
		checkemsconnection (emsapiconnection)

		parseendpoints = json.loads(emsapiconnection.text)
		endpointlist = parseendpoints['data']['total']

		endpointcount = 0
		count = 0
		while count < endpointlist:
			print ("")
			print ("Information of Endpoint:")
			print ("   .Username: " + parseendpoints['data']['endpoints'][count]['username'])
			print ("   .Operating System: " + parseendpoints['data']['endpoints'][count]['os_version'])
			print ("   .FortiClient version: " + parseendpoints['data']['endpoints'][count]['fct_version_major_minor_patch'])
			print ("   ." + args.option + " events: ", parseendpoints['data']['endpoints'][count]['value'])
			print ("")
			count += 1
			endpointcount = count
		
		print ("")
		print "Total number of endpoint out of date of " + args.option + " is", endpointcount
		print ("")


def getuserinfo (args):
	#Quarantine endpoint    
	headers = {'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid}
	emsapiconnection = requests.request("GET",url = url_ems + "endpoints/get/", headers=headers, verify=False)

	checkemsconnection (emsapiconnection)
	
	parseendpoints = json.loads(emsapiconnection.text)
	endpointlist = parseendpoints['data']['total']

	count = 0

	while count < endpointlist:
		if parseendpoints['data']['endpoints'][count]['ip_addr'] == args.endpoint :
			
			if parseendpoints['data']['endpoints'][count]['is_ems_onnet'] == 1:
				message = "On-net "	
			else:
				message = "Off-net"
			
			print ("")			
			print ("Information of Endpoint " + args.endpoint + ":")
			print ("   .Username: " + parseendpoints['data']['endpoints'][count]['username'])
			print ("   .Domain: " + parseendpoints['data']['endpoints'][count]['user_domain'])
			print ("   .Operating System: " + parseendpoints['data']['endpoints'][count]['os_version'])
			print ("   .Mac address: " + parseendpoints['data']['endpoints'][count]['mac_addr'])
			print ("   .EMS Group path: " + parseendpoints['data']['endpoints'][count]['group_path'])
			print ("   .Location: " + message )
			print ("")			
			sys.exit()

		else:
			count += 1
	
	print ("")
	print ("This endpoint is not declared into FortiEMS")
	print ("")



def quarantineendpoint (args):
	#Quarantine endpoint
	headers = {'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid}
	emsapiconnection = requests.request("GET",url = url_ems + "endpoints/get/", headers=headers, verify=False)

	checkemsconnection (emsapiconnection)

	parseendpoints = json.loads(emsapiconnection.text)
	endpointlist = parseendpoints['data']['total']

	count = 0

	while count < endpointlist:
		if parseendpoints['data']['endpoints'][count]['ip_addr'] == args.endpoint :
			if parseendpoints['data']['endpoints'][count]['is_quarantined'] == 1:
				print ("")
				print ("The endpoint is already in quarantine.")
				print ("")
				break
			else:
					payload = {'addresses':[{'ip': args.endpoint }]}
					headers = {'Content-Type': "application/json", 'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid, 'X-CSRFToken': csrftoken}

					quarantine = requests.request("POST",url = url_ems + "clients/quarantine", headers=headers, verify=False, json=payload)
					if quarantine.status_code == 200:
						message = "The endpoint " + args.endpoint + " has been put in quarantine."
						print ("")
						print (message)
						print ("")
						break
					else:
						message = "Something was wrong."
						print ("")
						print (message)
						print ("")
					break
		else:
			count += 1


def unquarantineendpoint (args):
	#Unquarantine endpoint
	headers = {'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid}
	emsapiconnection = requests.request("GET",url = url_ems + "endpoints/get/", headers=headers, verify=False)

	checkemsconnection (emsapiconnection)


	parseendpoints = json.loads(emsapiconnection.text)
	endpointlist = parseendpoints['data']['total']

	count = 0

	while count < endpointlist:
		if parseendpoints['data']['endpoints'][count]['ip_addr'] == args.endpoint :
			if parseendpoints['data']['endpoints'][count]['is_quarantined'] == 0:
				print ("")
				print ("The endpoint is already out of quarantine.")
				print ("")
			else:
				payload = {'addresses':[{'ip': args.endpoint }]}
				headers = {'Content-Type': "application/json", 'Referer': url_ems, 'Cookie': "csrftoken=" + csrftoken + ";sessionid=" + sessionid, 'X-CSRFToken': csrftoken}
					
				quarantine = requests.request("POST",url = url_ems + "clients/unquarantine", headers=headers, verify=False, json=payload)

				if quarantine.status_code == 200:
					message = "The endpoint " + args.endpoint + " has been put out of quarantine."
				else:
					message = "Something was wrong."
				print ("")
				print (message)
				print ("")
			break
		else:
			count += 1


def checkemsconnection (emsapiconnection):
	#error!=200
	if emsapiconnection.status_code == 200:
		return
	else:
		print ("")
		print ("Something goes wrong. Please check user/pass and EMS https access.")
		print "HTTP status code: " ,emsapiconnection.status_code
		print ("")	
		print ("Note: If the password has special characters, please put the password in single quote. Example: 'passw$rd'")
		print ("")	
		sys.exit()


def noaction ():
	#defaultcheckemsconnection
	print ("")
	print ("No action selected. Please review help for more information.")
	print ("")


#Global token parameters
csrftoken, sessionid = gettoken (args)

if args.action == "getemsinfo":
	getserialnumber (args)
elif args.action == "quarantine":
	quarantineendpoint (args)
elif args.action == "unquarantine":
	unquarantineendpoint (args)
elif args.action == "getuserinfo":
	getuserinfo (args)
elif args.action == "outofdate":
	outofdate (args)
else:
	noaction ()
