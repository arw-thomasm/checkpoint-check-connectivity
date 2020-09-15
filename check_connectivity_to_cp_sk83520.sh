#!/bin/bash

# ------------------------------------------------------------------
# [Author]    Thomas Marko
# [Company]   Arrow ECS Internet Security AG
#
#             Check Point Cloud Services Checker
#
#             sk83520 How to verify that Security Gateway and/or 
#             Security Management Server can access Check Point 
#             servers
#
# ------------------------------------------------------------------

VERSION=0.0.1
SUBJECT=checkpoint-check-connectivity
USAGE="Usage: $0"
DESC="This script checks the connectivity to several Check Point Cloud Services according to SK83520"

# --- Option processing --------------------------------------------
if [ $# -gt 0 ]
then
	printf "\n$DESC\n"
    printf "\n$USAGE\n\n"
    exit 1;
fi

# Gather information about this host

if [ "$(which fw)" == "" ]
then
	printf "\n$DESC"
	printf "\nThis script only runs in Check Point Gaia environments.\n"
	printf "\n$USAGE\n\n"
	exit 2
fi

CPVERSION=$(fw ver | awk '{print $7}') # Currently not used
CPISMODULE=$(cpprod_util FwIsFirewallModule) # Is this a firewall module?
CPISMGMT=$(cpprod_util FwIsFirewallMgmt) # Is this a management server?
CPISMABGW=0 # Currently not supported

# Get the terminal width
TWIDTH=$(tput cols) 

# --- Locks -------------------------------------------------------
LOCK_FILE=/tmp/${SUBJECT}.lock

if [ -f "$LOCK_FILE" ]; then
	echo "Script is already running"
	exit
fi

trap "rm -f $LOCK_FILE" EXIT
touch $LOCK_FILE

# -- Functions ----------------------------------------------------

check_url () {
	
	indentation="   "

	protocol=$1
	hostname=$2
	url=$3
	description="$indentation$4"

	result=" [ NOK ]"
	message="\e[1m\e[31m$result\e[0m"

	if [ "$protocol" == "https" ]
	then 
		httpscacerts="--cacert $CPDIR/conf/ca-bundle.crt" 
	else 
		httpscacerts="" 
	fi

	response=$(curl_cli $httpscacerts -Lisk "$protocol://$hostname$url")
	responsecode=$(echo $response | head -1 | awk '{ print $2}')

	if [ $? -eq 0 ]
	then
		if [  $responsecode -eq 200 ] || [ $responsecode -eq 301 ] || [ $responsecode -eq 302 ] || [ $responsecode -eq 403 ] 
		then 
			result=" [ OK-$responsecode ]"
			message="\e[1m\e[32m$result\e[0m"
		else
			result=" [ NOK-$responsecode ]"
			message="\e[1m\e[31m$result\e[0m"
		fi
	else
		result=" [ ERR ]"
		message="\e[1m\e[31m$result\e[0m"
	fi

	while [ ${#description} -lt $(( $TWIDTH - ${#result} - ${#indentation} )) ]; do description="$description."; done
	
	echo -en "$description "

	echo -e $message
}

function csw_checkpoint_com () {

	hostname="cws.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/APPI/SystemStatus/type/short" "Social Media Widget Detection (from R75)"
			check_url $protocol $hostname "/URLF/SystemStatus/type/short" "URL Filtering Cloud Categorization (from R75.20)"
			check_url $protocol $hostname "/AntiVirus/SystemStatus/type/short" "Virus Detection (from R75.40)"
			check_url $protocol $hostname "/Malware/SystemStatus/type/short" "Bot Detection (from R75.40)"
		done
	fi

}

function updates_checkpoint_com() {

	hostname="updates.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("http" "https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "IPS Updates, Updatable Object (from R80.20, on Security Gateway and Security Management)"
		done
	fi

}

function crl_globalsign_com() {

	hostname="crl.globalsign.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "CRL that updates service certificate uses"
		done
	fi

}

function dl3_checkpoint_com() {

	hostname="dl3.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Download Service Updates (from R70), Updatable Object (from R80.20, on Security Gateway and Security Management)"
		done
	fi

}

function usercenter_checkpoint_com() {

	hostname="usercenter.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/usercenter/services/ProductCoverageService" "Contract Entitlement for IPS (from R70), Traditional Anti-Virus, Legacy URL Filtering, etc."
			check_url $protocol $hostname "/usercenter/services/BladesManagerService" "Software Blades Manager Service"
		done
	fi

}

function resolverX_chkp_ctmail_com() {

	hostnames=("resolver1.chkp.ctmail.com" "resolver2.chkp.ctmail.com" "resolver3.chkp.ctmail.com" "resolver4.chkp.ctmail.com" "resolver5.chkp.ctmail.com")
	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			for hostname in "${hostnames[@]}"
			do
				printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
				check_url $protocol $hostname "/" "Suspicious Mail Outbreaks (from R75.40)"
			done
		done
	fi

}

function download_ctmail_com() {

	hostname="download.ctmail.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Anti-Spam"
		done
	fi

}

function te_checkpoint_com() {

	hostname="te.checkpoint.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http" "https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Threat Emulation (from R77)"
		done
	fi

}

function teadv_checkpoint_com() {

	hostname="teadv.checkpoint.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http" "https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Threat Emulation (from R77)"
		done
	fi

}

function threat_emulation_checkpoint_com() {

	hostname="threat-emulation.checkpoint.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http" "https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Threat Emulation (from R77)"
			check_url $protocol $hostname "/tecloud/Ping" "Threat Emulation (from R77)"
		done
	fi

}

function ptcX_checkpoint_com() {

	hostnames=("ptcs.checkpoint.com" "ptcd.checkpoint.com")

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("https")

		for protocol in "${protocols[@]}"
		do
			for hostname in "${hostnames[@]}"
			do
				printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
				check_url $protocol $hostname "/" "PTC Updates"
			done
		done
	fi

}

function kav8_zonealarm_com() {

	hostname="kav8.zonealarm.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/version.txt" "Archive scanning in R75.40 and higher. Deep inspection in R77.10 and higher."
		done
	fi

}

function kav8_checkpoint_com() {

	hostname="kav8.checkpoint.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http" "https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Traditional Anti-Virus, Endpoint Security Management pulling Anti-Malware updates"
		done
	fi

}

function avupdates_checkpoint_com() {

	hostname="avupdates.checkpoint.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http" "https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/UrlList.txt" "Traditional Anti-Virus, Legacy URL Filtering"
		done
	fi

}

function sigcheck_checkpoint_com() {

	hostname="sigcheck.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/Siglist2.txt" "Download of signature updates for Traditional Anti-Virus, Legacy URL Filtering, Edge devices, etc."
		done
	fi

}

function secureupdates_checkpoint_com() {

	hostname="secureupdates.checkpoint.com"

	if [ $CPISMODULE -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Manage Security Gateways"
		done
	fi

}

function productcoverage_checkpoint_com() {

	hostname="productcoverage.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/ProductCoverageService" "Makes sure the machine's contracts are up-to-date (since R75.47)"
		done
	fi

}

function scX_checkpoint_com() {

	hostnames=("sc1.checkpoint.com" "sc2.checkpoint.com" "sc3.checkpoint.com" "sc4.checkpoint.com" "sc5.checkpoint.com")

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("https")

		for protocol in "${protocols[@]}"
		do
			for hostname in "${hostnames[@]}"
			do
				printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
				check_url $protocol $hostname "/sc/images/checkmark.gif" "Download of icons and screenshots from Check Point media storage servers (e.g., Check Point AppWiki)"
				check_url $protocol $hostname "/za/images/facetime/large_png/60342479_lrg.png" "Download of icons and screenshots from Check Point media storage servers (e.g., Check Point AppWiki)"
				check_url $protocol $hostname "/za/images/facetime/large_png/60096017_lrg.png" "Download of icons and screenshots from Check Point media storage servers (e.g., Check Point AppWiki)"
			done
		done
	fi

}

function push_checkpoint_com() {

	hostname="push.checkpoint.com"

	if [ $CPISMABGW -eq 1 ]
	then
		protocols=("https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/push/ping" "Push Notifications (since R77.10) for incoming e-mails and meeting requests on hand held devices, while the Capsule Workspace Mail app is in the background"
		done
	fi

}

function downloads_checkpoint_com() {

	hostname="downloads.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMABGW -eq 1 ]
	then
		protocols=("http")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Download of Endpoint Compliance Updates (Endpoint Security On Demand (ESOD) database)"
		done
	fi

}

function productservices_checkpoint_com() {

	hostname="productservices.checkpoint.com"

	if [ $CPISMGMT -eq 1 ] || [ $CPISMODULE -eq 1 ]
	then
		protocols=("https")

		for protocol in "${protocols[@]}"
		do
			printf "\n\e[1mChecking \e[4m$hostname\e[24m with protocol \e[4m$protocol\e[0m\n"
			check_url $protocol $hostname "/" "Next Generation Licensing uses this service. (Entitlement/Licensing Updates)"
		done
	fi

}

# -- Body ---------------------------------------------------------

source /etc/profile.d/CP.sh

csw_checkpoint_com
updates_checkpoint_com
crl_globalsign_com
dl3_checkpoint_com
usercenter_checkpoint_com
resolverX_chkp_ctmail_com
download_ctmail_com
te_checkpoint_com
teadv_checkpoint_com
threat_emulation_checkpoint_com
ptcX_checkpoint_com
kav8_zonealarm_com
kav8_checkpoint_com
avupdates_checkpoint_com
sigcheck_checkpoint_com
secureupdates_checkpoint_com
productcoverage_checkpoint_com
scX_checkpoint_com
push_checkpoint_com
downloads_checkpoint_com
productservices_checkpoint_com

# -----------------------------------------------------------------


