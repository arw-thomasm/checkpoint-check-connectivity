#!/bin/bash
check_url () {
 result=" [ NOK ]"
 name="$2 "
 while [ ${#name} -lt 74 ]; do name="$name."; done
 echo -en "$name "
 if [ `curl_cli -Lisk $1 | head -1 | egrep -c "OK|Found|Moved"` -gt 0 ]; then result=" [ OK ]"; fi
 echo $result
}

echo
echo "sk83520 How to verify that Security Gateway and/or Security Management Server can access Check Point servers"
echo


check_url 'http://cws.checkpoint.com/APPI/SystemStatus/type/short' 'Social Media Widget Detection'
check_url 'http://cws.checkpoint.com/URLF/SystemStatus/type/short' 'URL Filtering Cloud Categorization'
check_url 'http://cws.checkpoint.com/AntiVirus/SystemStatus/type/short' 'Virus Detection'
check_url 'http://cws.checkpoint.com/Malware/SystemStatus/type/short' 'Bot Detection'
check_url 'https://updates.checkpoint.com/' 'IPS Updates'
check_url 'http://dl3.checkpoint.com' 'Download Service Updates '
check_url 'https://usercenter.checkpoint.com/usercenter/services/ProductCoverageService' 'Contract Entitlement '
check_url 'https://usercenter.checkpoint.com/usercenter/services/BladesManagerService' 'Software Blades Manager Service'
check_url 'http://resolver1.chkp.ctmail.com' 'Suspicious Mail Outbreaks'
check_url 'http://download.ctmail.com' 'Anti-Spam'
check_url 'http://te.checkpoint.com' 'Threat Emulation'
check_url 'http://teadv.checkpoint.com' 'Threat Emulation Advanced'
check_url 'http://kav8.zonealarm.com/version.txt' 'Deep inspection'
check_url 'http://kav8.checkpoint.com' 'Traditional Anti-Virus'
check_url 'http://avupdates.checkpoint.com/UrlList.txt' 'Traditional Anti-Virus, Legacy URL Filtering'
check_url 'http://sigcheck.checkpoint.com/Siglist2.txt' 'Download of signature updates'
check_url 'http://secureupdates.checkpoint.com' 'Manage Security Gateways'
check_url 'https://productcoverage.checkpoint.com/ProductCoverageService' 'Makes sure the machines contracts are up-to-date'
check_url 'https://sc1.checkpoint.com/sc/images/checkmark.gif' 'Download of icons and screenshots from Check Point media storage s ervers'
check_url 'https://sc1.checkpoint.com/za/images/facetime/large_png/60342479_lrg.png' 'Download of icons and screenshots from Check Point media storage servers'
check_url 'https://sc1.checkpoint.com/za/images/facetime/large_png/60096017_lrg.png' 'Download of icons and screenshots from Check Point media storage servers'
check_url 'https://push.checkpoint.com' 'Push Notifications '
check_url 'http://downloads.checkpoint.com' 'Download of Endpoint Compliance Updates'

