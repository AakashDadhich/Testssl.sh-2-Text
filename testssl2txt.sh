#!/bin/sh

# Welcome to the testssl.sh to txt/csv parser, here to make your life easier!
# This script comes in handy when you have many testssl.sh results to parse through.
# It can output findings a spreadsheet ready .csv (not totally finished), or a human-readable .txt.

# Version Number: v0.1
# Author: Aakash Dadhich

####################################################
# !!! PLEASE NOTE: THIS IS A WORK IN PROGRESS. !!! #
####################################################

# To start, ensure you run testssl.sh with the '--log' flag, and save these log files into a directory by themselves.
# You may then run this script; it takes no arguments.

# chmod +x tssl2txt.sh
# ./tssl2txt.sh

# START OF PROGRAM

# $preference denotes whether the output file will be a .txt or .csv
preference=2

until [ "$preference" = 0 ] || [ "$preference" = 1 ]
do
        echo "Choose a format for your results to be parsed into:"
        echo "0. A .csv whereby issue, host, port and additional info are in separate columns."
        echo "1. A .txt containing issue heading followed by host:port."
        printf "\n"
        echo "Please enter 0 or 1:"
        read preference
        printf "\n"
done
        echo "Enter name of file (file extension will be automatically applied):"
        read filename

case "$preference" in
0)
        echo "You chose 0. a .csv whereby issue, host, port and additional info are in separate columns."
        ext=".csv"
        echo "Issue,Host,Port" > "${filename}${ext}"
        printf "\n" ;;
1)
        echo "You chose 1. a .txt containing issue title followed by a list of host:port."
        ext=".txt"
        touch "${filename}${ext}"
        printf "\n" ;;
esac

##################
# GENERAL ISSUES #
##################

# SSLv2
if [ "$preference" = 1 ]
then
        echo "Hosts supporting SSLv2:"| tee -a "${filename}${ext}"
        grep -ir "SSLv2" ./*.log | grep -i "offered (NOT ok)" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "SSLv2" ./*.log | grep -i "offered (NOT ok)" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSLv2 Protocol Detection,/g' | tee -a "${filename}${ext}"
fi

# SSLv3
if [ "$preference" = 1 ]
then
        echo "Hosts supporting SSLv3:" | tee -a "${filename}${ext}"
        grep -ir "SSLv3" ./*.log | grep -i "offered (NOT ok)" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "SSLv3" ./*.log | grep -i "offered (NOT ok)" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSLv3 Protocol Detection,/g' | tee -a "${filename}${ext}"
fi

# TLSv1.0
if [ "$preference" = 1 ]
then
        echo "Hosts supporting TLSv1.0:" | tee -a "${filename}${ext}"
        grep -ir "TLS 1" ./*.log | grep -i "deprecated" | grep -v "1.1" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "TLS 1" ./*.log | grep -i "deprecated" | grep -v "1.1" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/TLSv1.0 Protocol Detection,/g' | tee -a "${filename}${ext}"
fi

# TLSv1.1
if [ "$preference" = 1 ]
then
        echo "Hosts supporting TLSv1.1:" | tee -a "${filename}${ext}"
        grep -ir "TLS 1.1" ./*.log | grep -i "deprecated" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "TLS 1.1" ./*.log | grep -i "deprecated" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/TLSv1.1 Protocol Detection,/g' | tee -a "${filename}${ext}"
fi

# Server Cipher Order
if [ "$preference" = 1 ]
then
        echo "Hosts without a server cipher order:" | tee -a "${filename}${ext}"
        grep -ir "server cipher" ./*.log | grep -v "yes" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "server cipher" ./*.log | grep -v "yes" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/No server cipher order,/g' | tee -a "${filename}${ext}"
fi

##########################
# SSL CERTIFICATE ISSUES #
##########################

# Signing Algorithm
if [ "$preference" = 1 ]
then
        echo "Hosts with weak SSL certificate signing algorithm:" | tee -a "${filename}${ext}"
        grep -ir "Signature Algorithm" ./*.log | grep -i "SHA1" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Signature Algorithm" ./*.log | grep -i "SHA1" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL cert - weak signing algorithm,/g' | tee -a "${filename}${ext}"
fi

# Server Key Usage
if [ "$preference" = 1 ]
then
        echo "Hosts using the server key incorrectly:" | tee -a "${filename}${ext}"
        grep -ir "Certificate incorrectly used" ./*.log | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Certificate incorrectly used" ./*.log | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL cert - incorrect server key usage,/g' | tee -a "${filename}${ext}"
fi

# subjectAltName
if [ "$preference" = 1 ]
then
        echo "Hosts missing subjectAltName (SAN):" | tee -a "${filename}${ext}"
        grep -ir "subjectAltName" ./*.log | grep -i "missing" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "subjectAltName" ./*.log | grep -i "missing" | cut -f1 -d - | cut -f 2 -d /  | sed 's/_p/,/g' | sed 's/^/SSL cert - missing subjectAltName,/g' | tee -a "${filename}${ext}"
fi

# Chain of Trust
if [ "$preference" = 1 ]
then
        echo "Hosts with incomplete chain of trust:" | tee -a "${filename}${ext}"
        grep -ir "Chain of trust" ./*.log | grep -i "NOT ok" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Chain of trust" ./*.log | grep -i "NOT ok" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL cert - incomplete chain of trust,/g' | tee -a "${filename}${ext}"
fi

# Certificate Validity - Expired
if [ "$preference" = 1 ]
then
        echo "Hosts with expired SSL certificates:" | tee -a "${filename}${ext}"
        grep -ir "Certificate Validity" ./*.log | grep -i "expired" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' > temp1.file
        grep -ir "Certificate Validity" ./*.log | grep -i "expired" | sed 's/.*-->//' | cut -f 2 -d ' ' > temp2.file
        paste -d, temp1.file temp2.file > temp3.file
        cat temp3.file | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Certificate Validity" ./*.log | grep -i "expired" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL certificate - expired,/g' > temp1.file
        grep -ir "Certificate Validity" ./*.log | grep -i "expired" | sed 's/.*-->//' | cut -f 2 -d ' ' > temp2.file
        paste -d, temp1.file temp2.file > temp3.file
        cat temp3.file | tee -a "${filename}${ext}"
fi

# Certificate Validity - Expires Soon
if [ "$preference" = 1 ]
then
        echo "Hosts with SSL certificates expiring soon:" | tee -a "${filename}${ext}"
        grep -ir "Certificate Validity" ./*.log | grep -i "expires" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g'  > temp1.file
        grep -ir "Certificate Validity" ./*.log | grep -i "expires" | sed 's/.*-->//' | cut -f 2 -d ' ' > temp2.file
        paste -d, temp1.file temp2.file > temp3.file
        cat temp3.file | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Certificate Validity" ./*.log | grep -i "expires" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL certificate - expires soon,/g' > temp1.file
        grep -ir "Certificate Validity" ./*.log | grep -i "expires" | sed 's/.*-->//' | cut -f 2 -d ' ' > temp2.file
        paste -d, temp1.file temp2.file > temp3.file
        cat temp3.file | tee -a "${filename}${ext}"
fi

# Remove the temporary files created from adding the expiry dates
rm temp1.file temp2.file temp3.file

# OCSP URI
if [ "$preference" = 1 ]
then
        echo "Hosts who did not provide OCSP URI:" | tee -a "${filename}${ext}"
        grep -ir "OCSP URI provided" ./*.log | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "OCSP URI provided" ./*.log | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL cert - OCSP URI not provided,/g' | tee -a "${filename}${ext}"
fi

# OCSP stapling
if [ "$preference" = 1 ]
then
        echo "Hosts who did not offer OCSP stapling:" | tee -a "${filename}${ext}"
        grep -ir "OCSP stapling" ./*.log | grep -i "not offered" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "OCSP stapling" ./*.log | grep -i "not offered" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL cert - OCSP stapling not offered,/g' | tee -a "${filename}${ext}"
fi

# DNS CAA RR
if [ "$preference" = 1 ]
then
        echo "Hosts who did not offer DNS CAA RR:" | tee -a "${filename}${ext}"
        grep -ir "DNS CAA RR" ./*.log | grep -i "not offered" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "DNS CAA RR" ./*.log | grep -i "not offered" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/SSL cert - DNS CAA RR not offered,/g' | tee -a "${filename}${ext}"
fi

################
# HTTP HEADERS #
################

# HTTP Strict Transport Security (HSTS)
if [ "$preference" = 1 ]
then
        echo "Hosts not enforcing HSTS policy:" | tee -a "${filename}${ext}"
        grep -ir "Strict Transport Security" ./*.log | grep -i "not offered" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Strict Transport Security" ./*.log | grep -i "not offered" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/HSTS policy not enforced,/g' | tee -a "${filename}${ext}"
fi

###
# To be completed
# Output WIP message to user
###

if [ "$preference" = 1 ]
then
        echo "This script is still a WIP." | tee -a "${filename}${ext}"
        echo "Please check banners and cookies separately." | tee -a "${filename}${ext}"
        echo "Check banners: grep -ir \"banner\" ./*.log" | tee -a "${filename}${ext}"
        echo "Check cookies: grep -ir \"Cookie\" ./*.log" | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
fi

# HTTP Security Headers
if [ "$preference" = 1 ]
then
        echo "Hosts missing HTTP security headers:" | tee -a "${filename}${ext}"
        grep -ir "Security Headers" ./*.log | grep -v "X\|C" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Security Headers" ./*.log | grep -v "X\|C" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Missing HTTP Security Headers,/g' | tee -a "${filename}${ext}"
fi

###################
# VULNERABILITIES #
###################

# HEARTBLEED
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to HEARTBLEED:" | tee -a "${filename}${ext}"
        grep -ir "Heartbleed" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Heartbleed" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/X,/g' | tee -a "${filename}${ext}"
fi

# CCS
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to CCS:" | tee -a "${filename}${ext}"
        grep -ir "CCS" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "CCS" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to CCS,/g' | tee -a "${filename}${ext}"
fi

# TICKETBLEED
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to TICKETBLEED:" | tee -a "${filename}${ext}"
        grep -ir "Ticketbleed" ./*.log | grep -v "not vulnerable\|applicable only for HTTPS"  | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Ticketbleed" ./*.log | grep -v "not vulnerable\|applicable only for HTTPS"  | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to TICKETBLEED,/g' | tee -a "${filename}${ext}"
fi

# ROBOT
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to ROBOT:" | tee -a "${filename}${ext}"
        grep -ir "ROBOT" ./*.log | grep -v "not vulnerable\|RSA key transport" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "ROBOT" ./*.log | grep -v "not vulnerable\|RSA key transport" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to ROBOT,/g' | tee -a "${filename}${ext}"
fi

# Secure Renegotiation
if [ "$preference" = 1 ]
then
        echo "Hosts not supporting Secure Renegotiation:" | tee -a "${filename}${ext}"
        grep -ir "Secure Reneg" ./*.log | grep -v "supported (OK)" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Secure Reneg" ./*.log | grep -v "supported (OK)" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Secure Renegotiation Unsupported,/g' | tee -a "${filename}${ext}"
fi

# Secure Client-Initiated Renegotiation
if [ "$preference" = 1 ]
then
        echo "Hosts not supported Secure Client-Initiated Renegotiation:" | tee -a "${filename}${ext}"
        grep -ir "Secure Client" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "Secure Client" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Secure Client-Initiated Renegotiation Unsupported,/g' | tee -a "${filename}${ext}"
fi

# CRIME
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to CRIME:" | tee -a "${filename}${ext}"
        grep -ir "CRIME" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "CRIME" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to CRIME,/g' | tee -a "${filename}${ext}"
fi

# POODLE
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to POODLE:" | tee -a "${filename}${ext}"
        grep -ir "POODLE" ./*.log | grep -v "not vulnerable\|POODLE SSL" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "POODLE" ./*.log | grep -v "not vulnerable\|POODLE SSL" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to POODLE,/g' | tee -a "${filename}${ext}"
fi

# TLS_FALLBACK_SCSV
if [ "$preference" = 1 ]
then
        echo "Hosts without TLS_FALLBACK_SCSV:" | tee -a "${filename}${ext}"
        grep -ir "RFC 7507" ./*.log | grep -i "Downgrade attack prevention NOT supported" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "RFC 7507" ./*.log | grep -i "Downgrade attack prevention NOT supported" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/TLS_FALLBACK_SCSV not enabled,/g' | tee -a "${filename}${ext}"
fi

# SWEET32
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to SWEET32:" | tee -a "${filename}${ext}"
        grep -ir "SWEET32" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "SWEET32" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to SWEET32,/g' | tee -a "${filename}${ext}"
fi

# FREAK
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to FREAK:" | tee -a "${filename}${ext}"
        grep -ir "FREAK" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "FREAK" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to FREAK,/g' | tee -a "${filename}${ext}"
fi

# DROWN
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to DROWN:" | tee -a "${filename}${ext}"
        grep -ir "DROWN" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "DROWN" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to DROWN,/g' | tee -a "${filename}${ext}"
fi

# LOGJAM
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to LOGJAM:" | tee -a "${filename}${ext}"
        grep -ir "LOGJAM" ./*.log | grep -v "not vulnerable\|common prime with 2048 bits detected" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "LOGJAM" ./*.log | grep -v "not vulnerable\|common prime with 2048 bits detected" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to LOGJAM,/g' | tee -a "${filename}${ext}"
fi

# BEAST
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to BEAST:" | tee -a "${filename}${ext}"
        grep -ir "BEAST" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "BEAST" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to BEAST,/g' | tee -a "${filename}${ext}"
fi

# LUCKY13
if [ "$preference" = 1 ]
then
        echo "Hosts vulnerable to LUCKY13:" | tee -a "${filename}${ext}"
        grep -ir "LUCKY13" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "LUCKY13" ./*.log | grep -v "not vulnerable" | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/Vulnerable to LUCKY13,/g' | tee -a "${filename}${ext}"
fi

# RC4 Ciphers
if [ "$preference" = 1 ]
then
        echo "Hosts using RC4 Ciphers:" | tee -a "${filename}${ext}"
        grep -ir "CVE-2013-2566" ./*.log | grep -i 'vulnerable' | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/:/g' | tee -a "${filename}${ext}"
        printf "\n" | tee -a "${filename}${ext}"
else
        grep -ir "CVE-2013-2566" ./*.log | grep -i 'vulnerable' | cut -f1 -d - | cut -f 2 -d / | sed 's/_p/,/g' | sed 's/^/RC4 Ciphers in use,/g' | tee -a "${filename}${ext}"
fi

printf "\n"
printf "Files have been parsed, with results stored within ./${filename}${ext}\n"
echo "As this is still a work in progress, please run the following commands and review manually."
printf "\n"
echo "Cookies:"
echo 'grep -ir "Cookie" ./*.log | grep -v "none issued" '
printf "\n"
echo "Information disclosure within banners: "
echo 'grep -ir "banner" ./*.log'
