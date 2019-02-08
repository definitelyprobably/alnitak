#!/bin/bash
#
# This is a sample script to show how any external program used to manage
# your DNS zone should operate. This code should only be indicative. You
# might in fact find the python package 'requests' to be quite useful, if
# your DNS provider uses a REST API; so you might want to make a quick
# python script instead of a shell script.
#


create_record () {
	# Suppose we wish to publish a TLSA record:
	#    TLSA 3 1 2 _25._tcp.example.com 123456789ABCDEF0...
	#
	# The environment will have set the parameters:
	#
	#    TLSA_USAGE: "3"
	#    TLSA_SELECTOR: "1"
	#    TLSA_MATCHING: "2"
	#    TLSA_PARAM: "312"
	#    TLSA_PORT: "25"
	#    TLSA_PROTOCOL: "tcp"
	#    TLSA_DOMAIN: "example.com"
	#    TLSA_HASH: "123456789ABCDEF0..."
	#
	# You can use this information to publish the TLSA record as required
	# by whatever API you are using.

	# Suppose we use REST as the API:
	response=$(curl -X POST "https://api.dnsprovider.com/" --data '...')

	# obviously, your code shouldn't be this dumb...
	if [[ "$response" == "record created successfully" ]]; then
		exit 0
	elif [[ "$response" == "record is up" ]]; then
		exit 1
	else
		exit 2
	fi
}


delete_record () {
	# Suppose we wish to unconditionally delete a TLSA record:
	#    TLSA 3 1 2 _25._tcp.example.com 123456789ABCDEF0...
	#
	# The environment will have set the parameters:
	#
	#    TLSA_USAGE: "3"
	#    TLSA_SELECTOR: "1"
	#    TLSA_MATCHING: "2"
	#    TLSA_PARAM: "312"
	#    TLSA_PORT: "25"
	#    TLSA_PROTOCOL: "tcp"
	#    TLSA_DOMAIN: "example.com"
	#    TLSA_HASH: "123456789ABCDEF0..."
	#
	# If we wish to delete an old TLSA record:
	#    TLSA 3 1 2 _25._tcp.example.com 123456789ABCDEF0...
	# 
	# only if the new TLSA record (previously published) is up:
	#    TLSA 3 1 2 _25._tcp.example.com FEDCBA9876543210...
	#
	# Then the environment will have set the parameters as above, but now
	# also the parameter:
	#
	#    TLSA_LIVE_HASH: "FEDCBA9876543210..."
	#
	# You can use this information to delete the TLSA record as required
	# by whatever API you are using.

	if [[ -z "$TLSA_LIVE_HASH" ]] ; then
		# unconditional deletion

		# Suppose we use REST as the API:
		response=$(curl -X DELETE "https://api.dnsprovider.com/" --data '...')
		if [[ "$response" == "record deleted successfully" ]]; then
			exit 0
		else
			exit 2
		fi

	else
		# delete old record only if the new one is up

		response=$(curl -X GET "https://api.dnsprovider.com/" --data '...')
		if [[ "$response" == "record not found" ]]; then
			exit 1
		fi

		response=$(curl -X DELETE "https://api.dnsprovider.com/" --data '...')
		if [[ "$response" == "record deleted successfully" ]]; then
			exit 0
		else
			exit 2
		fi
	fi
}



if [[ "$TLSA_OPERATION" == "publish" ]]; then
	create_record
elif [[ "$TLSA_OPERATION" == "delete" ]]; then
	delete_record
fi

exit 3
