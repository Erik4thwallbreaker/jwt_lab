import json

def write_jwt():
	#Header goes here
	header = "Header"

	#Payload goes here
	payload = "Payload"

	#Signature goes here
	signature = "Signature"

	#All three parts to be encoded to binary

	return(header + '.' + payload + '.' + signature)
