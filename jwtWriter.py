import json
import hmac
import hashlib
import base64
# import pyjwt
#
CONST_KEY = "Secret key".encode()

def write_jwt():
	#Header goes here
	header = json.dumps({															#JSON object in string format{
		"alg": "HS256",
		"typ": "JWT"
		})
	uHeader = base64.urlsafe_b64encode(header.encode())								#Byte object (URL-safe)

	#Payload goes here
	payload = json.dumps({															#JSON object in string format{
		"sub": "1234567890",
		"name": "John Doe",
		"iat": 1516239022
	})
	uPayload = base64.urlsafe_b64encode(payload.encode())							#Byte object (URL-safe)

	#Signature goes here
	message = uHeader.decode() + "." + uPayload.decode()							#String
	signature = hmac.new( CONST_KEY, message.encode(), hashlib.sha256)	#Byte object
	#All three parts to be encode to URL
	print ( uHeader.decode() + "." + uPayload.decode() + "." + signature.hexdigest() )
	return( uHeader.decode() + '.' + uPayload.decode() + '.' + signature.hexdigest() )
