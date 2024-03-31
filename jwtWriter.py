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
	signature = hmac.new( CONST_KEY, message.encode(), hashlib.sha256)				#Bytes object
	uSignature = base64.urlsafe_b64encode(signature.digest())						#Encoded bytes object
	#All three parts to be encode to URL
	print ( uHeader.decode() + "." + uPayload.decode() + "." + uSignature.decode() )
	return( uHeader.decode() + '.' + uPayload.decode() + '.' + uSignature.decode() )

def read_jwt(token):
	try:
		uToken_list = token.split('.')													#List with Encoded strings
		print('uToken_list')
		print(uToken_list)
		token_list = [ base64.urlsafe_b64decode(jwt_part.encode()) for jwt_part in uToken] #Binary list
		print('Token_list')
		print(token_list)
		header = token_list[0].decode()
		print('Header, Payload, Signature')
		print(header)
		payload = token_list[1].decode()
		print(payload)
		signature = token_list[2]
		print(signature)

		authentic_signature = TRUE
		if authentic_signature:
			print("Signature verified")
			print("Payload: " + payload)
		else:
			print("Invalid signature")

	except:
		print("Invalid token")
	
token = write_jwt()
read_jwt(token)
