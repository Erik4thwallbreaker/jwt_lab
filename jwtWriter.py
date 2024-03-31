import json
import time
import hmac
import hashlib
import base64
# import pyjwt
#
CONST_KEY = "Secret key".encode()

def write_jwt():
	#Header goes here
	header = json.dumps({																				#String
		"alg": "HS256",
		"typ": "JWT"
		})
	uHeader = base64.urlsafe_b64encode(header.encode())													#Encoded bytes (Meaning Base64URL)

	#Payload goes here
	payload = json.dumps({																				#String
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.time()
	})
	uPayload = base64.urlsafe_b64encode(payload.encode())												#Encoded bytes

	#Signature goes here
	message = uHeader.decode() + "." + uPayload.decode()												#String
	signature = hmac.new( CONST_KEY, message.encode(), hashlib.sha256)									#HMAC Object
	uSignature = base64.urlsafe_b64encode(signature.digest())											#Encoded bytes

	#All three parts to be encode to URL
	return( uHeader.decode() + '.' + uPayload.decode() + '.' + uSignature.decode() )

def read_jwt(token):
	try:
		uToken_list = token.split('.')																	#List with encoded strings
		token_list = [ base64.urlsafe_b64decode(jwt_part.encode()) for jwt_part in uToken_list]			#List with bytes
		header = token_list[0].decode()																	#String
		payload = token_list[1].decode()																#String
		givenSignature = token_list[2]																	#Bytes

		givenAlg = json.loads(header)["alg"]
		givenTyp = json.loads(header)["typ"]
		if givenTyp != "JWT":
			return("Unnsported Token")
		if givenAlg != "HS256":
			return(givenAlg + "Is not supported")

		message = uToken_list[0] + '.' + uToken_list[1]
		signature = hmac.new( CONST_KEY, message.encode(), hashlib.sha256)								#HMAC Object
		ownSignature = signature.digest()																#Bytes
		authentic_signature = ( givenSignature == ownSignature )
		if authentic_signature:
			return "Signature verified \nPayload: " + payload
		else:
			return "Invalid signature"

	except:
			return "Invalid token"
	
token = write_jwt()
print("Token: " + token)
reply = read_jwt(token)
print(reply)
