#------------------------------------------
# Travail dans le cadre du projet de cryptographie 
# Encadre par Damien Vergnaud, Lip6
#
#   			 Lamport signature
#					Felix CHOI
#
# using sha256
#------------------------------------------


from hashlib import *
import random

word = "soum"
print(len(word.encode()))
hash_object = sha256(word.encode())
hex_dig = hash_object.hexdigest()
print("'"+word+"'" + " becomes -> " + hex_dig)
print(len(hex_dig))


def generate_privateKey(message):
	message_bin = ' '.join(format(x, 'b') for x in bytearray(message,'utf-8'))
	message_bin = ''.join(message_bin.split())
	#print(message_bin)
	privatekey = []
	for i0 in range(2*len(message_bin)):
		i0 = random.randint(0,1)
		privatekey.append(i0)

	#print(privatekey)
	return privatekey

def generate_publicKey(privatekey):
	y=[]
	for i in privatekey:
		hash_object = sha256(str(i).encode())
		hex_dig = hash_object.hexdigest()
		y.append(bin(int(hex_dig, 16))[2:])
	#print(y)
	return y




def signature(message, privatekey):
	sigma = []
	message_bin = ' '.join(format(x, 'b') for x in bytearray(message,'utf-8'))
	message_bin = ''.join(message_bin.split())
	for i in range(len(message_bin)):
		m = message_bin[i]
		m = int(m)
		x = privatekey[2*i + m]
		
		sigma.append(x)
	print(sigma)
	return sigma

def verification(message,sigma,publickey):
	message_bin = ' '.join(format(x, 'b') for x in bytearray(message,'utf-8'))
	message_bin = ''.join(message_bin.split())
	print(message_bin)
	d_sigma = []
	verif_y = []

	#calcul de d_sigma ("digest sigma") -> f(sigma)
	for s in sigma:
		hash_object = sha256(str(s).encode())
		hex_dig = hash_object.hexdigest()
		d_sigma.append(bin(int(hex_dig, 16))[2:])
	print(d_sigma)

	#calcul de verif_y -> y(m)
	for i in range(len(message_bin)):
		m = message_bin[i]
		m = int(m)
		y = publickey[2*i + m]
		verif_y.append(y)
	print(verif_y)

	#verification de l'egalite entre d_sigma et verif_y
	if ( verif_y == d_sigma):
		print("ok")
		return 1
	else:
		print("shit")
		return 0




#test
message = 'soum'
prv = generate_privateKey(word)
pbl = generate_publicKey(prv)
sig = signature(word,prv)
verification(word,sig,pbl)

