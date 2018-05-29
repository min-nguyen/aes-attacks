import sys, subprocess
from Crypto.Util import number
import time
import random, math

N = 0
e = 0

BASE_64 = (1 << 64)
MAX_DEC_LEN = 0
CIPHER_LENGTH = 4000
INTERACTIONS = 0
RHO = 0
RHO_SQR = 0
OMEGA = 0

def verify (DEC_KEY) :
    m = 101010101
    c = pow(m, e, N)
    m_r = pow(c, DEC_KEY, N)
    return m == m_r

def interact( ciphertext ) :
	global INTERACTIONS
	target_in.write( "%X\n" % ( ciphertext ) ) ; 
	target_in.flush()

	t       = int( target_out.readline().strip() )
	m       = int( target_out.readline().strip(), 16 )
	INTERACTIONS += 1
	return t

def readParams(file_path) :
	file = open(file_path, 'r')
	global N, e, MAX_DEC_LEN
	N = int(file.readline(), 16)
	e = int(file.readline(), 16)
	MAX_DEC_LEN = e.bit_length()
	print(e, MAX_DEC_LEN)
	file.close()
	return N, e

def init() :
    cipher = []
    cipher_montgomery = []
    cipher_temp = []
    cipher_time = [] 

    genCipherSet(CIPHER_LENGTH, cipher)

    for i in range(CIPHER_LENGTH) :
        time = interact(cipher[i])
        cipher_time.append(time)

        temp, montform = sqrMul(cipher[i])
        cipher_temp.append(temp)
        cipher_montgomery.append(montform)
    return cipher, cipher_temp, cipher_montgomery, cipher_time

def montParam() :
    global RHO, OMEGA, RHO_SQR
    RHO = 1
    while RHO <= N :
        RHO <<= 64
    RHO_SQR = pow(RHO, 2, N)
    OMEGA = (-number.inverse(N, RHO)) % RHO

def montProductBit(a, b) :
    t = a * b
    u = (t + (t * OMEGA % RHO) * N) / RHO
    Red = False

    if u >= N :
        u = u - N
        Red = True
    return (u, Red)

def genCipherSet(size, cipher) :
    for i in range(size) :
        abc = random.getrandbits(1024)
        while abc >= N :
            abc = random.getrandbits(1024)
        cipher.append(abc)

def sqrMul(ciphertext) :
    t1, _ = montProductBit(1, RHO_SQR)
    montCipher, _ = montProductBit(ciphertext, RHO_SQR)
    t2, _ = montProductBit(t1, t1)
    t3, _ = montProductBit(t2, montCipher)
    montSqrVal, _ = montProductBit(t3, t3)

    return (montSqrVal, montCipher)

def montProduct(DEC_KEY) :
    cipher = []
    cipher_montgomery = []
    cipher_temp = []
    cipher_time = []

    genCipherSet(CIPHER_LENGTH, cipher)

    if DEC_KEY != 1 :
        DEC_KEY = DEC_KEY >> 1

    length = len(bin(DEC_KEY)) - 4

    for i in range(CIPHER_LENGTH) :

        time = interact(cipher[i])
        cipher_time.append(time)

        temp, montform = sqrMul(cipher[i])
        cipher_montgomery.append(montform)

        for j in range(length, -1, -1):
            if  (DEC_KEY>>j)&1 == 1 :
                temp, _ = montProductBit(temp, montform)
            temp, _ = montProductBit(temp, temp)
        

        cipher_temp.append(temp)

    return cipher, cipher_temp, cipher_montgomery, cipher_time, DEC_KEY

def oracleA(temp, time, ciphertext_temp, BIT_0) :
    bit0, isReduction = montProductBit(temp, temp)
    ciphertext_temp[0].append(bit0)
    if isReduction :
        BIT_0[0][0] += time
        BIT_0[0][1] += 1
    else :
        BIT_0[1][0] += time
        BIT_0[1][1] += 1

def oracleB(montcipher, temp, time, ciphertext_temp, BIT_1) :
    t, _ = montProductBit(temp, montcipher)
    bit1, isReduction = montProductBit(t, t)
    ciphertext_temp[1].append(bit1)
    if isReduction :
        BIT_1[1][0] += time
        BIT_1[1][1] += 1
    else :
        BIT_1[0][0] += time
        BIT_1[0][1] += 1

def attack() :
    global CIPHER_LENGTH
    MIN_BOUND = 2.0
    DEC_KEY = 1
    (cipher, cipher_t1, cipher_montgomery, cipher_time) = init()

    while True :
        while True :
			#------------------------------#
			# Bit 1: No Reduction, Reduction
			BIT_1 = ([0, 0], [0, 0])
			# Bit 0: No Reduction, Reduction
			BIT_0 = ([0, 0], [0, 0])

			cipher_t2    = {
				0: [],
				1: []
			}
			#Compute timings of reduction/noreduction of bits 0 & 1
			for i in range(CIPHER_LENGTH) :
				oracleA(cipher_t1[i], cipher_time[i], cipher_t2, BIT_0)
				oracleB(cipher_montgomery[i], cipher_t1[i],cipher_time[i], cipher_t2, BIT_1)

			#Average of bit 1, with reduction
			M1 = BIT_1[1][0]/BIT_1[1][1]
			#Average of bit 1, no reduction
			M2 = BIT_1[0][0]/BIT_1[0][1]
			#Average of bit 0, with reduction
			M3 = BIT_0[1][0]/BIT_0[1][1]
			#Average of bit 0, with reduction
			M4 = BIT_0[0][0]/BIT_0[0][1]
			#Difference of each bit's average timings, between reduction & no reduction
			BIT1_DIFF = abs(M1-M2)
			BIT0_DIFF = abs(M3-M4)
			#Verify most likely bit
			if      ((BIT1_DIFF > BIT0_DIFF) and 
					(abs(BIT0_DIFF - BIT1_DIFF) > MIN_BOUND)) :
				cipher_t1 = cipher_t2[1]
				bit = 1
				break
			elif    ((BIT1_DIFF < BIT0_DIFF) and 
					(abs(BIT0_DIFF - BIT1_DIFF) > MIN_BOUND)) :
				cipher_t1 = cipher_t2[0]
				bit = 0
				break
			else :
				(cipher, cipher_t1, cipher_montgomery, cipher_time, DEC_KEY) = montProduct(DEC_KEY)
			#------------------------------#

        #--------------------------------#
		# Compute last bit of decryption key by trial and error
        DEC_KEY     = (DEC_KEY << 1) | bit
        lastbit0    = (DEC_KEY << 1)
        lastbit1    = lastbit0 | 1

        if verify(lastbit0) :
            DEC_KEY = lastbit0
            break
        if verify(lastbit1) :
            DEC_KEY = lastbit1
            break

		# If computed decryption key exceeds max length, start again
        if DEC_KEY.bit_length() >= MAX_DEC_LEN :
            (cipher, cipher_t1, cipher_montgomery, 
                          cipher_time) = init()
            DEC_KEY = 1
        print( str(bin(DEC_KEY))[2:])
    	#--------------------------------#

    return DEC_KEY


if ( __name__ == "__main__" ) :
    #-----------------------#
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )
    target_out = target.stdout
    target_in  = target.stdin
    #-----------------------#
    readParams(sys.argv[2])
    montParam()
    #-----------------------#
    time_before = time.time()
    DEC_KEY = attack()
    time_after = time.time()
    time_taken = time_after - time_before
    print ("Time Taken      : " +str(time_taken) + "s")
    print ("Decryption Key  : " +str("%X" %DEC_KEY))
    print ("Interactions    : " +str(INTERACTIONS))
