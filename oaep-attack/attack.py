import sys, subprocess
import math
from hashlib import sha1
import time
POW32 = 2**32

def getConf( file ) :
    global N, k, B, e, label, c, num_interactions

    N_string 	= file.readline()
    N 			= int(N_string, 16)
    e 			= int(file.readline(), 16)
    label 		= int(file.readline(), 16)
    c 			= int(file.readline(), 16)
    file.close()
    k = floorDiv(len(N_string),2)
    B =  1 << (8*(k-1))

    num_interactions = 0



def interact( cipher ) :

    global num_interactions
    num_interactions += 1

    cipher = (pow(cipher , e, N) * c) % N
    # Send (label, cipher) to target
    target_in.write( "%s\n" % ("%X" % label ).zfill(256) ) ; target_in.flush()
    target_in.write( "%s\n" % ("%X" % cipher ).zfill(256) ) ;target_in.flush()
    err = int( target_out.readline().strip() )
    # Receive ( t, r ) from target.
    return err

def floorDiv(a, b) :
    r = a%b 
    return (a-(a%b))/b

def ceilDiv(a, b):
  r = a%b
  return (a - r)/b + 1 & (r > 0)


def Step1():
    f1 = 2
    error = interact(f1)
    # Create upper bound s.t  2B > f1 >= B
    while error == 2:
        f1 *= 2
        error = interact(f1)
    # Verify decryption > B i.e most significant octet isn't present
    if error != 1 :
        raise Exception()
    return f1

def Step2(f1):
    
    
    # Set f2 as largest multiple of m s.t (f2 * m) < (n + B)
    half_f1 = int(f1 * 0.5)
    f2 = floorDiv((N+B), B) * half_f1
    error = interact(f2)

    # Create lower bound - increase until (n + B) > f2 > B 
    while error == 1 :
        f2 += half_f1
        error = interact(f2)

    # Verify decryption < B
    if error != 2 :
        raise Exception()
    return f2

def Step3(f2) :
    # Possible em values are within m_min = n/f2 and m_max = (n+B)/f2
    m_min = ceilDiv(N,f2)
    m_max = floorDiv(N+B, f2)
    B2 = 2*B
    # Converge upper & lower bounds
    while m_min != m_max :
        
	ftmp = floorDiv((B2) , (m_max-m_min))

	i_n = floorDiv((ftmp*m_min) , N)* N

	f3 = ceilDiv(i_n , m_min)

	error = interact(f3)
	if error == 1 :
		m_min = ceilDiv(i_n + B, f3)
	elif error == 2 :
		m_max = floorDiv(i_n + B, f3)
	elif error == 0:
		break
	else:
		raise Exception("")

    # Verify em
    c_vrfy = pow(m_min, e, N)
    if c_vrfy == c:
		print ("******    EM RECOVERED   ********")
		em = ("%X" % m_min).zfill(256)
		print ( em )
		return em
    else:
        raise Exception("Step 3 failed")
    

def floorDiv(a, b) :
    r = (a%b)
    return (a-r)/b

def ceilDiv(a, b):
  r = a%b
  if r > 0 :
    return (a-r)/b +1
  else :
    return (a-r)/b

def I2OSP(x, xlength) :
    if x >= 256**xlength :
        raise Exception("int to octet conversion failed")
    x = "%X" % x
    return x.zfill(xlength + xlength)


four_xlen = 256**4

def I2OSP(x) :
    if x >= four_xlen:
        raise Exception("int to octet conversion failed")
    x = "%X" % x
    return x.zfill(8)

def MGF(seed, maskLen) :
    if maskLen > POW32 :
        raise Exception("mask length > POW32")

    hLen = sha1().digest_size
    T = ''.join(map(  lambda(i, v): 
                            sha1((seed + I2OSP(i)).decode('hex')  ).hexdigest()
                            , enumerate(xrange(0, ceilDiv(maskLen, hLen)))      ))

    if len(T) < 2*maskLen :
        raise Exception("T too short")

    return T[:2*maskLen]

def EME_OAEP_Decode(em) :

    lHash = sha1(( "%X" % label ).decode('hex')).hexdigest()
    hLen  = sha1().digest_size
    hLen2 = hLen+hLen
    # Separate components
    # em  = {     maskedSeed                ||      maskedDB        || 00} 
    #     = {  MGF(m xor MGF(seed), seed)   ||     m xor MGF(seed)  || 00)
    OO = em[:2]
    maskedSeed = em[2:(hLen2+2)]
    maskedDB = em[(hLen2+2):]

    #Find seed  = { maskedSeed xor MGF(maskedDB) }
    seedMask    = MGF(maskedDB, hLen)
    seed        = "%X" % ( int(maskedSeed, 16) ^ int(seedMask, 16) )
    #Find DB    = { maskedDB xor MGF(seed) }
    dbMask      = MGF(seed, k-hLen-1)
    DB          = "%X" % ( int(maskedDB, 16) ^ int(dbMask, 16) )

    # Separate components
    # DB = { kHash || PS || 0x01 || m }
    index       = DB.find("01", hLen2)

    kHash       = DB[:hLen2]
    PS          = DB[hLen2:index]
    OXO1        = DB[index:index+2]
    m           = DB[index+2:]

    if int(OO, 16) != 0 :
        raise Exception("Missing 00")
    if index == -1 :
        raise Exception("Missing 0x01")
    if int(lHash, 16) != int(kHash, 16) :
        raise Exception("lHash != kHash")
    print ("****** MESSAGE RECOVERED ********") 
    print ( m ) 
    return m

def attack() :
    # Manger's attack - Get encoded message from ciphertext
    f1 = Step1()
    f2 = Step2(f1)
    em = Step3(f2)
    # EME OAEP decode - Get message from encoded message
    m = EME_OAEP_Decode(em)
    print ("******* NUM INTERACTIONS ********")
    print ( num_interactions )

if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                                stdout = subprocess.PIPE,
                                stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Read public parameters
    file = open(sys.argv[2], 'r')
    getConf(file)
    #   print(interact2(c))
    # Execute a function representing the attacker.
    millis = int(round(time.time() * 1000))
    attack()
    millise = int(round(time.time() * 1000))
    print ("TIME %d" % (millise - millis))
