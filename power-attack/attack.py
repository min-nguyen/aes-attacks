import multiprocessing
import subprocess
import sys
import random
import ctypes
import binascii
import time
from numpy import ctypeslib, matrix, corrcoef, float32, uint8
from numpy.ma import zeros
from Crypto.Cipher import AES


SAMPLE_SIZE     = 20
CIPHER_SIZE  	= 128
KEY_SIZE        = 256
KEY_BYTES	= 16
TRACE_NUM       = 3000 
CHUNKS       	= 750
CHUNK_SIZE	= 4
MIN_CONFIDENCE  = 1
TWEAKS          = []
POW_hypo 	= []	
POW_trace 	= []	
CORRELATION 	= []	

# Rijndael S-box
S_Box = [   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16
    ]

    #"3E6A70391DD40E04B6622E86303A1B64" 
    #"BE6E4860D4D27C755BD2189CE389296D" 


def XTS_Validate(key1, key2):
    print("--Validating Key--")

    invalid_sectaddr  =  ("%X" % random.randrange(1 << 127, 1 << 128)).strip().zfill(32)
    tweak	= hex_to_byte(invalid_sectaddr)
    key1 	= hex_to_byte(key1)
    key2 	= hex_to_byte(key2)
    c 		= 0

    tweakenc 			= AES.new(key2).encrypt(tweak)  
    tweakenc			= os2ip(byte_to_hex(tweakenc))
    tweakXORcipher 		= c ^ tweakenc

    PP 			= AES.new(key1).decrypt(hex_to_byte(i2osp(tweakXORcipher)))
    res_attack     	= i2osp(os2ip(byte_to_hex(PP)) ^ tweakenc)

    _, res_oracle = interact(invalid_sectaddr)

    print("Attack Key Decryption : " + res_attack)
    print("Disk Key Decryption   : " + res_oracle)
    if(res_attack == res_oracle):
	print("Successful attack, correct key recovered")
	return True
    else: 
	print("Error, decryption values do not match between recovered key and disk encryption key")
	return False

def byte_to_hex(byte_string) :
    if len(byte_string) <= 16:
        return binascii.hexlify(byte_string).zfill(32)
    else :
        return byte_string.zfill(32)


def hex_to_byte(hex_string) :
    if len(hex_string) <= 16:
        return hex_string.zfill(16)
    else :
        return hex_string.strip().zfill(16).decode('hex').zfill(16)


def os2ip(oct_str):
    if isinstance(oct_str, ( int, long )):
        return oct_str  
    elif oct_str  == '':
        return 0
    else:
        return int(oct_str, 16)

def i2osp(X):
    if isinstance(X, basestring):
        return X.zfill(32)
    else:
        return format(X, 'X').zfill(32)

def to_hex(X):
    if isinstance(X, ( int, long )):
        return ("%X" % X).zfill(2)
    elif X == '':
        return 0
    else:
        return X.encode('hex')

def get_trace(t_traces) :
    t_traces = t_traces.split(',')[1:]
    traces = []
    for i in t_traces:
        traces.append(int(i))
    return traces

def next_trace_set(traces):
    smallest = len(traces[0])
    for t in traces:
        if len(t) < smallest:
            smallest = len(t)
    for i in range(len(traces)):
        tmp = traces[i]
        traces[i] = tmp[:smallest]
    return traces

def get_byte(ciphertext, index) :
    return int(ciphertext[index*2 : index*2 + 2], 16)

def sub_bytes(x):
    return S_Box[x]

def init(t_POW_trace, t_POW_hypo, t_CORRELATION):
    global POW_trace, POW_hypo, CORRELATION
    POW_trace = t_POW_trace
    POW_hypo = t_POW_hypo
    CORRELATION = t_CORRELATION


def encrypt_tweak_vals(inputs, key):
    global TWEAKS
    for i in inputs:
        TWEAKS.append(	byte_to_hex( 
				AES.new( hex_to_byte(key) ).encrypt(
              		hex_to_byte(i))))


# Generate random set of ciphertext samples
def gen_ciphers() :
    print("-- Generating random ciphertext samples --")
    samples = []
    for i in range(0, SAMPLE_SIZE):
        sample = "%X" % random.randrange(1 << (CIPHER_SIZE-1), 1 << CIPHER_SIZE)
        samples.append(sample.zfill(32))
    return samples


# Interact with oracle, acquire set of decryption and power consumption values
def gen_samples(ciphers):
    print("-- Acquiring plaintext and trace samples --")
    traces = []
    outputs = []
    for i in ciphers:
        t_trace, t_output = interact(i)
        traces.append(t_trace)
        outputs.append(t_output)
    return (traces, outputs)


def interact(input):
    target_in.write("%s\n" % "000")
    target_in.write("%s\n" % input)
    target_in.flush()

    trace = target_out.readline().strip()
    plaintext = target_out.readline().strip().zfill(32)

    traces = get_trace(trace)
    return (traces, plaintext)

# Find hamming weight
def hamming_weight(V):
    H = zeros((len(V), KEY_SIZE), uint8)
    for i in range(len(V)):
        for j in range(KEY_SIZE):
            H[i][j] = bin(V[i][j]).count("1")
    return H

# Compute correlation coefficient given a hypothetical array index and array index range of trace samples
def calc_correlation(params):
    global POW_trace, POW_hypo, CORRELATION
    a, b, c = params
    POW_hypo = ctypeslib.as_array(POW_hypo)
    POW_trace = ctypeslib.as_array(POW_trace)
    CORRELATION   = ctypeslib.as_array(CORRELATION)
    # Use numpy corrcoef() function to calculate correlation coefficient
    CORRELATION[a][b:c] = corrcoef(POW_hypo[a], POW_trace[b:c])[0][1]
    


def attack_key2(ciphertexts, traces):
    global POW_trace, POW_hypo, CORRELATION, MIN_CONFIDENCE
    key = ""
    key_byte = 0
      
    for byte in range(KEY_BYTES):
        start = time.time()

	# Compute hypothetical intermediate values
        IV = zeros((len(ciphertexts), KEY_SIZE), uint8)
        # Iterate set of ciphertexts & compute potential key values
        for i, p in enumerate(ciphertexts):
            p_i = get_byte(p, byte)
            for k in range(KEY_SIZE):
                IV[i][k] = sub_bytes(p_i ^ k) 
		

	# Hypothetical power consumption
        POW_hypo = hamming_weight(IV).transpose()
	# Observed power consumption
        POW_trace = matrix(traces).transpose()[:TRACE_NUM]

	# Split correlation coefficient array between processors
        params = []
        for i in range(0, KEY_SIZE):
             for j in range(CHUNKS):
          	  params.append( (i, j*CHUNK_SIZE, (j+1)*CHUNK_SIZE) )
        # Initialise multiprocessing pools with shared power consumption array and correlation coefficient array  
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count(), 
				initializer=init, 
				initargs=(POW_trace,POW_hypo, CORRELATION,))
	#Map over parameters (array chunks) assigned per processor & compute current correlation coefficient values
        pool.map(calc_correlation, params)
        pool.close()
        pool.join()


        # Find highest correlation coefficient value; these positively correlate with most likely key byte
	max_coeff = CORRELATION[0].max()
    	for k in range(1, KEY_SIZE):
            current_coeff = CORRELATION[k].max()
	    if current_coeff > max_coeff:
	        max_coeff = current_coeff
	        key_byte  = k

	# Update min confidence
	if (MIN_CONFIDENCE > max_coeff):
	    MIN_CONFIDENCE = max_coeff 
		
	# Append byte with highest correlation coefficient to key    
	key+= to_hex(key_byte)

	end = time.time()

        print "    Byte " + str(byte) + ": " + to_hex(key_byte)
        print "    Confidence:  %.3f  "   % max_coeff
        print "    Time:        %.3f s"  % (end - start)
        print "    Key:         %s\n  " % key

    return key   



def attack_key1(plaintexts, traces):
    global POW_trace, MIN_CONFIDENCE,POW_hypo, CORRELATION
    key = ""
    key_byte = 0
      
    for byte in range(KEY_BYTES):
        start = time.time()

	# Compute hypothetical intermediate values
        IV = zeros((len(plaintexts), KEY_SIZE), uint8)
        # Iterate set of ciphertexts & compute hypothetical key values
        for i, p in enumerate(plaintexts):
            p_i = get_byte(p, byte)

            for k in range(KEY_SIZE):
                t_i = get_byte(TWEAKS[i], byte)
                IV[i][k] = sub_bytes((p_i ^ t_i) ^ k)

        # Hypothetical power consumption     
        POW_hypo = hamming_weight(IV).transpose()
	# Set power consumption traces of cipher sample 
        POW_trace = matrix(traces).transpose()[len(traces[0]) - TRACE_NUM : len(traces[0])]

        # Initialise multiprocessing pools with shared power consumption array and correlation coefficient array
        params = []
        for i in range(0, KEY_SIZE):
            for j in range(CHUNKS):
	            params.append( (i, j*CHUNK_SIZE, (j+1)*CHUNK_SIZE) )
        # Initialise multiprocessing pools with shared power consumption array and correlation coefficient array  
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count(), 
				initializer=init, 
				initargs=(POW_trace,POW_hypo, CORRELATION,))
	#Map over parameters (array chunks) assigned per processor & compute current correlation coefficient values
        pool.map(calc_correlation, params)
        pool.close()
        pool.join()

	# Find highest correlation coefficient value; these positively correlate with most likely key byte
	max_coeff = CORRELATION[0].max()
	for k in range(1, KEY_SIZE):
		current_coeff = CORRELATION[k].max()
		if current_coeff > max_coeff:
		    max_coeff = current_coeff
		    key_byte  = k

	# Update min confidence
	if (MIN_CONFIDENCE > max_coeff):
		MIN_CONFIDENCE = max_coeff 
	
	# Append byte with highest correlation coefficient to key
	key += to_hex(key_byte)

	end = time.time()

	print "    Byte " + str(byte) + ": " + to_hex(key_byte)
	print "    Confidence:  %.3f  "   % max_coeff
	print "    Time:        %.3f s"  % (end - start)
	print "    Key:         %s  \n" % key

    return key

    
def attack():
    global SAMPLE_SIZE, KEY_SIZE, TRACE_NUM, POW_hypo, POW, trace, CORRELATION

    key1 = "" 
    key2 = ""

    while True:

	# Initialise memory for parallel processing
	hypo_arr 	= ctypeslib.as_array(multiprocessing.Array(ctypes.c_float, KEY_SIZE * SAMPLE_SIZE).get_obj())
	POW_hypo   	= hypo_arr.reshape(KEY_SIZE, SAMPLE_SIZE)

	trace_arr 	= ctypeslib.as_array(multiprocessing.Array(ctypes.c_float, SAMPLE_SIZE * TRACE_NUM).get_obj())
	POW_trace 	= trace_arr.reshape(TRACE_NUM, SAMPLE_SIZE)

	corrco_arr	= ctypeslib.as_array(multiprocessing.Array(ctypes.c_float, KEY_SIZE * TRACE_NUM).get_obj())
	CORRELATION 	= corrco_arr.reshape(KEY_SIZE, TRACE_NUM)

	# Generate ciphertext inputs
	ciphertexts 		= gen_ciphers() 
	# Acquire oracle decryptions and power consumption traces
	traces, plaintexts 	= gen_samples(ciphertexts)
	traces 			= next_trace_set(traces)


	# Attack Key 2
	print "---- KEY 2 ATTACK ----\n"
	key2 = attack_key2(ciphertexts, traces)
	print "KEY 2: " + key2

	encrypt_tweak_vals(ciphertexts, key2)

	# Attack Key 1
	print "---- KEY 1 ATTACK ----\n"
	key1 = attack_key1(plaintexts, traces)
	print "KEY 1: " + key1


	if not XTS_Validate(key1, key2):
	    # Double sample size
	    print "Invalid key recovered, attempting again with larger sample size"
	    SAMPLE_SIZE <<= 1
        else:
	    break	

    return key1, key2

if (__name__ == "__main__"):
    target = subprocess.Popen(args=sys.argv[1],
                              stdout=subprocess.PIPE,
                              stdin=subprocess.PIPE)
    target_out = target.stdout
    target_in = target.stdin

    start = time.time()
	
    key1, key2 = attack()

    end = time.time()
    print("Minimum confidence value %.3f" % MIN_CONFIDENCE)
    print("Key: 	        " + key1 + key2)
    print("Time Taken:    %.3f s" % (end - start))
    print("Interactions: 	" + str(SAMPLE_SIZE))
    print("Traces per attack:	" + str(TRACE_NUM))








