import itertools as itr
import random
import threading
import multiprocessing as mp


SBOX = [1, 14, 27, 40, 53, 66, 79, 92, 105, 118, 131, 144, 157, 170, 183, 196, 209, 222, 235, 248, 5, 18, 31, 44, 57, 70, 83, 96, 109, 122, 135, 148, 161, 174, 187, 200, 213, 226, 239, 252, 9, 22, 35, 48, 61, 74, 87, 100, 113, 126, 139, 152, 165, 178, 191, 204, 217, 230, 243, 0, 13, 26, 39, 52, 65, 78, 91, 104, 117, 130, 143, 156, 169, 182, 195, 208, 221, 234, 247, 4, 17, 30, 43, 56, 69, 82, 95, 108, 121, 134, 147, 160, 173, 186, 199, 212, 225, 238, 251, 8, 21, 34, 47, 60, 73, 86, 99, 112, 125, 138, 151, 164, 177, 190, 203, 216, 229, 242, 255, 12, 25, 38, 51, 64, 77, 90, 103, 116, 129, 142, 155, 168, 181, 194, 207, 220, 233, 246, 3, 16, 29, 42, 55, 68, 81, 94, 107, 120, 133, 146, 159, 172, 185, 198, 211, 224, 237, 250, 7, 20, 33, 46, 59, 72, 85, 98, 111, 124, 137, 150, 163, 176, 189, 202, 215, 228, 241, 254, 11, 24, 37, 50, 63, 76, 89, 102, 115, 128, 141, 154, 167, 180, 193, 206, 219, 232, 245, 2, 15, 28, 41, 54, 67, 80, 93, 106, 119, 132, 145, 158, 171, 184, 197, 210, 223, 236, 249, 6, 19, 32, 45, 58, 71, 84, 97, 110, 123, 136, 149, 162, 175, 188, 201, 214, 227, 240, 253, 10, 23, 36, 49, 62, 75, 88, 101, 114, 127, 140, 153, 166, 179, 192, 205, 218, 231, 244]
ROUNDS = 2

pts = ['4728c057c95eccf6', '6c162342d8ec4329', '13487135b5749119', 'edc9314bcb16b7f5', '176132f27f2c9070', '872b245348d80856', '7d080386a3c174d6', '53ddb1972cf2ec11']
cts = ['e0ce7ba2f97651ba', '84db1cabc78805c5', 'c0dfa7b65bbb7319', 'ad91c4bdbe339f94', 'dc0c4a20cbecd2c8', '9c803ed2bbd66b95', '002665bd1cd98198', '22f3a7e791ae78b3']

bpts = [bytes.fromhex(x) for x in pts]
bcts = [bytes.fromhex(x) for x in cts]


def all_shuffles(bline):
	return list(itr.permutations(list(bline)))


def hex8(h):
    res = ''
    i = 0
    while i < len(h):
        res += h[i]
        i += 1
        if i % 2 == 0:
            res += ' '
    return res


def unmix(bs, step):
	return bytes(bs[8-step:]+bs[:8-step])

def unsub(bs):
	bytes(SBOX.index(x) for x in bs)

def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(i^j for i,j in zip(a,b))

def mix_bytes(bs, step):
    return bytes(bs[step:] + bs[:step])

def sub_bytes(bs):
    return bytes(SBOX[x] for x in bs)


def inzip(bs, key, step):
	assert len(bs) == len(key)
	ct = bs
	for round in range(ROUNDS):
		ct = xor_bytes(ct, key)
		ct = sub_bytes(ct)
		ct = mix_bytes(ct, step)
	return ct


def solve_for_step(pt, ct, step):
	key = ''
	#for byte in 
	#mix_bytes(sub_bytes(xor_bytes(pt, key)), step)
	#unsub(unmix(ct, step))


def th(s, e, threadnum):
	for num in range(s, e):
		key = num.to_bytes(8)
		if num % 0x0010000000000000 == 0:
			print(f'Thread-{threadnum}: {num}')
		for step in range(1, 8):
			ctr = sorted([inzip(ct, key, step) for ct in bpts])
			res = sorted(bcts)
			if all(ctr[i] == res[i] for i in range(8)):
				print(f'Thread-{threadnum}: ' + 'ctfcup{' + key.hex() + '}')
				open('answer.txt', 'a').write('ctfcup{' + key.hex() + '}\n')
				return 'ctfcup{' + key.hex() + '}'


if __name__ == "__main__":
	threads = []
	steps = [0x0000000000000000, 0x2200000000000000, 0x4400000000000000, 0x6600000000000000, 
	0x9900000000000000, 0xbb00000000000000, 0xdd00000000000000, 0xFFFFFFFFFFFFFFFF]
	for i in range(len(steps) - 1):
		p = mp.Process(target=th, args=[steps[i], steps[i+1], i])
		p.start()
		threads.append(p)

	
