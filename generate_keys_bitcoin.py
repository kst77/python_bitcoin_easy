import random
import utils_bitcoin

def generate():
    private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
    print('private key : %s' % private_key)
    public_key  = utils_bitcoin.privateKeyToPublicKey(private_key)
    print('public_key : %s' % public_key)
    address = utils_bitcoin.pubKeyToAddr(public_key)
    print('address : %s' % address)


if __name__ == '__main__':
    generate()

