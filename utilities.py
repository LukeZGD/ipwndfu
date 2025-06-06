import subprocess
import sys

def apply_patches(binary, patches):
    for (offset, data) in patches:
        binary = binary[:offset] + data + binary[offset + len(data):]
    return binary

def aes_decrypt(data, iv, key):
    if len(key) == 32:
        aes = 128
    elif len(key) == 64:
        aes = 256
    else:
        print('ERROR: Bad AES key given to aes_decrypt. Exiting.')
        sys.exit(1)

    # Ensure IV and key are passed as strings (hex format expected)
    p = subprocess.Popen(
        ['openssl', 'enc', f'-aes-{aes}-cbc', '-d', '-nopad', '-iv', iv, '-K', key],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = p.communicate(input=data)

    if p.returncode != 0 or len(stderr) > 0:
        print(f'ERROR: openssl failed: {stderr.decode()}')
        sys.exit(1)

    return stdout
