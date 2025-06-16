import binascii, datetime, hashlib, struct, sys, time
import usb  # pyusb: use 'pip install pyusb' to install this module
import dfu, recovery, image3, image3_24Kpwn, utilities

EXEC_MAGIC = 'exec'[::-1].encode()
AES_BLOCK_SIZE = 16
AES_GID_KEY = 0x20000200
AES_DECRYPT = 17

class PwnedDeviceConfig:
    def __init__(self, version, cpid, aes_crypto_cmd, memmove, get_block_device, load_address):
        self.version = version
        self.cpid = cpid
        self.aes_crypto_cmd = aes_crypto_cmd
        self.memmove = memmove
        self.get_block_device = get_block_device
        self.load_address = load_address

configs = [
    PwnedDeviceConfig(
        version='359.3',
        cpid='8920',
        aes_crypto_cmd=0x925,
        memmove=0x83d4,
        get_block_device=0x1351,
        load_address=0x84000000
    ),
    PwnedDeviceConfig(
        version='359.3.2',
        cpid='8920',
        aes_crypto_cmd=0x925,
        memmove=0x83dc,
        get_block_device=0x1351,
        load_address=0x84000000
    ),
]

class PwnedDFUDevice():
    def __init__(self):
        device = dfu.acquire_device()
        self.identifier = device.serial_number
        dfu.release_device(device)

        if 'PWND:[' not in self.identifier:
            print('ERROR: Device is not in pwned DFU Mode. Use -p flag to exploit device and then try again.')
            sys.exit(1)

        if 'CPID:8920' not in self.identifier:
            print('ERROR: This is not a compatible device. iPhone 3GS only.')
            sys.exit(1)

        self.config = None
        for config in configs:
            if f'SRTG:[iBoot-{config.version}]' in self.identifier:
                self.config = config
                break
        if self.config is None:
            print('ERROR: Device seems to be in pwned DFU Mode, but a matching configuration was not found.')
            sys.exit(1)

    def ecid_string(self):
        tokens = self.identifier.split()
        for token in tokens:
            if token.startswith('ECID:'):
                return token[5:]
        print('ERROR: ECID is missing from USB serial number string.')
        sys.exit(1)

    def execute(self, cmd, receiveLength):
        device = dfu.acquire_device()
        assert self.identifier == device.serial_number

        dfu.reset_counters(device)
        dfu.usb_reset(device)
        dfu.send_data(device, EXEC_MAGIC + cmd)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number

        requiredLength = 0x8 + receiveLength
        requiredLength = requiredLength if requiredLength % 0x800 == 0 else (requiredLength // 0x800) * 0x800 + 0x800
        received = dfu.get_data(device, requiredLength)
        dfu.release_device(device)

        (exec_cleared, retval) = struct.unpack('<2I', received[:8])
        assert exec_cleared == 0
        return (retval, received[8:8 + receiveLength])

    def aes(self, data, action, key):
        if len(data) % AES_BLOCK_SIZE != 0:
            print(f'ERROR: Length of data for AES encryption/decryption must be a multiple of {AES_BLOCK_SIZE}.')
            sys.exit(1)

        cmd = struct.pack('<8I', self.config.aes_crypto_cmd, action, self.config.load_address + 36,
                          self.config.load_address + 0x8, len(data), key, 0, 0)
        (retval, received) = self.execute(cmd + data, len(data))
        return received[:len(data)]

    def read_memory(self, address, length):
        (retval, data) = self.execute(struct.pack('<4I', self.config.memmove, self.config.load_address + 8, address, length), length)
        return data

    def nor_dump(self, saveBackup):
        (bdev, _) = self.execute(struct.pack('<2I5s', self.config.get_block_device, self.config.load_address + 12, b'nor0\x00'), 0)
        if bdev == 0:
            print('ERROR: Unable to dump NOR. Pointer to nor0 block device was NULL.')
            sys.exit(1)

        data = self.read_memory(bdev + 28, 4)
        (read,) = struct.unpack('<I', data)
        if read == 0:
            print('ERROR: Unable to dump NOR. Function pointer for reading was NULL.')
            sys.exit(1)

        NOR_PART_SIZE = 0x20000
        NOR_PARTS = 8
        nor = b''
        for i in range(NOR_PARTS):
            print(f'Dumping NOR, part {i+1}/{NOR_PARTS}.')
            (retval, received) = self.execute(struct.pack('<6I', read, bdev, self.config.load_address + 8, i * NOR_PART_SIZE, 0, NOR_PART_SIZE), NOR_PART_SIZE)
            nor += received

        if saveBackup:
            date = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = f'nor-backups/nor-{self.ecid_string()}-{date}.dump'
            with open(filename, 'wb') as f:
                f.write(nor)
            print(f'NOR backed up to file: {filename}')

        return nor

    def boot_ibss(self):
        print('Sending iBSS.')
        if self.config.cpid != '8920':
            print('ERROR: Boot iBSS is currently only supported on iPhone 3GS.')
            sys.exit(1)

        help1 = 'Download iPhone2,1_4.3.5_8L1_Restore.ipsw and use the following command to extract iBSS:'
        help2 = 'unzip -p iPhone2,1_4.3.5_8L1_Restore.ipsw Firmware/dfu/iBSS.n88ap.RELEASE.dfu > n88ap-iBSS-4.3.5.img3'
        try:
            with open('n88ap-iBSS-4.3.5.img3', 'rb') as f:
                data = f.read()
        except:
            print('ERROR: n88ap-iBSS-4.3.5.img3 is missing.')
            print(help1)
            print(help2)
            sys.exit(1)
        if len(data) == 0:
            print('ERROR: n88ap-iBSS-4.3.5.img3 exists, but is empty (size: 0 bytes).')
            print(help1)
            print(help2)
            sys.exit(1)
        if hashlib.sha256(data).hexdigest() != 'b47816105ce97ef02637ec113acdefcdee32336a11e04eda0a6f4fc5e6617e61':
            print('ERROR: n88ap-iBSS-4.3.5.img3 exists, but is from the wrong IPSW or corrupted.')
            print(help1)
            print(help2)
            sys.exit(1)

        iBSS = image3.Image3(data)
        decryptediBSS = iBSS.newImage3(decrypted=True)
        n88ap_iBSS_435_patches = [
            (0x14954, b'run\x00'),
            (0x17654, struct.pack('<I', 0x41000001)),
        ]
        patchediBSS = decryptediBSS[:64] + utilities.apply_patches(decryptediBSS[64:], n88ap_iBSS_435_patches)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number
        dfu.reset_counters(device)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        device = dfu.acquire_device()
        assert self.identifier == device.serial_number
        dfu.send_data(device, patchediBSS)
        dfu.request_image_validation(device)
        dfu.release_device(device)

        time.sleep(0.5)

        print('Waiting for iBSS to enter Recovery Mode.')
        device = recovery.acquire_device()
        recovery.release_device(device)

    def flash_nor(self, nor):
        self.boot_ibss()
        print('Sending iBSS payload to flash NOR.')
        MAX_SHELLCODE_LENGTH = 128
        with open('bin/ibss-flash-nor-shellcode.bin', 'rb') as f:
            payload = f.read()
        assert len(payload) <= MAX_SHELLCODE_LENGTH
        payload += b'\x00' * (MAX_SHELLCODE_LENGTH - len(payload)) + nor

        device = recovery.acquire_device()
        assert 'CPID:8920' in device.serial_number
        recovery.send_data(device, payload)
        try:
            print('Sending run command.')
            recovery.send_command(device, 'run')
        except usb.core.USBError:
            pass
        recovery.release_device(device)
        print('If screen is not red, NOR was flashed successfully and device will reboot.')

    def decrypt_keybag(self, keybag):
        KEYBAG_LENGTH = 48
        assert len(keybag) == KEYBAG_LENGTH

        KEYBAG_FILENAME = f'aes-keys/S5L{self.config.cpid}-firmware'
        try:
            with open(KEYBAG_FILENAME, 'rb') as f:
                data = f.read()
        except IOError:
            data = b''
        assert len(data) % (2 * KEYBAG_LENGTH) == 0

        for i in range(0, len(data), 2 * KEYBAG_LENGTH):
            if keybag == data[i:i + KEYBAG_LENGTH]:
                return data[i + KEYBAG_LENGTH:i + 2 * KEYBAG_LENGTH]

        decrypted_keybag = self.aes(keybag, AES_DECRYPT, AES_GID_KEY)

        with open(KEYBAG_FILENAME, 'ab') as f:
            f.write(keybag + decrypted_keybag)

        return decrypted_keybag
