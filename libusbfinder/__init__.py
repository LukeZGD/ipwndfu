import hashlib
import os
import platform
import io
import tarfile

class VersionConfig:
    def __init__(self, version, bottle, bottle_sha256, dylib_patches, dylib_sha256):
        self.version = version
        self.bottle = bottle
        self.bottle_sha256 = bottle_sha256
        self.dylib_patches = dylib_patches
        self.dylib_sha256 = dylib_sha256

configs = [
    VersionConfig(
        version='14.0',
        bottle='libusb-1.0.28.sonoma.bottle',
        bottle_sha256='1f2de0243e7dd67d4cf6c5fde24fa146db8681d287ad6db6af45d6dc544f36c8',
        dylib_patches=[],
        dylib_sha256='4eb8d2cb5a75a84a3a038d168b643b1aa19a3f319955c9b71ea70eb5355f624d'),
    VersionConfig(
        version='10.14',
        bottle='libusb-1.0.22.mojave.bottle',
        bottle_sha256='6accd1dfe6e66c30aac825ad674e9c7a48b752bcf84561e9e2d397ce188504ff',
        dylib_patches=[(0x8fd1, bytes.fromhex('E985000000'))],
        dylib_sha256='34d4c0ca821a31f83f3860575f9683cdb8fc5cbd4167383eedfb8b2ba7f7d9d5'),
    VersionConfig(
        version='10.13',
        bottle='libusb-1.0.22.high_sierra.bottle',
        bottle_sha256='7b1fd86a5129620d1bbf048c68c7742ecad450de138b8186bf8e985a752b2302',
        dylib_patches=[(0x98fb, bytes.fromhex('E97F000000'))],
        dylib_sha256='7bd48a3a9955fc20752433f944f61d58d5ec9b68d25dcfab1671f3c82339c4f8'),
    VersionConfig(
        version='10.12',
        bottle='libusb-1.0.22.sierra.bottle',
        bottle_sha256='7f2b65d09525c432a86e46699a1448bab36503f45f16d6e0d8f42be6b1ef55cf',
        dylib_patches=[(0x98fb, bytes.fromhex('E97F000000'))],
        dylib_sha256='0d386845a96fa0457cb6c200f956c9b0d5f236729ef1e2cff34cd312f8cfc7ba'),
    VersionConfig(
        version='10.11',
        bottle='libusb-1.0.22.el_capitan.bottle',
        bottle_sha256='33575c9f56bc0d57bf985a21e40be019d5c269b432939416be8f24c5921bbb28',
        dylib_patches=[(0x9917, bytes.fromhex('E956010000'))],
        dylib_sha256='7ae848e0e8730bf8de48bb534a8ee42eb301a2f6ba6cc188228ce8bf79a6ba07'),
    VersionConfig(
        version='10.10',
        bottle='libusb-1.0.21.yosemite.bottle',
        bottle_sha256='8831059f7585ed973d983dd82995e1732c240a78f4f7a82e5d5c7dfe27d49941',
        dylib_patches=[],
        dylib_sha256='8e89265251d119f3422a760cf3472ecc46b7c3d22598600905dd5595a1ec146a'),
    VersionConfig(
        version='10.9',
        bottle='libusb-1.0.20.mavericks.bottle.1',
        bottle_sha256='5a475e2ca93886e51b994d1ea323e915c91d8463e5b23b45203acb69edf69981',
        dylib_patches=[],
        dylib_sha256='8f21fc0af0c7b04e7db988e1fc66ea9dbc31289096c68416140152d70138c316'),
    VersionConfig(
        version='10.8',
        bottle='libusb-1.0.19.mountain_lion.bottle.1',
        bottle_sha256='d5c4bd99b359a8319d49e06b6b13fc529f91a5bd61ce5a8ff14c291b44b676da',
        dylib_patches=[],
        dylib_sha256='0490800ca9ff82d37c310a09f9bd29aaa87143cf86b35d94b170617ec9d127bb'),
]

dir = os.path.dirname(__file__)
BOTTLE_PATH_FORMAT = os.path.join(dir, 'bottles', '%s.tar.gz')
DYLIB_PATH_FORMAT = os.path.join(dir, '%s.dylib')
DYLIB_NAME = 'libusb-1.0.0.dylib'

def apply_patches(binary, patches):
    for (offset, data) in patches:
        binary = binary[:offset] + data + binary[offset + len(data):]
    return binary

def libusb1_path_internal():
    version = platform.mac_ver()[0]
    processor = platform.mac_ver()[2]

    if version == '':
        # We're not running on a Mac.
        return None

    # HACK to support macOS 10.15 and newer
    versions = ['10.8', '10.9', '10.10', '10.11', '10.12', '10.13', '10.14']
    hack = True
    for x in versions:
        if version.startswith(x):
            version = x
            hack = False
    if hack:
        version = '10.14'
    if processor != 'x86_64':
        version = '14.0'

    for config in configs:
        if version.startswith(config.version):
            path = DYLIB_PATH_FORMAT % config.bottle
            try:
                with open(path, 'rb') as f:
                    dylib = f.read()
                if hashlib.sha256(dylib).hexdigest() == config.dylib_sha256:
                    return path
                print('WARNING: SHA256 hash of existing dylib does not match.')
            except IOError:
                pass

            with open(BOTTLE_PATH_FORMAT % config.bottle, 'rb') as f:
                bottle = f.read()
            if hashlib.sha256(bottle).hexdigest() != config.bottle_sha256:
                print('ERROR: SHA256 hash of bottle does not match.')
                sys.exit(1)

            tar = tarfile.open(fileobj=io.BytesIO(bottle))
            for member in tar.getmembers():
                if member.name.endswith(DYLIB_NAME):
                    extracted_data = tar.extractfile(member.name).read()
                    patched_dylib = apply_patches(extracted_data, config.dylib_patches)
                    if hashlib.sha256(patched_dylib).hexdigest() != config.dylib_sha256:
                        print('ERROR: SHA256 hash of new dylib does not match.')
                        sys.exit(1)
                    with open(path, 'wb') as f:
                        f.write(patched_dylib)
                    return path

    # No match found.
    return None

cached_path = libusb1_path_internal()

def libusb1_path():
    return cached_path
