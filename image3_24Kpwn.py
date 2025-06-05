# Credit: This file is based on 24Kpwn exploit (segment overflow) by chronic, CPICH, ius, MuscleNerd, Planetbeing, pod2g, posixninja, et al.

import struct
import image3

def remove_exploit(img3):
    assert len(img3) > 0x24000
    assert img3[16:20] == b'illb'[::-1]

    obj = image3.Image3(img3)
    if obj.getDecryptedPayload()[:4] != b'\x0e\x00\x00\xea':
        # This is a 24Kpwn implementation which changes DATA tag. First dword of DATA tag should look like a shellcode address.
        shellcode_address, = struct.unpack('<I', img3[64:68])
        assert img3[52:56] == b'DATA'[::-1]
        assert 0x84000000 <= shellcode_address <= 0x84024000

        # Try to find the correct value for the first dword.
        found = False
        for pos in range(shellcode_address - 0x84000000, len(img3)):
            obj = image3.Image3(img3[:64] + img3[pos:pos + 4] + img3[68:])
            if obj.getDecryptedPayload()[:4] == b'\x0e\x00\x00\xea':
                found = True
                break
        assert found

    obj.shrink24KpwnCertificate()

    img3 = obj.newImage3(decrypted=False)
    assert len(img3) <= 0x24000
    return img3
