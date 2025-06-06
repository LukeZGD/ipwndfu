import binascii
import struct
import dfuexec
import utilities

class Image3:
    def __init__(self, data: bytes):
        (self.magic, self.totalSize, self.dataSize, self.signedSize, self.type) = struct.unpack(b'4s3I4s', data[0:20])
        self.tags = []
        pos = 20
        while pos < 20 + self.dataSize:
            (tagMagic, tagTotalSize, tagDataSize) = struct.unpack(b'4s2I', data[pos:pos+12])
            self.tags.append((tagMagic, tagTotalSize, tagDataSize, data[pos+12:pos+tagTotalSize]))
            pos += tagTotalSize
            if tagTotalSize == 0:
                break

    @staticmethod
    def createImage3FromTags(type: bytes, tags):
        dataSize = 0
        signedSize = 0
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in tags:
            dataSize += 12 + len(tagData)
            if tagMagic[::-1] not in [b'CERT', b'SHSH']:
                signedSize += 12 + len(tagData)

        # totalSize must be rounded up to 64-byte boundary
        totalSize = 20 + dataSize
        remainder = totalSize % 64
        if remainder != 0:
            totalSize += 64 - remainder

        bytes_data = struct.pack(b'4s3I4s', b'Img3'[::-1], totalSize, dataSize, signedSize, type)
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in tags:
            bytes_data += struct.pack(b'4s2I', tagMagic, tagTotalSize, tagDataSize) + tagData
        return bytes_data + b'\x00' * (totalSize - len(bytes_data))

    def getTags(self, magic: bytes):
        return [tag for tag in self.tags if tag[0] == magic]

    def getKeybag(self):
        keybags = self.getTags(b'KBAG'[::-1])
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in keybags:
            (kbag_type, aes_type) = struct.unpack(b'<2I', tagData[:8])
            if kbag_type == 1:
                return tagData[8:8+48]
        return None

    def getPayload(self):
        data = self.getTags(b'DATA'[::-1])
        return data[0][3] if len(data) == 1 else None

    def getDecryptedPayload(self):
        keybag = self.getKeybag()
        device = dfuexec.PwnedDFUDevice()
        decrypted_keybag = device.decrypt_keybag(keybag)
        return utilities.aes_decrypt(self.getPayload(), binascii.hexlify(decrypted_keybag[:16]), binascii.hexlify(decrypted_keybag[16:]))

    def shrink24KpwnCertificate(self):
        for i in range(len(self.tags)):
            tag = self.tags[i]
            if tag[0] == b'CERT'[::-1] and len(tag[3]) >= 3072:
                data = tag[3][:3072]
                assert data[-1] == b'\x00'[0]
                data = data.rstrip(b'\x00')
                self.tags[i] = (b'CERT'[::-1], 12 + len(data), len(data), data)
                break

    def newImage3(self, decrypted=True):
        typeTag = self.getTags(b'TYPE'[::-1])
        assert len(typeTag) == 1
        versTag = self.getTags(b'VERS'[::-1])
        assert len(versTag) <= 1
        dataTag = self.getTags(b'DATA'[::-1])
        assert len(dataTag) == 1
        sepoTag = self.getTags(b'SEPO'[::-1])
        bordTag = self.getTags(b'BORD'[::-1])
        kbagTag = self.getTags(b'KBAG'[::-1])
        shshTag = self.getTags(b'SHSH'[::-1])
        certTag = self.getTags(b'CERT'[::-1])

        (tagMagic, tagTotalSize, tagDataSize, tagData) = dataTag[0]
        newTagData = self.getDecryptedPayload() if decrypted and kbagTag else tagData
        kbagTag = [] if decrypted and kbagTag else kbagTag

        assert len(tagData) == len(newTagData)

        return Image3.createImage3FromTags(self.type, typeTag + [(tagMagic, tagTotalSize, tagDataSize, newTagData)] + versTag + sepoTag + bordTag + kbagTag + shshTag + certTag)
