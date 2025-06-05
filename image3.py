import binascii
import struct
import dfuexec
import utilities

class Image3:
    def __init__(self, data):
        (self.magic, self.totalSize, self.dataSize, self.signedSize, self.type) = struct.unpack('>4s3I4s', data[0:20])
        self.tags = []
        pos = 20
        while pos < 20 + self.dataSize:
            (tagMagic, tagTotalSize, tagDataSize) = struct.unpack('>4s2I', data[pos:pos+12])
            self.tags.append((tagMagic, tagTotalSize, tagDataSize, data[pos+12:pos+tagTotalSize]))
            pos += tagTotalSize
            if tagTotalSize == 0:
                break

    @staticmethod
    def createImage3FromTags(img_type, tags):
        dataSize = 0
        signedSize = 0
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in tags:
            dataSize += 12 + len(tagData)
            if tagMagic[::-1].decode('utf-8') not in ['CERT', 'SHSH']:
                signedSize += 12 + len(tagData)

        totalSize = 20 + dataSize
        remainder = totalSize % 64
        if remainder != 0:
            totalSize += 64 - remainder

        header = struct.pack('>4s3I4s', b'3gmI', totalSize, dataSize, signedSize, img_type)
        bytes_data = header
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in tags:
            bytes_data += struct.pack('>4s2I', tagMagic, tagTotalSize, tagDataSize) + tagData
        return bytes_data + b'\x00' * (totalSize - len(bytes_data))

    def getTags(self, magic):
        return [tag for tag in self.tags if tag[0] == magic]

    def getKeybag(self):
        keybags = self.getTags(b'GABK')
        for (tagMagic, tagTotalSize, tagDataSize, tagData) in keybags:
            (kbag_type, aes_type) = struct.unpack('>2I', tagData[:8])
            if kbag_type == 1:
                return tagData[8:8+48]
        return None

    def getPayload(self):
        data = self.getTags(b'ATAD')
        if len(data) == 1:
            return data[0][3]
        return None

    def getDecryptedPayload(self):
        keybag = self.getKeybag()
        device = dfuexec.PwnedDFUDevice()
        decrypted_keybag = device.decrypt_keybag(keybag)
        return utilities.aes_decrypt(
            self.getPayload(),
            binascii.hexlify(decrypted_keybag[:16]),
            binascii.hexlify(decrypted_keybag[16:])
        )

    def shrink24KpwnCertificate(self):
        for i, tag in enumerate(self.tags):
            if tag[0] == b'TREC' and len(tag[3]) >= 3072:
                data = tag[3][:3072]
                if data[-1] == 0:
                    data = data.rstrip(b'\x00')
                    self.tags[i] = (b'TREC', 12 + len(data), len(data), data)
                break

    def newImage3(self, decrypted=True):
        typeTag = self.getTags(b'EPYT')
        assert len(typeTag) == 1
        versTag = self.getTags(b'SREV')
        assert len(versTag) <= 1
        dataTag = self.getTags(b'ATAD')
        assert len(dataTag) == 1
        sepoTag = self.getTags(b'OPES')
        assert len(sepoTag) <= 2
        bordTag = self.getTags(b'DROB')
        assert len(bordTag) <= 2
        kbagTag = self.getTags(b'GABK')
        assert len(kbagTag) <= 2
        shshTag = self.getTags(b'HSHS')
        assert len(shshTag) <= 1
        certTag = self.getTags(b'TREC')
        assert len(certTag) <= 1

        (tagMagic, tagTotalSize, tagDataSize, tagData) = dataTag[0]
        if kbagTag and decrypted:
            newTagData = self.getDecryptedPayload()
            kbagTag = []
        else:
            newTagData = tagData

        assert len(tagData) == len(newTagData)

        return Image3.createImage3FromTags(self.type, typeTag + [(tagMagic, tagTotalSize, tagDataSize, newTagData)] + versTag + sepoTag + bordTag + kbagTag + shshTag + certTag)
