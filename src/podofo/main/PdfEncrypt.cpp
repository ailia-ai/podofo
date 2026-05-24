#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "PdfEncrypt.h"
#include <podofo/private/PdfDeclarationsPrivate.h>

#include "PdfDictionary.h"
#include "PdfFilter.h"

#include <podofo/auxiliary/AES.h>
#include <podofo/auxiliary/SHA.h>

#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>
using boost::uuids::detail::md5;

# define MD5_DIGEST_LENGTH 16

# define DUMP_API_CALL
//# define DUMP_API_CALL printf("%s %d\n", __FUNCTION__, __LINE__);

using namespace std;
using namespace PoDoFo;

PdfEncryptAlgorithm PdfEncrypt::s_EnabledEncryptionAlgorithms =
PdfEncryptAlgorithm::RC4V1 |
PdfEncryptAlgorithm::RC4V2 |
PdfEncryptAlgorithm::AESV2 |
PdfEncryptAlgorithm::AESV3 |
PdfEncryptAlgorithm::AESV3R6;

#define AES_IV_LENGTH 16
#define AES_BLOCK_SIZE 16

static void MD5Final(unsigned char * dst, unsigned char *src){
    for (int i = 0; i < MD5_DIGEST_LENGTH; i+=4){
        dst[i + 0] = src [i + 3];
        dst[i + 1] = src [i + 2];
        dst[i + 2] = src [i + 1];
        dst[i + 3] = src [i + 0];
    }
}


/** A class that can encrypt/decrpyt streamed data block wise
 *  This is used in the input and output stream encryption implementation.
 *  Only the RC4 encryption algorithm is supported
 */
class PdfRC4Stream
{
public:
    PdfRC4Stream(unsigned char rc4key[256], unsigned char rc4last[256],
        unsigned char* key, unsigned keylen) :
        m_a(0), m_b(0)
    {
        size_t i;
        size_t j;
        size_t t;

        if (std::memcmp(key, rc4key, keylen) != 0)
        {
            for (i = 0; i < 256; i++)
                m_rc4[i] = static_cast<unsigned char>(i);

            j = 0;
            for (i = 0; i < 256; i++)
            {
                t = static_cast<size_t>(m_rc4[i]);
                j = (j + t + static_cast<size_t>(key[i % keylen])) % 256;
                m_rc4[i] = m_rc4[j];
                m_rc4[j] = static_cast<unsigned char>(t);
            }

            std::memcpy(rc4key, key, keylen);
            std::memcpy(rc4last, m_rc4, 256);
        }
        else
        {
            std::memcpy(m_rc4, rc4last, 256);
        }
    }

    ~PdfRC4Stream()
    {
    }

    /** Encrypt or decrypt a block
     *
     *  \param buffer the input/output buffer. Data is read from this buffer and also stored here
     *  \param len    the size of the buffer
     */
    size_t Encrypt(char* buffer, size_t len)
    {
        unsigned char k;
        int t;

        // Do not encode data with no length
        if (len == 0)
            return len;

        for (size_t i = 0; i < len; i++)
        {
            m_a = (m_a + 1) % 256;
            t = m_rc4[m_a];
            m_b = (m_b + t) % 256;

            m_rc4[m_a] = m_rc4[m_b];
            m_rc4[m_b] = static_cast<unsigned char>(t);

            k = m_rc4[(m_rc4[m_a] + m_rc4[m_b]) % 256];
            buffer[i] = buffer[i] ^ k;
        }

        return len;
    }

private:
    unsigned char m_rc4[256];

    int m_a;
    int m_b;

};

/** An InputStream that decrypts all data read
 *  using the RC4 encryption algorithm
 */
class PdfRC4InputStream : public InputStream
{
public:
    PdfRC4InputStream(InputStream& inputStream, size_t inputLen, unsigned char rc4key[256], unsigned char rc4last[256],
        unsigned char* key, unsigned keylen) :
        m_InputStream(&inputStream),
        m_inputLen(inputLen),
        m_stream(rc4key, rc4last, key, keylen) { }

protected:
    size_t readBuffer(char* buffer, size_t size, bool& eof) override
    {
        // CHECK-ME: The code has never been tested after refactor
        // If it's correct, remove this warning
        bool streameof;
        size_t count = ReadBuffer(*m_InputStream, buffer, std::min(size, m_inputLen), streameof);
        m_inputLen -= count;
        eof = streameof || m_inputLen == 0;
        return m_stream.Encrypt(buffer, count);
    }

private:
    InputStream* m_InputStream;
    size_t m_inputLen;
    PdfRC4Stream m_stream;
};

/** A PdfAESInputStream that decrypts all data read
 *  using the AES encryption algorithm
 */
class PdfAESInputStream : public InputStream
{
public:
    PdfAESInputStream(InputStream& inputStream, size_t inputLen, unsigned char* key, unsigned keylen) :
        m_InputStream(&inputStream),
        m_inputLen(inputLen),
        m_inputEof(false),
        m_init(true),
        m_keyLen(keylen),
        m_drainLeft(0)
    {
        std::memcpy(this->m_key, key, keylen);
    }

protected:
    size_t readBuffer(char* buffer, size_t len, bool& eof) override
    {
        int outlen = 0;
        size_t read;

        // if (m_inputEof)
        //     goto DrainBuffer;

        int rc;
        if (m_init)
        {
            // Read the initialization vector separately first
            char iv[AES_IV_LENGTH];
            bool streameof;
            read = ReadBuffer(*m_InputStream, iv, AES_IV_LENGTH, streameof);
            if (read != AES_IV_LENGTH)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnexpectedEOF, "Can't read enough bytes for AES IV");

            switch (m_keyLen)
            {
                case (size_t)PdfKeyLength::L128 / 8:
                {
                    m_aes = AES(AESKeyLength::AES_128);
                    break;
                }
                case (size_t)PdfKeyLength::L256 / 8:
                {
                    m_aes = AES(AESKeyLength::AES_256);
                    break;
                }
                default:
                    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Invalid AES key length");
            }

            m_aes.DecryptCBCInit(m_key, (unsigned char*)iv);

            m_inputLen -= AES_IV_LENGTH;
            m_init = false;
        }

        bool streameof;
        read = ReadBuffer(*m_InputStream, buffer, std::min(len, m_inputLen), streameof);
        m_inputLen -= read;

        unsigned char *tempBuffer = m_aes.DecryptCBC((unsigned char*)buffer, (unsigned int)read);
        outlen = read;

        PODOFO_ASSERT((size_t)outlen <= len);
        std::memcpy(buffer, tempBuffer, (size_t)outlen);

        delete[] tempBuffer;

        if (m_inputLen == 0 || streameof)
        {
            uint8_t paddingLen = buffer[outlen - 1];
            outlen -= paddingLen;

            eof = true;
            return outlen;
        }

        eof = false;
        return outlen;
    }

private:
    // EVP_CIPHER_CTX* m_ctx;
    InputStream* m_InputStream;
    size_t m_inputLen;
    bool m_inputEof;
    bool m_init;
    unsigned char m_key[32];
    unsigned m_keyLen;
    vector<unsigned char> m_tempBuffer;
    size_t m_drainLeft;
    AES m_aes;
};

PoDoFo::PdfEncrypt::~PdfEncrypt()
{
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::Create(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection, PdfEncryptAlgorithm algorithm, PdfKeyLength keyLength)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::CreateFromObject(const PdfObject &encryptObj)
{
    DUMP_API_CALL

    if (!encryptObj.GetDictionary().HasKey(PdfName::KeyFilter) ||
        encryptObj.GetDictionary().GetKey(PdfName::KeyFilter)->GetName() != "Standard")
    {
        if (encryptObj.GetDictionary().HasKey(PdfName::KeyFilter))
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnsupportedFilter, "Unsupported encryption filter: {}",
                encryptObj.GetDictionary().GetKey(PdfName::KeyFilter)->GetName().GetString());
        else
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnsupportedFilter, "Encryption dictionary does not have a key /Filter");
    }

    int lV;
    int64_t length;
    int rValue;
    PdfPermissions pValue;
    PdfString oValue;
    PdfString uValue;
    PdfName cfmName;
    bool encryptMetadata = true;

    try
    {
        lV = static_cast<int>(encryptObj.GetDictionary().MustGetKey("V").GetNumber());
        rValue = static_cast<int>(encryptObj.GetDictionary().MustGetKey("R").GetNumber());

        pValue = static_cast<PdfPermissions>(encryptObj.GetDictionary().MustGetKey("P").GetNumber());

        oValue = encryptObj.GetDictionary().MustGetKey("O").GetString();
        uValue = encryptObj.GetDictionary().MustGetKey("U").GetString();

        if (encryptObj.GetDictionary().HasKey("Length"))
            length = encryptObj.GetDictionary().GetKey("Length")->GetNumber();
        else
            length = 0;

        const PdfObject* encryptMetadataObj = encryptObj.GetDictionary().GetKey("EncryptMetadata");
        if (encryptMetadataObj != nullptr && encryptMetadataObj->IsBool())
            encryptMetadata = encryptMetadataObj->GetBool();

        auto stmfObj = encryptObj.GetDictionary().GetKey("StmF");
        if (stmfObj != nullptr && stmfObj->IsName())
        {
            const PdfObject* obj = encryptObj.GetDictionary().GetKey("CF");
            if (obj != nullptr && obj->IsDictionary())
            {
                obj = obj->GetDictionary().GetKey(stmfObj->GetName());
                if (obj != nullptr && obj->IsDictionary())
                {
                    obj = obj->GetDictionary().GetKey("CFM");
                    if (obj != nullptr && obj->IsName())
                        cfmName = obj->GetName();
                }
            }
        }
    }
    catch (PdfError& e)
    {
        PODOFO_PUSH_FRAME_INFO(e, "Invalid or missing key in encryption dictionary");
        throw e;
    }

    if ((lV == 1) && (rValue == 2 || rValue == 3)
        && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::RC4V1))
    {
        return unique_ptr<PdfEncrypt>(new PdfEncryptRC4(oValue, uValue, pValue, rValue, PdfEncryptAlgorithm::RC4V1, (int)PdfKeyLength::L40, encryptMetadata));
    }
    else if ((((lV == 2) && (rValue == 3)) || cfmName == "V2")
        && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::RC4V2))
    {
        // length is int64_t. Please make changes in encryption algorithms
        // Check key length length here to prevent
        // stack-based buffer over-read later in this file
        if (length > MD5_DIGEST_LENGTH * CHAR_BIT) // length in bits, md5 in bytes
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::ValueOutOfRange, "Given key length too large for MD5");
        }
        return unique_ptr<PdfEncrypt>(new PdfEncryptRC4(oValue, uValue, pValue, rValue, PdfEncryptAlgorithm::RC4V2, static_cast<int>(length), encryptMetadata));
    }
    else
    {
        if ((lV == 4) && (rValue == 4)
            && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::AESV2))
        {
            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV2(oValue, uValue, pValue, encryptMetadata));
        }
        else if ((lV == 5) && (
            (rValue == 5 && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::AESV3))
            || (rValue == 6 && PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm::AESV3R6))))
        {
            PdfString permsValue = encryptObj.GetDictionary().MustFindKey("Perms").GetString();
            PdfString oeValue = encryptObj.GetDictionary().MustFindKey("OE").GetString();
            PdfString ueValue = encryptObj.GetDictionary().MustFindKey("UE").GetString();

            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV3(oValue, oeValue, uValue,
                ueValue, pValue, permsValue, (PdfAESV3Revision)rValue));
        }
        else
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::UnsupportedFilter, "Unsupported encryption method Version={} Revision={}", lV , rValue);
        }
    }
}

std::unique_ptr<PdfEncrypt> PoDoFo::PdfEncrypt::CreateFromEncrypt(const PdfEncrypt &rhs)
{
    DUMP_API_CALL

    switch (rhs.m_Algorithm)
    {
        case PdfEncryptAlgorithm::RC4V1:
        case PdfEncryptAlgorithm::RC4V2:
            return unique_ptr<PdfEncrypt>(new PdfEncryptRC4(rhs));
        case PdfEncryptAlgorithm::AESV2:
            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV2(rhs));
        case PdfEncryptAlgorithm::AESV3:
        case PdfEncryptAlgorithm::AESV3R6:
            return unique_ptr<PdfEncrypt>(new PdfEncryptAESV3(rhs));
        default:
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEnumValue, "Invalid algorithm");
    }
}

PdfEncryptAlgorithm PoDoFo::PdfEncrypt::GetEnabledEncryptionAlgorithms()
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::SetEnabledEncryptionAlgorithms(PdfEncryptAlgorithm nEncryptionAlgorithms)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEncryptionEnabled(PdfEncryptAlgorithm algorithm)
{
    DUMP_API_CALL
    return (PdfEncrypt::s_EnabledEncryptionAlgorithms & algorithm) != PdfEncryptAlgorithm::None;
}

void PoDoFo::PdfEncrypt::GenerateEncryptionKey(const PdfString &documentId)
{
    DUMP_API_CALL
    GenerateEncryptionKey(documentId.GetRawData());
}

bool PoDoFo::PdfEncrypt::Authenticate(const std::string_view &password, const PdfString &documentId)
{
    DUMP_API_CALL
    return Authenticate(password, documentId.GetRawData());
}

bool PoDoFo::PdfEncrypt::IsPrintAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEditAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsCopyAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsEditNotesAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsFillAndSignAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsAccessibilityAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsDocAssemblyAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

bool PoDoFo::PdfEncrypt::IsHighPrintAllowed() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

int PoDoFo::PdfEncrypt::GetKeyLength() const
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncrypt::EncryptTo(charbuff &out, const bufferview &view, const PdfReference &objref) const
{
    DUMP_API_CALL
    size_t outputLen = this->CalculateStreamLength(view.size());
    out.resize(outputLen);
    this->Encrypt(view.data(), view.size(), objref, out.data(), outputLen);
}

void PoDoFo::PdfEncrypt::DecryptTo(charbuff &out, const bufferview &view, const PdfReference &objref) const
{
    // FIX-ME: The following clearly seems hardcoded for AES
    // It was found like this in PdfString and PdfTokenizer
    // Fix it so it will allocate the exact amount of memory
    // needed, including RC4
    size_t outBufferLen = view.size() - this->CalculateStreamOffset();
    out.resize(outBufferLen + 16 - (outBufferLen % 16));
    this->Decrypt(view.data(), view.size(), objref, out.data(), outBufferLen);
    out.resize(outBufferLen);
    out.shrink_to_fit();
}

PoDoFo::PdfEncrypt::PdfEncrypt() :
    m_Algorithm(PdfEncryptAlgorithm::AESV2),
    m_eKeyLength(PdfKeyLength::L128),
    m_keyLength(0),
    m_rValue(0),
    m_pValue(PdfPermissions::None),
    m_EncryptMetadata(true)
{
    DUMP_API_CALL
    memset(m_uValue, 0, 48);
    memset(m_oValue, 0, 48);
    memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncrypt::PdfEncrypt(const PdfEncrypt &rhs)
{
    DUMP_API_CALL
    m_Algorithm = rhs.m_Algorithm;
    m_eKeyLength = rhs.m_eKeyLength;

    m_pValue = rhs.m_pValue;
    m_rValue = rhs.m_rValue;

    m_keyLength = rhs.m_keyLength;

    m_documentId = rhs.m_documentId;
    m_userPass = rhs.m_userPass;
    m_ownerPass = rhs.m_ownerPass;
    m_EncryptMetadata = rhs.m_EncryptMetadata;
}

bool PoDoFo::PdfEncrypt::CheckKey(unsigned char key1[32], unsigned char key2[32])
{
    DUMP_API_CALL

    // Check whether the right password had been given
    bool success = true;
    for (unsigned k = 0; success && k < m_keyLength; k++)
        success = success && (key1[k] == key2[k]);
    
    return success;
}

PoDoFo::PdfEncryptSHABase::PdfEncryptSHABase()
    : m_ueValue{ }, m_oeValue{ }, m_permsValue{ }
{
}

PoDoFo::PdfEncryptSHABase::PdfEncryptSHABase(const PdfEncrypt &rhs) : PdfEncrypt(rhs)
{
    const PdfEncrypt* ptr = &rhs;
    std::memcpy(m_uValue, rhs.GetUValue(), sizeof(unsigned char) * 48);
    std::memcpy(m_oValue, rhs.GetOValue(), sizeof(unsigned char) * 48);
    std::memcpy(m_encryptionKey, rhs.GetEncryptionKey(), sizeof(unsigned char) * 32);
    std::memcpy(m_permsValue, static_cast<const PdfEncryptSHABase*>(ptr)->m_permsValue, sizeof(unsigned char) * 16);
    std::memcpy(m_ueValue, static_cast<const PdfEncryptSHABase*>(ptr)->m_ueValue, sizeof(unsigned char) * 32);
    std::memcpy(m_oeValue, static_cast<const PdfEncryptSHABase*>(ptr)->m_oeValue, sizeof(unsigned char) * 32);
}

void PoDoFo::PdfEncryptSHABase::CreateEncryptionDictionary(PdfDictionary &dictionary) const
{
    dictionary.AddKey(PdfName::KeyFilter, PdfName("Standard"));

    PdfDictionary cf;
    PdfDictionary stdCf;

    dictionary.AddKey("V", static_cast<int64_t>(5));
    dictionary.AddKey("R", static_cast<int64_t>(m_rValue));
    dictionary.AddKey("Length", static_cast<int64_t>(256));

    stdCf.AddKey("CFM", PdfName("AESV3"));
    stdCf.AddKey("Length", static_cast<int64_t>(32));

    dictionary.AddKey("O", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetOValue()), 48 }));
    dictionary.AddKey("OE", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetOEValue()), 32 }));
    dictionary.AddKey("U", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetUValue()), 48 }));
    dictionary.AddKey("UE", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetUEValue()), 32 }));
    dictionary.AddKey("Perms", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetPermsValue()), 16 }));

    stdCf.AddKey("AuthEvent", PdfName("DocOpen"));
    cf.AddKey("StdCF", stdCf);

    dictionary.AddKey("CF", cf);
    dictionary.AddKey("StrF", PdfName("StdCF"));
    dictionary.AddKey("StmF", PdfName("StdCF"));

    dictionary.AddKey("P", PdfVariant(static_cast<int64_t>(this->GetPValue())));
}

bool PoDoFo::PdfEncryptSHABase::Authenticate(const std::string_view &documentID, const std::string_view &password, const bufferview &uValue, const std::string_view &ueValue, const bufferview &oValue, const std::string_view &oeValue, PdfPermissions pValue, const std::string_view &permsValue, int lengthValue, int rValue)
{
    m_pValue = pValue;
    m_keyLength = lengthValue / 8;
    m_rValue = rValue;

    std::memcpy(m_uValue, uValue.data(), 48);
    std::memcpy(m_ueValue, ueValue.data(), 32);
    std::memcpy(m_oValue, oValue.data(), 48);
    std::memcpy(m_oeValue, oeValue.data(), 32);
    std::memcpy(m_permsValue, permsValue.data(), 16);

    return Authenticate(password, documentID);
}

void PoDoFo::PdfEncryptSHABase::GenerateInitialVector(unsigned char iv[]) const
{
    for (unsigned i = 0; i < AES_IV_LENGTH; i++)
        iv[i] = rand() % 255;
}

void PoDoFo::PdfEncryptSHABase::ComputeEncryptionKey()
{
    srand((unsigned)time(nullptr));
    for (unsigned i = 0; i < m_keyLength; i++)
        m_encryptionKey[i] = rand() % 255;
}

void PoDoFo::PdfEncryptSHABase::ComputeHash(const unsigned char *pswd, unsigned pswdLen, unsigned char salt[8], unsigned char uValue[48], unsigned char hashValue[32])
{
    PODOFO_ASSERT(pswdLen <= 127);

    // Initial SHA-256 hash: password + salt + uValue(optional)
    SHA256 sha256;
    if (pswdLen != 0)
        sha256.update(pswd, pswdLen);
    sha256.update(salt, 8);
    if (uValue != nullptr)
        sha256.update(uValue, 48);
    sha256.final(hashValue);

    if (m_rValue > 5) // R6: extended hash algorithm per PDF 2.0
    {
        unsigned dataLen = 0;
        unsigned blockLen = 32;
        unsigned char data[(127 + 64 + 48) * 64];
        unsigned char block[64];
        std::memcpy(block, hashValue, 32);

        for (unsigned i = 0; i < 64 || i < (unsigned)(32 + data[dataLen - 1]); i++)
        {
            dataLen = pswdLen + blockLen;
            std::memcpy(data, pswd, pswdLen);
            std::memcpy(data + pswdLen, block, blockLen);
            if (uValue)
            {
                std::memcpy(data + dataLen, uValue, 48);
                dataLen += 48;
            }
            for (unsigned j = 1; j < 64; j++)
                std::memcpy(data + j * dataLen, data, dataLen);

            unsigned totalDataLen = dataLen * 64;

            // AES-128-CBC encrypt with key=block[0..15], iv=block[16..31]
            AES aes(AESKeyLength::AES_128);
            unsigned char *encrypted = aes.EncryptCBC(data, totalDataLen, block, block + 16);
            std::memcpy(data, encrypted, totalDataLen);
            dataLen = totalDataLen;
            delete[] encrypted;

            unsigned sum = 0;
            for (unsigned j = 0; j < 16; j++)
                sum += data[j];
            blockLen = 32 + (sum % 3) * 16;

            if (blockLen == 32)
            {
                SHA256::hash(data, dataLen, block);
            }
            else if (blockLen == 48)
            {
                SHA384::hash(data, dataLen, block);
            }
            else
            {
                SHA512::hash(data, dataLen, block);
            }
        }
        std::memcpy(hashValue, block, 32);
    }
}

void PoDoFo::PdfEncryptSHABase::ComputeUserKey(const unsigned char *userpswd, unsigned len)
{
    // Generate User Salts
    unsigned char vSalt[8];
    unsigned char kSalt[8];
    for (unsigned i = 0; i < 8; i++)
    {
        vSalt[i] = rand() % 255;
        kSalt[i] = rand() % 255;
    }

    unsigned char hashValue[32];
    ComputeHash(userpswd, len, vSalt, 0, hashValue);

    std::memcpy(m_uValue, hashValue, 32);
    std::memcpy(m_uValue + 32, vSalt, 8);
    std::memcpy(m_uValue + 32 + 8, kSalt, 8);

    // UE = AES-256 encrypted file encryption key
    ComputeHash(userpswd, len, kSalt, 0, hashValue);
    unsigned char iv[AES_IV_LENGTH];
    std::memset(iv, 0, AES_IV_LENGTH);
    AES aes(AESKeyLength::AES_256);
    unsigned char *encrypted = aes.EncryptCBC(m_encryptionKey, m_keyLength, hashValue, iv);
    std::memcpy(m_ueValue, encrypted, 32);
    delete[] encrypted;
}

void PoDoFo::PdfEncryptSHABase::ComputeOwnerKey(const unsigned char *ownerpswd, unsigned len)
{
    unsigned char vSalt[8];
    unsigned char kSalt[8];
    for (unsigned i = 0; i < 8; i++)
    {
        vSalt[i] = rand() % 255;
        kSalt[i] = rand() % 255;
    }

    unsigned char hashValue[32];
    ComputeHash(ownerpswd, len, vSalt, m_uValue, hashValue);

    std::memcpy(m_oValue, hashValue, 32);
    std::memcpy(m_oValue + 32, vSalt, 8);
    std::memcpy(m_oValue + 32 + 8, kSalt, 8);

    ComputeHash(ownerpswd, len, kSalt, m_uValue, hashValue);
    unsigned char iv[AES_IV_LENGTH];
    std::memset(iv, 0, AES_IV_LENGTH);
    AES aes(AESKeyLength::AES_256);
    unsigned char *encrypted = aes.EncryptCBC(m_encryptionKey, m_keyLength, hashValue, iv);
    std::memcpy(m_oeValue, encrypted, 32);
    delete[] encrypted;
}

void PoDoFo::PdfEncryptSHABase::PreprocessPassword(const std::string_view &password, unsigned char *outBuf, unsigned &len)
{
    // Simplified SASLprep: just truncate to 127 bytes
    size_t l = password.size();
    len = l > 127 ? 127 : (unsigned)l;
    std::memcpy(outBuf, password.data(), len);
}

PoDoFo::PdfEncryptAESBase::~PdfEncryptAESBase()
{
    DUMP_API_CALL
}

PoDoFo::PdfEncryptAESBase::PdfEncryptAESBase()
{
    DUMP_API_CALL
}

void PoDoFo::PdfEncryptAESBase::BaseDecrypt(const unsigned char *key, unsigned keylen, const unsigned char *iv, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t &textoutlen) const
{
    DUMP_API_CALL

    AES aes(keylen == (unsigned)((int)PdfKeyLength::L256 / 8) ? AESKeyLength::AES_256 : AESKeyLength::AES_128);
    unsigned char *tmp = aes.DecryptCBC(textin, textlen, key, iv);
    uint8_t paddingLen = tmp[textlen - 1];
    textoutlen = textlen - paddingLen;
    std::memcpy(textout, tmp, textoutlen);
    delete[] tmp;
}

void PoDoFo::PdfEncryptAESBase::BaseEncrypt(const unsigned char *key, unsigned keyLen, const unsigned char *iv, const unsigned char *textin, size_t textlen, unsigned char *textout, size_t textoutlen) const
{
    DUMP_API_CALL
    (void)textoutlen;

    AES aes;
    if (keyLen == (int)PdfKeyLength::L128 / 8)
        aes = AES(AESKeyLength::AES_128);
    else if (keyLen == (int)PdfKeyLength::L256 / 8)
        aes = AES(AESKeyLength::AES_256);
    else
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Invalid AES key length");

    unsigned int paddingLen = AES_BLOCK_SIZE - (textlen % AES_BLOCK_SIZE);
    unsigned int dataLenWithPadding = textlen + paddingLen;
    std::unique_ptr<unsigned char[]> dataWithPadding(new unsigned char[dataLenWithPadding]);
    std::memcpy(dataWithPadding.get(), textin, textlen);
    
    for (unsigned int i = 0; i < paddingLen; i++) {
        dataWithPadding[textlen + i] = paddingLen;
    }

    unsigned char *tempBuffer = aes.EncryptCBC(dataWithPadding.get(), dataLenWithPadding, key, iv);

    std::memcpy(textout, tempBuffer, (size_t)dataLenWithPadding);

    delete[] tempBuffer;
}

PoDoFo::PdfEncryptRC4Base::~PdfEncryptRC4Base()
{
    DUMP_API_CALL
}

PoDoFo::PdfEncryptRC4Base::PdfEncryptRC4Base()
{
    DUMP_API_CALL
}

typedef struct {
    unsigned char s[256];
    unsigned char i;
    unsigned char j;
} RC4_STATE;

void rc4_init(RC4_STATE* state, const unsigned char* key, unsigned keylen) {
    unsigned char tmp;
    int i;
    unsigned char j = 0;

    for (i = 0; i < 256; i++) {
        state->s[i] = (unsigned char)i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + state->s[i] + key[i % keylen]) % 256;
        tmp = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = tmp;
    }

    state->i = 0;
    state->j = 0;
}

void rc4_encrypt(RC4_STATE* state, const unsigned char* textin, size_t textlen, unsigned char* textout) {
    size_t dataOutMoved = 0;

    for (size_t k = 0; k < textlen; k++) {
        state->i = (state->i + 1) % 256;
        state->j = (state->j + state->s[state->i]) % 256;

        unsigned char tmp = state->s[state->i];
        state->s[state->i] = state->s[state->j];
        state->s[state->j] = tmp;

        unsigned char c = (state->s[state->i] + state->s[state->j]) % 256;
        textout[k] = textin[k] ^ state->s[c];
        dataOutMoved++;
    }
}

void PdfEncryptRC4Base::RC4(const unsigned char* key, unsigned keylen,
    const unsigned char* textin, size_t textlen,
    unsigned char* textout, size_t textoutlen) const
{
    if (textlen != textoutlen)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing RC4 encryption engine");

    DUMP_API_CALL

    RC4_STATE state;
    rc4_init(&state, key, keylen);
    rc4_encrypt(&state, textin, textlen, textout);
}

PoDoFo::PdfEncryptMD5Base::PdfEncryptMD5Base() : m_rc4key{ }, m_rc4last{ }
{
    DUMP_API_CALL
}

PoDoFo::PdfEncryptMD5Base::PdfEncryptMD5Base(const PdfEncrypt& rhs) : PdfEncrypt(rhs)
{
    DUMP_API_CALL
    const PdfEncrypt* ptr = &rhs;

    std::memcpy(m_uValue, rhs.GetUValue(), sizeof(unsigned char) * 32);
    std::memcpy(m_oValue, rhs.GetOValue(), sizeof(unsigned char) * 32);

    std::memcpy(m_encryptionKey, rhs.GetEncryptionKey(), sizeof(unsigned char) * 16);

    std::memcpy(m_rc4key, static_cast<const PdfEncryptMD5Base*>(ptr)->m_rc4key, sizeof(unsigned char) * 16);
    std::memcpy(m_rc4last, static_cast<const PdfEncryptMD5Base*>(ptr)->m_rc4last, sizeof(unsigned char) * 256);
    m_EncryptMetadata = static_cast<const PdfEncryptMD5Base*>(ptr)->m_EncryptMetadata;
}

void PoDoFo::PdfEncryptMD5Base::CreateEncryptionDictionary(PdfDictionary &dictionary) const
{
    DUMP_API_CALL
    dictionary.AddKey(PdfName::KeyFilter, PdfName("Standard"));

    if (m_Algorithm == PdfEncryptAlgorithm::AESV2 || !m_EncryptMetadata)
    {
        PdfDictionary cf;
        PdfDictionary stdCf;

        if (m_Algorithm == PdfEncryptAlgorithm::RC4V2)
            stdCf.AddKey("CFM", PdfName("V2"));
        else
            stdCf.AddKey("CFM", PdfName("AESV2"));
        stdCf.AddKey("Length", static_cast<int64_t>(16));

        dictionary.AddKey("O", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetOValue()), 32 }));
        dictionary.AddKey("U", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetUValue()), 32 }));

        stdCf.AddKey("AuthEvent", PdfName("DocOpen"));
        cf.AddKey("StdCF", stdCf);

        dictionary.AddKey("CF", cf);
        dictionary.AddKey("StrF", PdfName("StdCF"));
        dictionary.AddKey("StmF", PdfName("StdCF"));

        dictionary.AddKey("V", static_cast<int64_t>(4));
        dictionary.AddKey("R", static_cast<int64_t>(4));
        dictionary.AddKey("Length", static_cast<int64_t>(128));
        if (!m_EncryptMetadata)
            dictionary.AddKey("EncryptMetadata", PdfVariant(false));
    }
    else if (m_Algorithm == PdfEncryptAlgorithm::RC4V1)
    {
        dictionary.AddKey("V", static_cast<int64_t>(1));
        // Can be 2 or 3
        dictionary.AddKey("R", static_cast<int64_t>(m_rValue));
    }
    else if (m_Algorithm == PdfEncryptAlgorithm::RC4V2)
    {
        dictionary.AddKey("V", static_cast<int64_t>(2));
        dictionary.AddKey("R", static_cast<int64_t>(3));
        dictionary.AddKey("Length", PdfVariant(static_cast<int64_t>(m_eKeyLength)));
    }

    dictionary.AddKey("O", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetOValue()), 32 }));
    dictionary.AddKey("U", PdfString::FromRaw({ reinterpret_cast<const char*>(this->GetUValue()), 32 }));
    dictionary.AddKey("P", PdfVariant(static_cast<int64_t>(this->GetPValue())));
}

PdfString PoDoFo::PdfEncryptMD5Base::GetMD5String(const unsigned char *buffer, unsigned length)
{
    DUMP_API_CALL

    char data[MD5_DIGEST_LENGTH] = "";

    GetMD5Binary(buffer, length, reinterpret_cast<unsigned char*>(data));

    return PdfString::FromRaw({ data, MD5_DIGEST_LENGTH });

}

void PoDoFo::PdfEncryptMD5Base::GetMD5Binary(const unsigned char *data, unsigned length, unsigned char *digest)
{
    DUMP_API_CALL
    md5 hash;
    md5::digest_type digest2;
    hash.process_bytes(data, length);
    hash.get_digest(digest2);
    MD5Final(digest, (unsigned char*)digest2);
}

bool PoDoFo::PdfEncryptMD5Base::Authenticate(const std::string_view &documentID, const std::string_view &password, const bufferview &uValue, const bufferview &oValue, PdfPermissions pValue, int lengthValue, int rValue)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptMD5Base::GenerateInitialVector(unsigned char iv[]) const
{
    DUMP_API_CALL
    GetMD5Binary(reinterpret_cast<const unsigned char*>(m_documentId.c_str()),
        static_cast<unsigned>(m_documentId.length()), iv);
}

void PoDoFo::PdfEncryptMD5Base::ComputeOwnerKey(const unsigned char userPad[32], const unsigned char ownerPad[32], int keylength, int revision, bool authenticate, unsigned char ownerKey[32])
{
    DUMP_API_CALL

    unsigned char mkey[MD5_DIGEST_LENGTH];
    unsigned char digest[MD5_DIGEST_LENGTH];
    int rc;

    md5 hash;
    md5::digest_type digest2;

    /*
    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (ctx == nullptr || (rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr)) != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

    rc = EVP_DigestUpdate(ctx.get(), ownerPad, 32);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

    rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    */

    hash.process_bytes(ownerPad, 32);
    hash.get_digest(digest2);
    MD5Final(digest, (unsigned char*)digest2);

    if ((revision == 3) || (revision == 4))
    {
        // only use for the input as many bit as the key consists of
        for (int k = 0; k < 50; ++k)
        {
            /*
            rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

            rc = EVP_DigestUpdate(ctx.get(), digest, keyLength);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

            rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
            */

            md5 hash2;
            hash2.process_bytes(ownerPad, 32);
            hash2.get_digest(digest2);
            MD5Final(digest, (unsigned char*)digest2);
        }
        std::memcpy(ownerKey, userPad, 32);
        for (unsigned i = 0; i < 20; ++i)
        {
            for (int j = 0; j < keylength; ++j)
            {
                if (authenticate)
                    mkey[j] = static_cast<unsigned char>(static_cast<unsigned>(digest[j] ^ (19 - i)));
                else
                    mkey[j] = static_cast<unsigned char>(static_cast<unsigned>(digest[j] ^ i));
            }
            RC4(mkey, keylength, ownerKey, 32, ownerKey, 32);
        }
    }
    else
    {
        RC4(digest, 5, userPad, 32, ownerKey, 32);
    }
}

static unsigned char padding[] =
"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

void PoDoFo::PdfEncryptMD5Base::PadPassword(const std::string_view &password, unsigned char pswd[32])
{
    DUMP_API_CALL

    size_t m = password.length();

    if (m > 32) m = 32;

    size_t j;
    size_t p = 0;
    for (j = 0; j < m; j++)
        pswd[p++] = static_cast<unsigned char>(password[j]);

    for (j = 0; p < 32 && j < 32; j++)
        pswd[p++] = padding[j];
}

void PoDoFo::PdfEncryptMD5Base::ComputeEncryptionKey(const std::string_view &documentId, const unsigned char userPad[32], const unsigned char ownerKey[32], PdfPermissions pValue, PdfKeyLength keyLength, int revision, unsigned char userKey[32], bool encryptMetadata)
{
    DUMP_API_CALL

    unsigned j;
    unsigned k;
    m_keyLength = (int)keyLength / 8;
    int rc;

    md5 hash;
    md5::digest_type digest2;

    /*
    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (ctx == nullptr || (rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr)) != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

    rc = EVP_DigestUpdate(ctx.get(), userPad, 32);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

    rc = EVP_DigestUpdate(ctx.get(), ownerKey, 32);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    */

    hash.process_bytes(userPad, 32);
    hash.process_bytes(ownerKey, 32);

    unsigned char ext[4];
    ext[0] = static_cast<unsigned char> (((unsigned)pValue >> 0) & 0xFF);
    ext[1] = static_cast<unsigned char> (((unsigned)pValue >> 8) & 0xFF);
    ext[2] = static_cast<unsigned char> (((unsigned)pValue >> 16) & 0xFF);
    ext[3] = static_cast<unsigned char> (((unsigned)pValue >> 24) & 0xFF);
    
    /*
    rc = EVP_DigestUpdate(ctx.get(), ext, 4);
    if (rc != 1)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    */
    hash.process_bytes(ext, 4);

    unsigned docIdLength = static_cast<unsigned>(documentId.length());
    vector<unsigned char> docId;
    if (docIdLength > 0)
    {
        docId.resize(docIdLength);
        for (j = 0; j < docIdLength; j++)
        {
            docId[j] = static_cast<unsigned char>(documentId[j]);
        }
        //rc = EVP_DigestUpdate(ctx.get(), docId.data(), docIdLength);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
        hash.process_bytes(docId.data(), docIdLength);
    }

    // If document metadata is not being encrypted, 
    // pass 4 bytes with the value 0xFFFFFFFF to the MD5 hash function.
    if (!encryptMetadata)
    {
        unsigned char noMetaAddition[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        //rc = EVP_DigestUpdate(ctx.get(), noMetaAddition, 4);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
        hash.process_bytes(noMetaAddition, 4);
    }

    unsigned char digest[MD5_DIGEST_LENGTH];
    //rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
    //if (rc != 1)
    //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
    hash.get_digest(digest2);
    MD5Final(digest, (unsigned char*)digest2);

    // only use the really needed bits as input for the hash
    if (revision == 3 || revision == 4)
    {
        for (k = 0; k < 50; ++k)
        {
            /*
            rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

            rc = EVP_DigestUpdate(ctx.get(), digest, m_keyLength);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

            rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
            if (rc != 1)
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");
            */
            md5 hash2;
            hash2.process_bytes(digest, m_keyLength);
            hash2.get_digest(digest2);
            MD5Final(digest, (unsigned char*)digest2);
        }
    }

    std::memcpy(m_encryptionKey, digest, m_keyLength);

    // Setup user key
    if (revision == 3 || revision == 4)
    {
        md5 hash3;

        //rc = EVP_DigestInit_ex(ctx.get(), s_SSL.MD5, nullptr);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error initializing MD5 hashing engine");

        //rc = EVP_DigestUpdate(ctx.get(), padding, 32);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

        hash3.process_bytes(padding, 32);

        if (docId.size() != 0)
        {
            //rc = EVP_DigestUpdate(ctx.get(), docId.data(), docIdLength);
            //if (rc != 1)
            //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

            hash3.process_bytes(docId.data(), docIdLength);
        }

        //rc = EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
        //if (rc != 1)
        //    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Error MD5-hashing data");

        hash3.get_digest(digest2);
        MD5Final(digest, (unsigned char*)digest2);

        std::memcpy(userKey, digest, 16);
        for (k = 16; k < 32; k++)
            userKey[k] = 0;

        for (k = 0; k < 20; k++)
        {
            for (j = 0; j < m_keyLength; j++)
            {
                digest[j] = static_cast<unsigned char>(m_encryptionKey[j] ^ k);
            }

            RC4(digest, m_keyLength, userKey, 16, userKey, 16);
        }
    }
    else
    {
        RC4(m_encryptionKey, m_keyLength, padding, 32, userKey, 32);
    }
}

void PoDoFo::PdfEncryptMD5Base::CreateObjKey(unsigned char objkey[16], unsigned &pnKeyLen, const PdfReference &objref) const
{
    DUMP_API_CALL

    const unsigned n = static_cast<unsigned>(objref.ObjectNumber());
    const unsigned g = static_cast<unsigned>(objref.GenerationNumber());

    unsigned nkeylen = m_keyLength + 5;
    unsigned char nkey[MD5_DIGEST_LENGTH + 5 + 4];
    for (unsigned j = 0; j < m_keyLength; j++)
        nkey[j] = m_encryptionKey[j];

    nkey[m_keyLength + 0] = static_cast<unsigned char>(0xFF & n);
    nkey[m_keyLength + 1] = static_cast<unsigned char>(0xFF & (n >> 8));
    nkey[m_keyLength + 2] = static_cast<unsigned char>(0xFF & (n >> 16));
    nkey[m_keyLength + 3] = static_cast<unsigned char>(0xFF & g);
    nkey[m_keyLength + 4] = static_cast<unsigned char>(0xFF & (g >> 8));

    if (m_Algorithm == PdfEncryptAlgorithm::AESV2)
    {
        // AES encryption needs some 'salt'
        nkeylen += 4;
        nkey[m_keyLength + 5] = 0x73;
        nkey[m_keyLength + 6] = 0x41;
        nkey[m_keyLength + 7] = 0x6C;
        nkey[m_keyLength + 8] = 0x54;
    }

    GetMD5Binary(nkey, nkeylen, objkey);
    pnKeyLen = (m_keyLength <= 11) ? m_keyLength + 5 : 16;
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(PdfString oValue, PdfString uValue, PdfPermissions pValue, bool bEncryptMetadata)
{
    DUMP_API_CALL
    m_pValue = pValue;
    m_Algorithm = PdfEncryptAlgorithm::AESV2;

    m_eKeyLength = PdfKeyLength::L128;
    m_keyLength = (int)PdfKeyLength::L128 / 8;
    m_rValue = 4;
    m_EncryptMetadata = bEncryptMetadata;

    auto& oValueData = oValue.GetRawData();
    if (oValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/O value is invalid");

    auto& uValueData = uValue.GetRawData();
    if (uValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/U value is invalid");

    std::memcpy(m_oValue, oValueData.data(), 32);
    std::memcpy(m_uValue, uValueData.data(), 32);

    // Init buffers
    std::memset(m_rc4key, 0, 16);
    std::memset(m_rc4last, 0, 256);
    std::memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptAESV2::PdfEncryptAESV2(const PdfEncrypt &rhs)
    : PdfEncryptMD5Base(rhs)
{
    DUMP_API_CALL
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptAESV2::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    this->CreateObjKey(objkey, keylen, objref);
    return unique_ptr<InputStream>(new PdfAESInputStream(inputStream, inputLen, objkey, keylen));
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptAESV2::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

void PoDoFo::PdfEncryptAESV2::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    CreateObjKey(objkey, keylen, objref);
    size_t offset = CalculateStreamOffset();
    this->GenerateInitialVector((unsigned char *)outStr);
    this->BaseEncrypt(objkey, keylen, (unsigned char*)outStr, (const unsigned char*)inStr,
        inLen, (unsigned char*)outStr + offset, outLen - offset);
}

void PoDoFo::PdfEncryptAESV2::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    CreateObjKey(objkey, keylen, objref);

    size_t offset = CalculateStreamOffset();
    if (inLen <= offset)
    {
        // Is empty
        outLen = 0;
        return;
    }

    this->BaseDecrypt(objkey, keylen, (const unsigned char*)inStr,
        (const unsigned char*)inStr + offset,
        inLen - offset, (unsigned char*)outStr, outLen);
}

size_t PoDoFo::PdfEncryptAESV2::CalculateStreamOffset() const
{
    DUMP_API_CALL
    return AES_IV_LENGTH;
}

size_t PoDoFo::PdfEncryptAESV2::CalculateStreamLength(size_t length) const
{
    DUMP_API_CALL
    size_t realLength = ((length + 15) & ~15) + AES_IV_LENGTH;
    if (length % 16 == 0)
        realLength += 16;

    return realLength;
}

void PoDoFo::PdfEncryptAESV2::GenerateEncryptionKey(const std::string_view &documentId)
{
    DUMP_API_CALL
    unsigned char userpswd[32];
    unsigned char ownerpswd[32];

    // Pad passwords
    PadPassword(m_userPass, userpswd);
    PadPassword(m_ownerPass, ownerpswd);

    // Compute O value
    ComputeOwnerKey(userpswd, ownerpswd, m_keyLength, m_rValue, false, m_oValue);

    // Compute encryption key and U value
    m_documentId = documentId;
    ComputeEncryptionKey(m_documentId, userpswd,
        m_oValue, m_pValue, m_eKeyLength, m_rValue, m_uValue, m_EncryptMetadata);
}

bool PoDoFo::PdfEncryptAESV2::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    DUMP_API_CALL
    m_documentId = documentId;

    // Pad password
    unsigned char pswd[32];
    PadPassword(password, pswd);

    // Check password: 1) as user password, 2) as owner password
    unsigned char userKey[32];
    ComputeEncryptionKey(m_documentId, pswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);

    bool success = CheckKey(userKey, m_uValue);
    if (success)
    {
        m_userPass = password;
    }
    else
    {
        unsigned char userpswd[32];
        ComputeOwnerKey(m_oValue, pswd, m_keyLength, m_rValue, true, userpswd);
        ComputeEncryptionKey(m_documentId, userpswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);
        success = CheckKey(userKey, m_uValue);

        if (success)
            m_ownerPass = password;
    }

    return success;
}

PoDoFo::PdfEncryptAESV3::PdfEncryptAESV3(PdfString oValue, PdfString oeValue, PdfString uValue, PdfString ueValue, PdfPermissions pValue, PdfString permsValue, PdfAESV3Revision rev)
    : PdfEncryptAESBase()
{
    m_pValue = pValue;
    m_Algorithm = rev == PdfAESV3Revision::R6 ? PdfEncryptAlgorithm::AESV3R6 : PdfEncryptAlgorithm::AESV3;

    m_eKeyLength = PdfKeyLength::L256;
    m_keyLength = (int)PdfKeyLength::L256 / 8;
    m_rValue = (int)rev;

    auto& oValueData = oValue.GetRawData();
    if (oValueData.size() < 48)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/O value is invalid");

    auto& oeValueData = oeValue.GetRawData();
    if (oeValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/OE value is invalid");

    auto& uValueData = uValue.GetRawData();
    if (uValueData.size() < 48)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/U value is invalid");

    auto& ueValueData = ueValue.GetRawData();
    if (ueValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/UE value is invalid");

    auto& permsValueData = permsValue.GetRawData();
    if (permsValueData.size() < 16)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/Perms value is invalid");

    std::memcpy(m_oValue, oValueData.data(), 48);
    std::memcpy(m_oeValue, oeValueData.data(), 32);
    std::memcpy(m_uValue, uValueData.data(), 48);
    std::memcpy(m_ueValue, ueValueData.data(), 32);
    std::memcpy(m_permsValue, permsValueData.data(), 16);
    std::memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncryptAESV3::PdfEncryptAESV3(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfAESV3Revision rev, PdfPermissions protection)
    : PdfEncryptAESBase()
{
    m_userPass = userPassword;
    m_ownerPass = ownerPassword;
    m_Algorithm = rev == PdfAESV3Revision::R6 ? PdfEncryptAlgorithm::AESV3R6 : PdfEncryptAlgorithm::AESV3;

    m_rValue = (int)rev;
    m_eKeyLength = PdfKeyLength::L256;
    m_keyLength = (int)PdfKeyLength::L256 / 8;

    std::memset(m_oValue, 0, 48);
    std::memset(m_uValue, 0, 48);
    std::memset(m_encryptionKey, 0, 32);
    std::memset(m_ueValue, 0, 32);
    std::memset(m_oeValue, 0, 32);

    m_pValue = PdfPermissions::Default | protection;
}

PoDoFo::PdfEncryptAESV3::PdfEncryptAESV3(const PdfEncrypt &rhs)
    : PdfEncryptSHABase(rhs) {}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptAESV3::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    (void)objref;
    return unique_ptr<InputStream>(new PdfAESInputStream(inputStream, inputLen, m_encryptionKey, 32));
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptAESV3::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    (void)outputStream;
    (void)objref;
    PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "CreateEncryptionOutputStream does not yet support AESV3");
}

void PoDoFo::PdfEncryptAESV3::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    (void)objref;
    size_t offset = CalculateStreamOffset();
    this->GenerateInitialVector((unsigned char*)outStr);
    this->BaseEncrypt(m_encryptionKey, m_keyLength, (unsigned char*)outStr, (const unsigned char*)inStr, inLen, (unsigned char*)outStr + offset, outLen - offset);
}

void PoDoFo::PdfEncryptAESV3::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    (void)objref;
    size_t offset = CalculateStreamOffset();
    if (inLen <= offset)
    {
        outLen = 0;
        return;
    }
    this->BaseDecrypt(const_cast<unsigned char*>(m_encryptionKey), m_keyLength, (const unsigned char*)inStr, (const unsigned char*)inStr + offset, inLen - offset, (unsigned char*)outStr, outLen);
}

size_t PoDoFo::PdfEncryptAESV3::CalculateStreamOffset() const
{
    return AES_IV_LENGTH;
}

size_t PoDoFo::PdfEncryptAESV3::CalculateStreamLength(size_t length) const
{
    size_t realLength = ((length + 15) & ~15) + AES_IV_LENGTH;
    if (length % 16 == 0)
        realLength += 16;
    return realLength;
}

bool PoDoFo::PdfEncryptAESV3::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    (void)documentId;
    bool success = false;

    unsigned char pswd_sasl[127];
    unsigned pswdLen;
    PreprocessPassword(password, pswd_sasl, pswdLen);

    // Test 1: is it the user key?
    unsigned char hashValue[32];
    ComputeHash(pswd_sasl, pswdLen, m_uValue + 32, 0, hashValue); // user Validation Salt

    success = CheckKey(hashValue, m_uValue);
    if (!success)
    {
        // Test 2: is it the owner key?
        ComputeHash(pswd_sasl, pswdLen, m_oValue + 32, m_uValue, hashValue); // owner Validation Salt
        success = CheckKey(hashValue, m_oValue);

        if (success)
        {
            m_ownerPass = password;
            ComputeHash(pswd_sasl, pswdLen, m_oValue + 40, m_uValue, hashValue); // owner Key Salt

            // Decrypt OE to get file encryption key
            unsigned char iv[AES_IV_LENGTH];
            std::memset(iv, 0, AES_IV_LENGTH);
            AES aes(AESKeyLength::AES_256);
            unsigned char *decrypted = aes.DecryptCBC(m_oeValue, 32, hashValue, iv);
            std::memcpy(m_encryptionKey, decrypted, 32);
            delete[] decrypted;
        }
    }
    else
    {
        m_userPass = password;
        ComputeHash(pswd_sasl, pswdLen, m_uValue + 40, 0, hashValue); // user Key Salt

        // Decrypt UE to get file encryption key
        unsigned char iv[AES_IV_LENGTH];
        std::memset(iv, 0, AES_IV_LENGTH);
        AES aes(AESKeyLength::AES_256);
        unsigned char *decrypted = aes.DecryptCBC(m_ueValue, 32, hashValue, iv);
        std::memcpy(m_encryptionKey, decrypted, 32);
        delete[] decrypted;
    }

    return success;
}

void PoDoFo::PdfEncryptAESV3::GenerateEncryptionKey(const std::string_view &documentId)
{
    (void)documentId;

    unsigned char userpswd[127];
    unsigned char ownerpswd[127];
    unsigned userpswdLen;
    unsigned ownerpswdLen;
    PreprocessPassword(m_userPass, userpswd, userpswdLen);
    PreprocessPassword(m_ownerPass, ownerpswd, ownerpswdLen);

    ComputeEncryptionKey();
    ComputeUserKey(userpswd, userpswdLen);
    ComputeOwnerKey(ownerpswd, ownerpswdLen);

    // Compute Perms value
    unsigned char perms[16];
    perms[3] = ((unsigned)m_pValue >> 24) & 0xFF;
    perms[2] = ((unsigned)m_pValue >> 16) & 0xFF;
    perms[1] = ((unsigned)m_pValue >> 8) & 0xFF;
    perms[0] = ((unsigned)m_pValue >> 0) & 0xFF;
    perms[4] = 0xFF;
    perms[5] = 0xFF;
    perms[6] = 0xFF;
    perms[7] = 0xFF;
    perms[8] = m_EncryptMetadata ? 'T' : 'F';
    perms[9] = 'a';
    perms[10] = 'd';
    perms[11] = 'b';
    perms[12] = 0;
    perms[13] = 0;
    perms[14] = 0;
    perms[15] = 0;

    unsigned char iv[AES_IV_LENGTH];
    std::memset(iv, 0, AES_IV_LENGTH);
    AES aes(AESKeyLength::AES_256);
    unsigned char *encrypted = aes.EncryptCBC(perms, 16, m_encryptionKey, iv);
    std::memcpy(m_permsValue, encrypted, 16);
    delete[] encrypted;
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(PdfString oValue, PdfString uValue, PdfPermissions pValue, int rValue, PdfEncryptAlgorithm algorithm, int length, bool encryptMetadata)
{
    DUMP_API_CALL

    m_pValue = pValue;
    m_rValue = rValue;
    m_Algorithm = algorithm;
    m_eKeyLength = static_cast<PdfKeyLength>(length);
    m_keyLength = length / 8;
    m_EncryptMetadata = encryptMetadata;

    auto& oValueData = oValue.GetRawData();
    if (oValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/O value is invalid");

    auto& uValueData = uValue.GetRawData();
    if (uValueData.size() < 32)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidEncryptionDict, "/U value is invalid");

    std::memcpy(m_oValue, oValueData.data(), 32);
    std::memcpy(m_uValue, uValueData.data(), 32);

    // Init buffers
    std::memset(m_rc4key, 0, 16);
    std::memset(m_rc4last, 0, 256);
    std::memset(m_encryptionKey, 0, 32);
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(const std::string_view &userPassword, const std::string_view &ownerPassword, PdfPermissions protection, PdfEncryptAlgorithm algorithm, PdfKeyLength keyLength)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

PoDoFo::PdfEncryptRC4::PdfEncryptRC4(const PdfEncrypt &rhs)
    : PdfEncryptMD5Base(rhs)
{
    DUMP_API_CALL
}

void PoDoFo::PdfEncryptRC4::Encrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t outLen) const
{
    DUMP_API_CALL
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    CreateObjKey(objkey, keylen, objref);
    this->RC4(objkey, keylen, (const unsigned char *)inStr, inLen,
        (unsigned char*)outStr, outLen);
}

void PoDoFo::PdfEncryptRC4::Decrypt(const char *inStr, size_t inLen, const PdfReference &objref, char *outStr, size_t &outLen) const
{
    DUMP_API_CALL
    Encrypt(inStr, inLen, objref, outStr, outLen);
}

std::unique_ptr<InputStream> PoDoFo::PdfEncryptRC4::CreateEncryptionInputStream(InputStream &inputStream, size_t inputLen, const PdfReference &objref)
{
    DUMP_API_CALL

    (void)inputLen;
    unsigned char objkey[MD5_DIGEST_LENGTH];
    unsigned keylen;
    this->CreateObjKey(objkey, keylen, objref);
    return unique_ptr<InputStream>(new PdfRC4InputStream(inputStream, inputLen, m_rc4key, m_rc4last, objkey, keylen));
}

std::unique_ptr<OutputStream> PoDoFo::PdfEncryptRC4::CreateEncryptionOutputStream(OutputStream &outputStream, const PdfReference &objref)
{
    DUMP_API_CALL
    PODOFO_RAISE_ERROR(PdfErrorCode::UnsupportedEncryptedFile);
}

size_t PoDoFo::PdfEncryptRC4::CalculateStreamOffset() const
{
    DUMP_API_CALL
    return 0;
}

size_t PoDoFo::PdfEncryptRC4::CalculateStreamLength(size_t length) const
{
    DUMP_API_CALL
    return length;
}

void PoDoFo::PdfEncryptRC4::GenerateEncryptionKey(const std::string_view &documentId)
{
    DUMP_API_CALL

    unsigned char userpswd[32];
    unsigned char ownerpswd[32];

    // Pad passwords
    PadPassword(m_userPass, userpswd);
    PadPassword(m_ownerPass, ownerpswd);

    // Compute O value
    ComputeOwnerKey(userpswd, ownerpswd, m_keyLength, m_rValue, false, m_oValue);

    // Compute encryption key and U value
    m_documentId = documentId;
    ComputeEncryptionKey(m_documentId, userpswd,
        m_oValue, m_pValue, m_eKeyLength, m_rValue, m_uValue, m_EncryptMetadata);
}

bool PoDoFo::PdfEncryptRC4::Authenticate(const std::string_view &password, const std::string_view &documentId)
{
    DUMP_API_CALL

    bool success = false;

    m_documentId = documentId;

    // Pad password
    unsigned char userKey[32];
    unsigned char pswd[32];
    PadPassword(password, pswd);

    // Check password: 1) as user password, 2) as owner password
    ComputeEncryptionKey(m_documentId, pswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);

    success = CheckKey(userKey, m_uValue);
    if (!success)
    {
        unsigned char userpswd[32];
        ComputeOwnerKey(m_oValue, pswd, m_keyLength, m_rValue, true, userpswd);
        ComputeEncryptionKey(m_documentId, userpswd, m_oValue, m_pValue, m_eKeyLength, m_rValue, userKey, m_EncryptMetadata);
        success = CheckKey(userKey, m_uValue);
        if (success)
            m_ownerPass = password;
    }
    else
        m_userPass = password;

    return success;
}

#pragma GCC diagnostic pop