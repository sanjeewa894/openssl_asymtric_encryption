#ifndef ASYMETRIC_ENCRYPTION_H
#define ASYMETRIC_ENCRYPTION_H

#include <QFile>
#include <QObject>
#include <openssl/err.h>
#include <openssl/pem.h>

class AsymetricEncryption : public QObject {
    Q_OBJECT

  public:
    explicit AsymetricEncryption (QObject *parent = nullptr);
    ~AsymetricEncryption();

    void decryptFile (const QString &inputFilePath, const QString &outputFilePath);
    void encryptFile (const QString &inputFilePath, const QString &outputFilePath);
    void generateKeyPair();
    QString getErrorFromEVPHandler();

  private:
    int keySize = 2048;

    void runEncryption (QFile &inFile, QFile &outFile);
    void runDecryption (QFile &inFile, QFile &outFile);
    void generateEncryptData (QFile &inFile, EVP_CIPHER_CTX *ctx, QByteArray &outData);
    void generateDecryptData (QFile &inFile, EVP_CIPHER_CTX *ctx, QByteArray &outData);

    unsigned char *publicKey=nullptr;
    unsigned char *privateKey =nullptr;

};

#endif // ASYMETRIC_ENCRYPTION_H
