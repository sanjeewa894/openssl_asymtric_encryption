/**
 * @copyright Copyright (c) by Versatile Ag.
 *            All rights reserved.
 *  Author: skumara@versatile-ag.com
*/
#include "asymetric_encryption.h"
#include <QDebug>

AsymetricEncryption::AsymetricEncryption (QObject *parent)
  : QObject{parent} {

}

AsymetricEncryption::~AsymetricEncryption(){
  if(privateKey)
    free(privateKey);
  if(publicKey)
    free(publicKey);
}

/**
 * @brief AsymetricEncryption::generateKeyPair -- generate public and private keys
 */
void AsymetricEncryption::generateKeyPair() {
  // create private/public key pair
  // init RSA context, so we can generate a key pair
  EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init (keyCtx);
  EVP_PKEY_CTX_set_rsa_keygen_bits (keyCtx, keySize); // RSA 4096
  // variable that will hold both private and public keys
  EVP_PKEY *key = nullptr;
  EVP_PKEY_keygen (keyCtx, &key);// generate key
  EVP_PKEY_CTX_free (keyCtx);// free up key context

  // extract private key as string
  BIO *privateBIO = BIO_new (BIO_s_mem());
  PEM_write_bio_PrivateKey (privateBIO, key, nullptr, nullptr, 0, nullptr, nullptr); // dump key to IO

  int const privateKeyLen = BIO_pending (privateBIO);// get buffer length
  // create char reference of private key length
  auto *privateKeyChar = static_cast<unsigned char *> (malloc (privateKeyLen));
  // read the key from the buffer and put it in the char reference
  BIO_read (privateBIO, privateKeyChar, privateKeyLen);
  BIO_free_all (privateBIO);
  // at this point we can save the private key somewhere
  privateKey = privateKeyChar;

  // extract public key as string
  BIO *publicBIO = BIO_new (BIO_s_mem()); 
  PEM_write_bio_PUBKEY (publicBIO, key); // dump key to IO
  int const publicKeyLen = BIO_pending (publicBIO);// get buffer length
  // create char reference of public key length
  auto *publicKeyChar = static_cast<unsigned char *> (malloc (publicKeyLen));
  // read the key from the buffer and put it in the char reference
  BIO_read (publicBIO, publicKeyChar, publicKeyLen);
  BIO_free_all (publicBIO);
  // at this point we can save the public somewhere
  publicKey = publicKeyChar;
  EVP_PKEY_free (key);
}


/**
 * @brief AsymetricEncryption::encryptFile --  encrypt plain file and write it to file
 * @param inFile -- input plain file
 * @param outFile -- encripted file
 */
void AsymetricEncryption::encryptFile (const QString &inputFilePath, const QString &outputFilePath) {

  QFile inFile (inputFilePath);
  QFile outFile (outputFilePath);

  if (!inFile.open (QIODevice::ReadOnly)) {
    qDebug()<< "Failed to open input file" << __LINE__;
    return;
  }
  if (!outFile.open (QIODevice::WriteOnly)) {
    qDebug()<< "Failed to open output file for encrypt" << __LINE__;
    return;
  }

  if(publicKey==nullptr){
    qDebug()<< "Public key is empty!" << __LINE__;
    return;
  }

  runEncryption (inFile, outFile);
  inFile.close();
  outFile.close();
  qDebug() << "Encryption successfully completed.";

}

/**
 * @brief AsymetricEncryption::runEncryptionProcess -- create and initialize the EVP handler, save ek and iv to file,
 * get encrypted data and write to file
 * @param inFile -- input file
 * @param outFile -- output file
 */
void AsymetricEncryption::runEncryption (QFile &inFile,  QFile &outFile) {
  //Create new BIO...BIO is an I/O stream abstraction
  BIO *bo = BIO_new (BIO_s_mem());
  //Allocates an empty EVP_PKEY structure which is used by OpenSSL to store public and private keys
  EVP_PKEY *evpKey = EVP_PKEY_new();
  BIO_puts (bo, reinterpret_cast<const char *> (publicKey));  //public
  //read a public key in PEM format using an EVP_PKEY structure
  evpKey = PEM_read_bio_PUBKEY (bo, nullptr, nullptr, nullptr);

  BIO_free (bo); //free allocated BIO
  if (evpKey == nullptr) {
    qDebug()<< "PEM_read_bio_PUBKEY failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //creates a cipher context and initialise.
  if (ctx == nullptr) {
    EVP_PKEY_free (evpKey);
    qDebug()<< "EVP_CIPHER_CTX_new failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }
  int ekLen = 0;
  // variables for where the encrypted secret, length, and IV reside
  unsigned char *iv = static_cast<unsigned char *> (malloc (EVP_MAX_IV_LENGTH)); //create initialization vector (IV)
  //ek is array of buffers where the public key encrypted secret key will be written
  unsigned char *ek = static_cast<unsigned char *> (malloc (EVP_PKEY_size (evpKey)));

  /* Initialise the envelope seal operation. This operation generates a key for the provided cipher,
  * and then encrypts that key a number of times. This operation also generates an IV and places it in iv.
  */
  if (EVP_SealInit (ctx, EVP_aes_256_cbc(), &ek, &ekLen, iv, &evpKey, 1) != 1) {
    EVP_CIPHER_CTX_free (ctx);
    EVP_PKEY_free (evpKey);
    free (iv);
    free (ek);
    qDebug()<<"EVP_SealInit failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  //save ek and iv in the encypted file to use for decription.. it required to initialize the enlope. otherwise it will fail.
  outFile.write (reinterpret_cast<char *> (ek), ekLen);
  outFile.write ((char *)iv, EVP_MAX_IV_LENGTH);

  QByteArray outData;
  outData.reserve (inFile.size() + EVP_CIPHER_CTX_block_size (ctx)); //reserve size of array
  generateEncryptData (inFile, ctx, outData); //encrypt data
  outFile.write (outData); //write encry
  EVP_CIPHER_CTX_free (ctx);
  EVP_PKEY_free (evpKey);
  free (iv);
  free (ek);

}



/**
 * @brief AsymetricEncryption::getEncryptedData -- encrypt data and save to outdata array
 * @param inFile -- inuput Qfile
 * @param ctx -- EVP context
 */
void AsymetricEncryption::generateEncryptData (QFile &inFile, EVP_CIPHER_CTX *ctx, QByteArray &outData) {
  QByteArray inData;
  int totalOut = 0, outLength = 0;
  /* Provide the message to be encrypted, and obtain the encrypted output.
  * EVP_SealUpdate can be called multiple times if necessary
  * encrypt file with key size block... read remaining data up to key size
  */
  while ((inData = inFile.read (keySize)).size() > 0) {
    if (EVP_SealUpdate (ctx, reinterpret_cast<unsigned char *> (outData.data()), &outLength,
                        reinterpret_cast<const unsigned char *> (inData.constData()), inData.size()) != 1) {
      qDebug() << "EVP_SealUpdate failed. " << getErrorFromEVPHandler() << __LINE__;
      return;
    }
    totalOut += outLength; //count total encrypted data to be written
  }

  outData.resize (outLength); //resize the bytearray to encrypted size
  //Finalise the encryption. Further ciphertext bytes may be written at this stage.
  if (EVP_SealFinal (ctx, reinterpret_cast<unsigned char *> (outData.data()) + totalOut, &outLength) != 1) {
    qDebug()<< "EVP_SealFinal failed. " << getErrorFromEVPHandler()<< __LINE__;
    return;
  }
  totalOut += outLength;
  outData.resize (totalOut); //resize the bytearray to encrypted size
}

/**
 * @brief AsymetricEncryption::decryptFile -- decrypt encripted file and write it to file
 * @param inFile -- encripted file
 * @param outFile -- decrypt file
 */
void AsymetricEncryption::decryptFile (const QString &inputFilePath, const QString &outputFilePath) {

  QFile inFile (inputFilePath);
  QFile outFile (outputFilePath);

  if (!inFile.open (QIODevice::ReadOnly)) {
    qDebug()<< "Failed to open encrypted input file" << __LINE__;
    return;
  }
  if (!outFile.open (QIODevice::WriteOnly)) {
    qDebug()<< "Failed to open output file for decrypt" << __LINE__;
    return;
  }

  if(privateKey==nullptr){
    qDebug()<< "Private key is empty!" << __LINE__;
    return;
  }

  runDecryption (inFile, outFile);
  inFile.close();
  outFile.close();
  qDebug() << "Decryption successfully completed.";
}

/**
 * @brief AsymetricEncryption::runDecryptionProcess -- create and initialize the EVP handler, read ek and iv from file,
 * get decrypted data and write to file
 * @param inFile -- input file
 * @param outFile -- output file
 */
void AsymetricEncryption::runDecryption (QFile &inFile, QFile &outFile) {
  //Create new BIO...BIO is an I/O stream abstraction
  BIO *bo = BIO_new (BIO_s_mem());
  //Allocates an empty EVP_PKEY structure which is used by OpenSSL to store public and private keys
  EVP_PKEY *evpKey = EVP_PKEY_new();
  BIO_puts (bo, reinterpret_cast<const char *> (privateKey));//private key
  //read a private key in PEM format using an EVP_PKEY structure
  evpKey = PEM_read_bio_PrivateKey (bo, nullptr, nullptr, nullptr);

  BIO_free (bo); //free allocated BIO
  if (evpKey == nullptr) {
    qDebug()<< "PEM_read_bio_privKey failed"  << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  // Create and initialise the context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    EVP_PKEY_free (evpKey);
    qDebug()<< "EVP_CIPHER_CTX_new failed. "  << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  // variables for where the encrypted secret, length, and IV reside
  int ekLen = EVP_PKEY_size (evpKey);
  unsigned char *ek = static_cast<unsigned char *> (malloc (ekLen));
  unsigned char *iv = static_cast<unsigned char *> (malloc (EVP_MAX_IV_LENGTH));
  inFile.read (reinterpret_cast<char *> (ek), ekLen); //read the encription key saved when encripted
  inFile.read (reinterpret_cast<char *> (iv), EVP_MAX_IV_LENGTH); //read IV saved when encrypt

  /* Initialise the decryption operation. The asymmetric private key is
  * provided and priv_key, whilst the encrypted session key is held in
  * encrypted_key */
  if (EVP_OpenInit (ctx, EVP_aes_256_cbc(), ek, ekLen, iv, evpKey) != 1) {
    EVP_CIPHER_CTX_free (ctx);
    EVP_PKEY_free (evpKey);
    free (iv);
    free (ek);
    qDebug() << "EVP_OpenInit failed. " << getErrorFromEVPHandler() << __LINE__;
    return;
  }

  QByteArray outData;
  outData.reserve (inFile.size() + EVP_CIPHER_CTX_block_size (ctx));
  generateDecryptData (inFile, ctx, outData); //decrypt data
  outFile.write (outData); //write decripted data
  EVP_CIPHER_CTX_free (ctx);
  EVP_PKEY_free (evpKey);
  free (iv);
  free (ek);
}

/**
 * @brief AsymetricEncryption::generateDecryptData -- decrypt passed input file and save into array
 * @param inFile -- encrypted file
 * @param ctx -- evp contex
 */
void AsymetricEncryption::generateDecryptData (QFile &inFile, EVP_CIPHER_CTX *ctx, QByteArray &outData) {
  QByteArray inData;
  int totalOut = 0, outLength = 0;

  /* Provide the message to be decrypted, and obtain the plaintext output.
  * EVP_OpenUpdate can be called multiple times if necessary
  */
  while ((inData = inFile.read (keySize)).size() > 0) {
    if (EVP_OpenUpdate (ctx, reinterpret_cast<unsigned char *> (outData.data()), &outLength, reinterpret_cast<const unsigned char *> (inData.constData()), inData.size()) != 1) {
      qDebug() << "EVP_OpenUpdate failed. " << getErrorFromEVPHandler() << __LINE__;
      return;
    }
    totalOut += outLength;
  }

  outData.resize (totalOut);

  //Finalise the decryption. Further plaintext bytes may be written atthis stage.
  if (EVP_OpenFinal (ctx, reinterpret_cast<unsigned char *> (outData.data()) + totalOut, &outLength) != 1) {
    qDebug()<<"EVP_OpenFinal failed. " << getErrorFromEVPHandler()<< __LINE__;
    return;
  }

  totalOut += outLength;
  outData.resize (totalOut); //resize the array to decrypted length
}


/**
 * @brief AsymetricEncryption::getErrorFromEVP -- get all the error messsages when executing EVP functions
 * @return -- Error message received from EVP
 */
QString AsymetricEncryption::getErrorFromEVPHandler() {
  QString errorMsg;
  int line, flags;
  unsigned long e = 0;
  const char *file = nullptr, *func = nullptr, *data = nullptr;

  while ((e = ERR_get_error_all (&file, &line, &func, &data, &flags)) != 0) {
    errorMsg += "Error: " + QString (ERR_lib_error_string (e)) + ":"
                + ERR_reason_error_string (e) + ":" + file
                + ':' + func + ':' + QString::number(line) + "\n";
  }
  return errorMsg;
}


