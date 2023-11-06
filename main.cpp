#include <QCoreApplication>
#include <QDebug>
#include "asymetric_encryption.h"

const QString inputFile = "input.txt";
const QString encryptedFile = "encrypted.enc";
const QString decryptedFile = "decrypted.txt";

void checkAsymetric() {
  AsymetricEncryption opnessl;
  opnessl.generateKeyPair();
  opnessl.encryptFile (inputFile, encryptedFile);

  /*****************************Decript*************************************/
  opnessl.decryptFile (encryptedFile, decryptedFile);

}


int main (int argc, char *argv[]) {
  QCoreApplication a (argc, argv);

  checkAsymetric();

  return 0;
}
