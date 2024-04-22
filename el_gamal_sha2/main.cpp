#include <iostream>
#include "el_gamal.h"

using namespace std;

int main()
{
    ElGamal el;
    string some_text = "Hello, world!";
    cout << "Open key: " << el.get_open_key() << endl;
    cout << "Private key: " << el.get_private_key() << endl;

    cout << "####################### ENCRYPTION / DECRYPTION #######################" << endl << endl;
    vector<CHIPHER_TEXT> chipher(el.encrypt(some_text));
    cout << "Chpher text: ";
    for (const CHIPHER_TEXT& chip : chipher)
        cout << chip << " ";
    cout << "\n\nDecrypted text: " << el.decrypt(chipher) << endl << endl;

    cout << "############################## SIGNATURE ##############################" << endl << endl;
    SIGNATURE sign = el.create_signature(some_text);
    cout << "Signature: " << sign << endl << endl;

    //„тобы проверить правильность проверки подписи, нужно расскоментировать одну/две/три строки
    //sign.r += 1;
    //sign.s *= 2;
    //sign.hash -= 1;

    if (el.check_signature(sign))
        cout << "Signature is correct" << endl;
    else
        cout << "Signature is incorrect" << endl;


    
    return 0;
}