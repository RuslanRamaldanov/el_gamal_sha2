#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random/mersenne_twister.hpp>
#include "sha256.h"
#include <iostream>
#include "el_gamal.h"
using namespace boost::multiprecision;
using namespace std;
///////////////////////////////////////////////////////////////////////////
std::ostream& operator<<(std::ostream& stream, const CHIPHER_TEXT& chipher_block)
{
    stream << "[" << chipher_block.a << ", " << chipher_block.b << "]";
    return stream;
}
std::ostream& operator<<(std::ostream& stream, const OPEN_KEY& key)
{
    stream << "{" << key.p << ", " << key.g << ", " << key.y << "}";
    return stream;
}
std::ostream& operator<<(std::ostream& stream, const SIGNATURE& sign)
{
    stream << "<" << sign.r << ", " << sign.s << ">";
    return stream;
}
///////////////////////////////////////////////////////////////////////////
cpp_int ElGamal::get_random_number(const cpp_int&& l, const cpp_int&& r)
{
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(l, r);
    return dist(gen);
}
cpp_int ElGamal::generate_primary_number()
{
	cpp_int candidate;
	while (!miller_rabin_test(candidate, 25))
		candidate = get_random_number(1 << 9, 1 << 10); //генерируем простое число в пределах от 2^10 до 2^15
	return candidate;
}

cpp_int ElGamal::generate_primitive_root(const cpp_int& p)
{
    for (cpp_int g = 2; g < p; ++g) {
        bool is_primitive_root = true;
        for (cpp_int i = 1; i < p - 1; ++i) {
            cpp_int power = powm(g, i, p);
            if (power == 1) {
                is_primitive_root = false;
                break;
            }
        }
        if (is_primitive_root) {
            return g;
        }
    }
    return -1;
}

void ElGamal::generate_keys()
{
    cpp_int p = generate_primary_number();  //простое число
    cpp_int g = generate_primitive_root(p); //первообразный корень
    priv_key = get_random_number(1, p - 1); //приватный ключ
    cpp_int y = powm(g, priv_key, p);       //g^x mod p

    open_key.g = g;
    open_key.p = p;
    open_key.y = y;
}

cpp_int ElGamal::multm(cpp_int a, cpp_int b, const cpp_int& mod)
{
    while (a < 0)
        a += mod;
    while (b < 0)
        b += mod;
    return (a * b) % mod;
}
vector<CHIPHER_TEXT> ElGamal::encrypt(const string& text)
{
    cpp_int session_key = get_random_number(1, open_key.p - 1); //сессионный ключ
    cpp_int a = powm(open_key.g, session_key, open_key.p);
    vector<CHIPHER_TEXT> chipher;
    for (const char& c : text)
    {
        cpp_int b = multm(powm(open_key.y, session_key, open_key.p), c, open_key.p);
        chipher.push_back({a,b});                               //зашифрованное сообщение
    }
    return chipher;
}
cpp_int ElGamal::mult_inverse(const cpp_int& num, const cpp_int& mod, bool isPrime = true) //нахождение мультипликативно обратного элемента. ТОЛЬКО ДЛЯ ПРОСТЫХ ЧИСЕЛ
{
    if(isPrime)
        return powm(num, mod - 2, mod);
    else
    {
        for (cpp_int i = 1; i < mod; i++)
        {
            if ((num * i) % mod == 1)
                return i;
        }
    }
    return -1;
}
string ElGamal::decrypt(const vector<CHIPHER_TEXT>& chipher)
{
    string decrypted = "";
    for (const CHIPHER_TEXT& chip : chipher)
       decrypted +=  static_cast<char>(multm(chip.b, mult_inverse(powm(chip.a, priv_key, open_key.p), open_key.p), open_key.p));

    return decrypted;

}
bool ElGamal::is_coprime(cpp_int a, cpp_int b)
{
    while (b) {
        a = a % b;
        swap(a, b);
    }
    return a == 1 ? true : false;
}
SIGNATURE ElGamal::create_signature(const string& message)
{
    SIGNATURE sign{ 0,0,0 };
    SHA256 sha_alg;
    // Вычисление хеша
    sha_alg.update(message);
    std::array<uint8_t, 32> parts = sha_alg.digest();
    for (const uint8_t& part : parts)
        sign.hash = (sign.hash << 8) | cpp_int(part);
    
    //Вычисление сессионного ключа
    cpp_int session_key = get_random_number(1, open_key.p - 1);
    while(!is_coprime(open_key.p - 1, session_key))
        session_key = get_random_number(1, open_key.p - 1);
    
    
    //Формируем подпись: r = g^k mod p; s = (m - xr)*k^(-1) mod p-1
    sign.r = powm(open_key.g, session_key, open_key.p);

    cpp_int inv_session_key = mult_inverse(session_key, open_key.p - 1, false);
    cpp_int diff = sign.hash - priv_key * sign.r;

    sign.s = multm(diff, inv_session_key, open_key.p - 1);

    return sign;
}
bool ElGamal::check_signature(const SIGNATURE& sign)
{
    if (sign.r < open_key.p && sign.s < open_key.p - 1)
    {
        cpp_int mult = powm(open_key.y, sign.r, open_key.p) * powm(sign.r, sign.s, open_key.p) % open_key.p;
        cpp_int g_pow = powm(open_key.g, sign.hash, open_key.p);
        
        return mult == g_pow ? true : false;
    }
    else
        return false;
}
ElGamal::ElGamal()
{
    generate_keys();
}