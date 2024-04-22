#ifndef EL_GAMAL_H
#define EL_GAMAL_H
#include <boost/multiprecision/cpp_int.hpp>
#include <vector>

typedef struct							
{
	boost::multiprecision::cpp_int y;
	boost::multiprecision::cpp_int g;
	boost::multiprecision::cpp_int p;
} OPEN_KEY;
std::ostream& operator<<(std::ostream&, const OPEN_KEY&);

typedef struct
{
	boost::multiprecision::cpp_int a;
	boost::multiprecision::cpp_int b;
} CHIPHER_TEXT;
std::ostream& operator<<(std::ostream&, const CHIPHER_TEXT&);

typedef struct
{
	boost::multiprecision::cpp_int hash;
	boost::multiprecision::cpp_int r;
	boost::multiprecision::cpp_int s;
} SIGNATURE;
std::ostream& operator<<(std::ostream&, const SIGNATURE&);


class ElGamal
{
private:
	OPEN_KEY open_key;																				//публичный ключ
	boost::multiprecision::cpp_int priv_key;														//скрытый ключ
	boost::multiprecision::cpp_int get_random_number(												//генераци€ рандомного числа
													const boost::multiprecision::cpp_int&&, 
													const boost::multiprecision::cpp_int&&);
	boost::multiprecision::cpp_int generate_primary_number();										//генераци€ простого числа
	boost::multiprecision::cpp_int generate_primitive_root(const boost::multiprecision::cpp_int&);  //нахождение первообразного корн€
	boost::multiprecision::cpp_int multm(
													boost::multiprecision::cpp_int,          //умножение по модулю
													boost::multiprecision::cpp_int,
													const boost::multiprecision::cpp_int&);
	boost::multiprecision::cpp_int mult_inverse(													//мультипликативно обратное число
													const boost::multiprecision::cpp_int&,
													const boost::multiprecision::cpp_int&,
													bool);
	bool is_coprime(boost::multiprecision::cpp_int, boost::multiprecision::cpp_int);				//проверка на взаимную простоту
	void generate_keys();																			//генераци€ ключей
	

public:
	ElGamal();
	OPEN_KEY get_open_key() { return open_key; }
	boost::multiprecision::cpp_int get_private_key() { return priv_key; }

	std::vector<CHIPHER_TEXT> encrypt(const std::string&);											//шифрование
	std::string decrypt(const std::vector<CHIPHER_TEXT>&);											//расшифровка
	SIGNATURE create_signature(const std::string&);													//выработка Ё÷ѕ
	bool check_signature(const SIGNATURE&);
};

#endif
