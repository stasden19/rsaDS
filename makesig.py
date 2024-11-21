import argparse
import base64
import random
from math import gcd
from sympy import isprime, randprime
import hashlib
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def int_to_base64(number):
    # Определяем минимальное количество байт, чтобы представить число
    byte_length = (number.bit_length() + 7) // 8
    # Конвертируем число в байты (big-endian)
    number_bytes = number.to_bytes(byte_length, byteorder="big")
    # Кодируем байты в Base64
    base64_string = base64.b64encode(number_bytes).decode("utf-8")
    return base64_string


def derive_key(password):
    return sha256(password.encode('utf-8')).digest()


def base64_to_int(base64_string):
    # Декодируем строку Base64 обратно в байты
    number_bytes = base64.b64decode(base64_string)
    # Конвертируем байты обратно в число (big-endian)
    number = int.from_bytes(number_bytes, byteorder="big")
    return number


def aes_decrypt(ciphertext, password, iv):
    key = derive_key(password)  # Генерируем ключ из пароля
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Создаем расшифровщик
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Расшифровываем данные
    return plaintext.decode('utf-8')  # Преобразуем в строку


# Шифрование
def encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)


# Расшифрование
def decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)


parser = argparse.ArgumentParser()
parser.add_argument('-s', '--state', required=True, default='verify', choices=["verify", "signature"], )
parser.add_argument('-sig', '--signature')
parser.add_argument('-k', '--key')
parser.add_argument('-f', '--file', required=True)
args = vars(parser.parse_args())

if args['state'] == 'signature':
    if not args['key']:
        raise FileNotFoundError('Необходим ключ для подписи! (-k [FILE]) ')
    with open(args['file'], 'r') as f:
        hash_file = hashlib.sha3_512(f.read().encode()).hexdigest()
        # print(hash_file)
        with open(args['key'], 'r') as key, open(args['key'] + '.pub') as public_key:
            key = key.read()
            # print(key.split('.'))
            if key.split('.')[-1] == 'Y3J5cHRlZA==':
                password = input('Необходим пароль: ')
                dectypted_text = aes_decrypt(base64.b64decode(key.split('.')[0].encode()), password,
                                             base64.b64decode(key.split('.')[1].encode()))
                private_key = base64_to_int(dectypted_text.split('.')[0]), base64_to_int(
                    dectypted_text.split('.')[1])
            else:
                private_key = base64_to_int(key.split('.')[0]), base64_to_int(key.split('.')[1])
            sign_hash = encrypt(int(hash_file, 16), private_key)
            public_key_base64 = base64.b64encode(public_key.read().encode()).decode("utf-8")
            with open(args['file'] + '.sig', 'w') as sig:
                sig.write(f'{int_to_base64(sign_hash)}.{public_key_base64}')
                print('Файл был успешно подписан!')
elif args['state'] == 'verify':
    if not args['signature']:
        raise FileNotFoundError('Необходим файл подписи! (-sig [FILE])')
    with open(args['file'], 'r') as file:
        hash_file = hashlib.sha3_512(file.read().encode()).hexdigest()
        # print(hash_file)
        with open(args['signature'], 'r') as sig:
            signature = sig.read()
            hash_file_sig = signature.split('.')[0]
            # print(base64.b64decode(hash_file_sig).decode())
            hash_file_sig = base64_to_int(hash_file_sig)
            # print(signature)
            pub_key = signature.split('.')[1]
            # print(pub_key)
            signature = base64_to_int(signature)
            pub_key = base64.b64decode(pub_key.split('.')[0]).decode()
            pub_key = list(map(base64_to_int, pub_key.split('.')))
            # print(base64.b64decode(pub_key))
            # print(hash_file)
            # print(hex(decrypt(hash_file_sig, pub_key))[2:])
            if hex(decrypt(hash_file_sig, pub_key))[2:] == hash_file:
                print('Файл был подписан этой подписью и после этого не был изменен!')
            else:
                print('Файл был изменен после подписания или был подписан не этой подписью!')

            # print(hex(decrypt(hash_file_sig, pub_key))[2:])

# print(public_key)
# print(private_key)
# message = 123456789123
# print("Исходное сообщение:", message)
#
# ciphertext = encrypt(message, public_key)
# print("Зашифрованное сообщение:", ciphertext)
#
# decrypted_message = decrypt(ciphertext, private_key)
# print("Расшифрованное сообщение:", decrypted_message)
#
# signature = sign(message, private_key)
# print("Подпись:", signature)
#
# verified_message = verify(signature, public_key)
# print("Проверенное сообщение:", verified_message)
#
# assert message == decrypted_message, "Расшифрование не совпадает с исходным сообщением!"
# assert message == verified_message, "Подпись не совпадает с исходным сообщением!"
