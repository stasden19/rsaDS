import base64
from sympy import randprime
import argparse
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def derive_key(password):
    return sha256(password.encode('utf-8')).digest()


def aes_encrypt(data, password):
    if isinstance(data, str):
        data = data.encode('utf-8')  # Преобразуем в байты

    key = derive_key(password)  # Генерируем ключ из пароля
    cipher = AES.new(key, AES.MODE_CBC)  # Создаем шифратор в режиме CBC
    ciphertext = cipher.encrypt(pad(data, AES.block_size))  # Шифруем данные с паддингом
    return ciphertext, cipher.iv  # Возвращаем шифротекст и IV


def int_to_base64(number):
    # Определяем минимальное количество байт, чтобы представить число
    byte_length = (number.bit_length() + 7) // 8
    # Конвертируем число в байты (big-endian)
    number_bytes = number.to_bytes(byte_length, byteorder="big")
    # Кодируем байты в Base64
    base64_string = base64.b64encode(number_bytes).decode("utf-8")
    return base64_string


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keys(bits=512):
    p = randprime(2 ** bits, 2 ** (bits + 1))
    q = randprime(2 ** bits, 2 ** (bits + 1))
    while p == q:
        q = randprime(2 ** bits, 2 ** (bits + 1))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = randprime(2 ** 16, 2 ** 18)
    d = mod_inverse(e, phi)
    return (e, n), (d, n)


parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', default='key')
parser.add_argument('-b', '--bits', type=int, default=512)
parser.add_argument('-p', '--phrase', help='secrete phrase to generate')
args = vars(parser.parse_args())
file_name = args['file']
public_key, private_key = generate_keys(bits=args['bits'])
# print(private_key)
public_key_formated = int_to_base64(public_key[0]) + '.' + int_to_base64(public_key[1])
private_key_formated = f'{int_to_base64(private_key[0])}.{int_to_base64(private_key[1])}'
if args['phrase']:
    ciphertext, iv = aes_encrypt(private_key_formated, args['phrase'])
    ciphertext_formated = base64.b64encode(ciphertext).decode() + '.' + base64.b64encode(
        iv).decode() + '.' + base64.b64encode(b'crypted').decode()
    # print(ciphertext_formated)
else:
    ciphertext_formated = private_key_formated
with open(file_name + '.pub', 'w') as open_key:
    open_key.write(public_key_formated)
    print('Публичный ключ сформирован: {file_name}'.format(file_name=file_name + '.pub'))

with open(file_name, 'w') as private:
    private.write(ciphertext_formated)
    print('Приватный ключ сформирован: {file_name}'.format(file_name=file_name))
