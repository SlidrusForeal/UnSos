import os
import math
import base64
import hashlib
import hmac
import binascii


# Допустимый алфавит для представления чисел (аналог Base64)
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _generate_key_derivation(key, salt):
    """
    Генерирует производный ключ с использованием HMAC и PBKDF2.

    Параметры:
        key (str): Секретный ключ.
        salt (bytes): Соль для усиления ключа.

    Возвращает:
        tuple: (angle, seed, hmac_key) - угол, семя и ключ для HMAC.
    """
    derived_key = hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), salt, 100000, dklen=32)
    angle = int.from_bytes(derived_key[:2], 'big') % 360
    seed = (int.from_bytes(derived_key[2:4], 'big') % 1000) + 1
    hmac_key = derived_key[4:32]
    return angle, seed, hmac_key


def _chaotic_offset(i, angle, seed):
    """Вычисляет хаотическое смещение для i-го символа."""
    return ((i ** 3) + (seed * i) + (angle * math.sin(i))) % 360


def _modular_offset(i, angle, seed):
    """Вычисляет модульное смещение для улучшения рандомизации."""
    return ((i * seed) + int(math.floor(angle))) % 256


def _scale_offset(offset):
    """Масштабирует смещение в диапазон 0-65535."""
    return round(offset * (65535 / 360))


def _number_to_str(number):
    """Преобразует число (0-262143) в строку из 3 символов."""
    number = int(number)
    result = []
    for _ in range(3):
        result.append(_ALPHABET[number % 64])
        number //= 64
    return ''.join(reversed(result))


def _str_to_number(s):
    """Преобразует 3-символьную строку в число."""
    number = 0
    for ch in s:
        if ch not in _ALPHABET:
            raise ValueError(f"Недопустимый символ '{ch}' в данных.")
        number = number * 64 + _ALPHABET.index(ch)
    return number


def _encrypt_rounds(plaintext, angle, seed, rounds, iv):
    """Выполняет многораундовое шифрование с цепочкой."""
    current = [ord(ch) for ch in plaintext]
    for _ in range(rounds):
        next_round = []
        chain = iv if _ == 0 else 0
        for i, code in enumerate(current, start=1):
            offset = _chaotic_offset(i, angle, seed)
            mod_offset = _modular_offset(i, angle, seed)
            scaled_offset = _scale_offset(offset)
            encrypted = (code + scaled_offset + mod_offset + chain) % 65536
            next_round.append(encrypted)
            chain = encrypted
        current = next_round
    return current


def _decrypt_rounds(ciphertext, angle, seed, rounds, iv):
    """Выполняет многораундовое дешифрование с цепочкой."""
    current = ciphertext
    for r in range(rounds, 0, -1):
        next_round = []
        chain = iv if r == 1 else 0
        for i, code in enumerate(current, start=1):
            offset = _chaotic_offset(i, angle, seed)
            mod_offset = _modular_offset(i, angle, seed)
            scaled_offset = _scale_offset(offset)
            original = (code - scaled_offset - mod_offset - chain) % 65536
            next_round.append(original)
            chain = code
        current = next_round
    return current


def encrypt(plaintext, key):
    """
    Шифрует текст с использованием заданного ключа.

    Параметры:
        plaintext (str): Текст для шифрования.
        key (str): Секретный ключ (не менее 8 символов).

    Возвращает:
        str: Зашифрованная строка в формате DPPC1.

    Исключения:
        ValueError: При недопустимом ключе.
    """
    if len(key) < 8:
        raise ValueError("Ключ должен быть не менее 8 символов.")

    salt = os.urandom(12)
    iv_int = int.from_bytes(os.urandom(2), 'big') % 65536
    rounds = 3

    angle, seed, hmac_key = _generate_key_derivation(key, salt)
    ciphertext = _encrypt_rounds(plaintext, angle, seed, rounds, iv_int)
    payload = ''.join(_number_to_str(x) for x in ciphertext)

    version = "DPPC1"
    salt_encoded = base64.b64encode(salt).decode('ascii')
    iv_encoded = _number_to_str(iv_int)
    rounds_encoded = f"{rounds:02d}"
    header = version + salt_encoded + iv_encoded + rounds_encoded

    auth_data = (header + payload).encode('utf-8')
    mac = hmac.new(hmac_key, auth_data, hashlib.sha256).hexdigest()

    return header + payload + mac


def decrypt(ciphertext, key):
    """
    Дешифрует текст с использованием заданного ключа.

    Параметры:
        ciphertext (str): Зашифрованная строка.
        key (str): Секретный ключ (не менее 8 символов).

    Возвращает:
        str: Расшифрованный текст.

    Исключения:
        ValueError: При неверном формате, HMAC или ошибках данных.
    """
    if len(key) < 8:
        raise ValueError("Ключ должен быть не менее 8 символов.")
    if len(ciphertext) < 90:
        raise ValueError("Некорректная длина шифротекста.")

    header = ciphertext[:26]
    version = header[:5]
    if version != "DPPC1":
        raise ValueError("Неподдерживаемая версия шифра.")

    salt_encoded = header[5:21]
    iv_encoded = header[21:24]
    rounds_encoded = header[24:26]

    try:
        salt = base64.b64decode(salt_encoded)
    except binascii.Error as e:
        raise ValueError("Ошибка декодирования соли.") from e

    iv_int = _str_to_number(iv_encoded)

    try:
        rounds = int(rounds_encoded)
    except ValueError as e:
        raise ValueError("Некорректное количество раундов.") from e

    if rounds < 1 or rounds > 10:
        raise ValueError("Недопустимое количество раундов.")

    mac_received = ciphertext[-64:]
    payload = ciphertext[26:-64]

    if len(payload) % 3 != 0:
        raise ValueError("Некорректная длина полезной нагрузки.")

    angle, seed, hmac_key = _generate_key_derivation(key, salt)
    auth_data = (header + payload).encode('utf-8')
    mac_calculated = hmac.new(hmac_key, auth_data, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(mac_received, mac_calculated):
        raise ValueError("Ошибка проверки целостности данных.")

    try:
        ciphertext_numbers = [_str_to_number(payload[i:i + 3]) for i in range(0, len(payload), 3)]
    except ValueError as e:
        raise ValueError("Недопустимые символы в данных.") from e

    original_list = _decrypt_rounds(ciphertext_numbers, angle, seed, rounds, iv_int)

    try:
        plaintext = ''.join(chr(x) for x in original_list)
    except (ValueError, OverflowError) as e:
        raise ValueError("Ошибка преобразования данных.") from e

    return plaintext


def main():
    """Основная функция для взаимодействия с пользователем."""
    print("Выберите операцию:\n1 - Шифрование\n2 - Дешифрование")
    op = input("Введите номер операции: ").strip()
    key = input("Введите секретный ключ: ")

    try:
        if op == "1":
            msg = input("Введите сообщение для шифрования: ")
            enc_msg = encrypt(msg, key)
            print("\nЗашифрованное сообщение:\n", enc_msg)
        elif op == "2":
            msg = input("Введите шифротекст для дешифрования: ")
            dec_msg = decrypt(msg, key)
            print("\nДешифрованное сообщение:\n", dec_msg)
        else:
            print("Неверный выбор операции!")
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()
