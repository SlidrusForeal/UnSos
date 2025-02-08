import os
import math
import base64
import hashlib
import hmac

# Допустимый алфавит для представления чисел (аналог Base64)
_A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# Функция криптографически стойкого получения ключевых параметров из исходного ключа и соли
def _dk(key, salt):
    # Производное ключевое значение: 32 байта, PBKDF2 с 100000 итераций
    dk = hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), salt, 100000, dklen=32)
    K_angle = int.from_bytes(dk[0:2], 'big') % 360
    K_seed = (int.from_bytes(dk[2:4], 'big') % 1000) + 1
    hkey = dk[4:32]  # Ключ для HMAC
    return K_angle, K_seed, hkey


# Вычисление хаотического смещения Δ для i-го символа
def _dl(i, a, s):
    return ((i ** 3) + (s * i) + (a * math.sin(i))) % 360


# Дополнительное модульное смещение M(i)
def _mo(i, a, s):
    return ((i * s) + int(math.floor(a))) % 256


# Масштабирование Δ (в градусах) в сдвиг (целое число в диапазоне 0–65535)
def _sc(d):
    return round(d * (65535 / 360))


# Преобразование числа (0 <= n < 262144) в 3-символьную строку на основе алфавита _A
def _i2b(n):
    n = int(n)
    r = []
    for _ in range(3):
        r.append(_A[n % 64])
        n //= 64
    return ''.join(reversed(r))


# Обратное преобразование 3-символьной строки в число
def _b2i(s):
    n = 0
    for ch in s:
        n = n * 64 + _A.index(ch)
    return n


# Шифрование за один раунд с цепочкой (chaining)
def _rounds_encrypt(pt, a, s, rounds, iv):
    # pt – строка; возвращает список 16-битных чисел (результат шифрования)
    cur = [ord(ch) for ch in pt]
    for r in range(rounds):
        cur2 = []
        chain = iv if r == 0 else 0  # В первом раунде используем IV, далее цепная связь начинается с 0
        for i, code in enumerate(cur, start=1):
            d = _dl(i, a, s)
            m = _mo(i, a, s)
            sh = _sc(d)
            enc = (code + sh + m + chain) % 65536
            cur2.append(enc)
            chain = enc
        cur = cur2
    return cur


# Дешифрование (обратный процесс многораундового шифрования)
def _rounds_decrypt(ct_list, a, s, rounds, iv):
    cur = ct_list
    for r in range(rounds, 0, -1):
        new_round = []
        chain = iv if r == 1 else 0
        for i, code in enumerate(cur, start=1):
            d = _dl(i, a, s)
            m = _mo(i, a, s)
            sh = _sc(d)
            orig = (code - sh - m - chain) % 65536
            new_round.append(orig)
            chain = code
        cur = new_round
    return cur


# Основная функция шифрования с усилениями
def encrypt(plaintext, key):
    # Генерируем случайную соль (12 байт; 12 кратно 3, поэтому при Base64-представлении не будет символов "=")
    salt = os.urandom(12)
    # Генерируем случайный IV – 16-битное число
    iv_int = int.from_bytes(os.urandom(2), 'big') % 65536
    rounds = 3  # Количество раундов (можно увеличить для усиления)

    # Получаем ключевые параметры: K_angle, K_seed и ключ для HMAC
    a, s_val, hkey = _dk(key, salt)

    # Многораундовое шифрование с цепочкой
    ct_list = _rounds_encrypt(plaintext, a, s_val, rounds, iv_int)
    # Преобразуем каждый 16-битный результат в 3-символьный блок
    payload = ''.join(_i2b(x) for x in ct_list)

    # Формирование заголовка:
    # 1. Версия шифра: "DPPC1" (5 символов)
    # 2. Соль, закодированная стандартным Base64 (12 байт → 16 символов, без "=")
    # 3. IV, представленный в виде 3 символов
    # 4. Число раундов в виде 2‑значного десятичного числа
    version = "DPPC1"
    salt_enc = base64.b64encode(salt).decode('ascii')
    iv_enc = _i2b(iv_int)
    rounds_enc = f"{rounds:02d}"
    header = version + salt_enc + iv_enc + rounds_enc

    # Вычисляем HMAC (SHA256) по данным заголовка и payload
    auth_data = (header + payload).encode('utf-8')
    mac = hmac.new(hkey, auth_data, hashlib.sha256).hexdigest()

    # Итоговый шифротекст состоит из: header + payload + HMAC
    final_ct = header + payload + mac
    return final_ct


# Основная функция дешифрования
def decrypt(ciphertext, key):
    # Заголовок имеет фиксированную длину: 5 (версия) + 16 (соль) + 3 (IV) + 2 (раунды) = 26 символов
    if len(ciphertext) < 26:
        raise ValueError("Ciphertext слишком короткий.")
    header = ciphertext[:26]
    version = header[:5]
    if version != "DPPC1":
        raise ValueError("Неподдерживаемая версия шифра.")
    salt_enc = header[5:21]
    iv_enc = header[21:24]
    rounds_enc = header[24:26]
    salt = base64.b64decode(salt_enc)
    iv_int = _b2i(iv_enc)
    rounds = int(rounds_enc)

    # Извлекаем payload и HMAC
    mac_received = ciphertext[-64:]
    payload = ciphertext[26:-64]

    # Проверка целостности с помощью HMAC
    a, s_val, hkey = _dk(key, salt)
    auth_data = (header + payload).encode('utf-8')
    mac_calc = hmac.new(hkey, auth_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac_received, mac_calc):
        raise ValueError("Неверный HMAC. Возможно, данные повреждены или ключ неверный.")

    # Длина payload должна быть кратна 3
    if len(payload) % 3 != 0:
        raise ValueError("Неверная длина полезной нагрузки.")
    ct_list = [_b2i(payload[i:i + 3]) for i in range(0, len(payload), 3)]

    # Многораундовое дешифрование (обратный процесс)
    orig_list = _rounds_decrypt(ct_list, a, s_val, rounds, iv_int)
    plaintext = ''.join(chr(x) for x in orig_list)
    return plaintext


# Функция ввода с клавиатуры с выбором операции
def main():
    print("Выберите операцию:")
    print("1 - Шифрование")
    print("2 - Дешифрование")
    op = input("Введите номер операции: ").strip()
    key = input("Введите секретный ключ: ")
    if op == "1":
        msg = input("Введите сообщение для шифрования: ")
        enc_msg = encrypt(msg, key)
        print("\nЗашифрованное сообщение:")
        print(enc_msg)
    elif op == "2":
        msg = input("Введите шифротекст для дешифрования: ")
        try:
            dec_msg = decrypt(msg, key)
            print("\nДешифрованное сообщение:")
            print(dec_msg)
        except Exception as e:
            print("Ошибка при дешифровании:", e)
    else:
        print("Неверный выбор операции!")


if __name__ == "__main__":
    main()
