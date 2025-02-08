import math

_A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def _kp(k):
    a = sum(ord(x) for x in k) % 360
    p = 1
    for x in k:
        p = (p * ((ord(x) % 97) + 1)) % 100000
    s = (p % 1000) + 1
    return a, s

def _dl(i, a, s):
    return ((i**3) + (s * i) + (a * math.sin(i))) % 360

def _mo(i, a, s):
    return ((i * s) + int(math.floor(a))) % 256

def _sc(d):
    return round(d * (65535 / 360))

def _i2b(n):
    n = int(n)
    r = []
    for _ in range(3):
        r.append(_A[int(n % 64)])
        n //= 64
    return ''.join(reversed(r))

def _b2i(s):
    n = 0
    for ch in s:
        n = n * 64 + _A.index(ch)
    return n

def _enc(pt, k):
    a, s = _kp(k)
    ct = []
    for i, ch in enumerate(pt, start=1):
        U = ord(ch)
        d = _dl(i, a, s)
        M = _mo(i, a, s)
        sh = _sc(d)
        E = (U + sh + M) % 65536
        ct.append(_i2b(E))
    return ''.join(ct)

def _dec(ct, k):
    if len(ct) % 3 != 0:
        raise ValueError("Некорректная длина шифротекста")
    a, s = _kp(k)
    pt = []
    for i in range(1, len(ct) // 3 + 1):
        blk = ct[(i - 1) * 3: i * 3]
        E = _b2i(blk)
        d = _dl(i, a, s)
        M = _mo(i, a, s)
        sh = _sc(d)
        U = (E - sh - M) % 65536
        pt.append(chr(U))
    return ''.join(pt)

def main():
    print("Выберите операцию:")
    print("1 - Шифрование")
    print("2 - Дешифрование")
    op = input("Введите номер операции: ").strip()
    key = input("Введите секретный ключ: ")
    if op == "1":
        msg = input("Введите сообщение для шифрования: ")
        res = _enc(msg, key)
        print("\nЗашифрованное сообщение:")
        print(res)
    elif op == "2":
        msg = input("Введите шифротекст для дешифрования: ")
        try:
            res = _dec(msg, key)
            print("\nДешифрованное сообщение:")
            print(res)
        except Exception as e:
            print("Ошибка при дешифровании:", e)
    else:
        print("Неверный выбор операции!")

if __name__ == "__main__":
    main()
