import os
import hashlib
import base64
import logging
import shutil
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
import tkinter as tk
from tkinter import filedialog, messagebox

# Настройка логирования
logging.basicConfig(
    filename='encryption_errors.log',
    level=logging.ERROR,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Константы
MIN_KEY_LENGTH = 8
DELIMITER = "|||"
SECURE_DELETE_PASSES = 3  # Количество проходов для безопасного удаления

def derive_fernet_key(password, salt):
    """Генерация ключа Fernet из пароля и соли с использованием PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,  # Увеличено для защиты от перебора
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def validate_file(file_path):
    """Проверка существования файла и его непустоты."""
    if not os.path.exists(file_path):
        logging.error(f"Файл {file_path} не существует.")
        return False
    if os.path.getsize(file_path) == 0:
        logging.error(f"Файл {file_path} пуст.")
        return False
    return True

def secure_delete(file_path, passes=SECURE_DELETE_PASSES):
    """Безопасное удаление файла с многократной перезаписью."""
    try:
        with open(file_path, "ba+", buffering=0) as f:
            length = f.tell()
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(file_path)
    except Exception as e:
        logging.error(f"Ошибка при безопасном удалении {file_path}: {e}")

def encrypt_file(file_path, key):
    """Шифрование содержимого и имени файла с использованием Fernet."""
    if not validate_file(file_path):
        print(f"Пропуск {file_path}: некорректный ввод.")
        return

    # Чтение содержимого файла
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        logging.error(f"Ошибка чтения файла {file_path}: {e}")
        return

    # Шифрование содержимого
    try:
        salt_content = os.urandom(16)
        fernet_key_content = derive_fernet_key(key, salt_content)
        fernet_obj_content = Fernet(fernet_key_content)
        encrypted_content = fernet_obj_content.encrypt(data)
        salt_content_enc = base64.urlsafe_b64encode(salt_content).decode("utf-8")
    except Exception as e:
        logging.error(f"Ошибка шифрования содержимого {file_path}: {e}")
        return

    # Шифрование имени файла
    try:
        original_filename = os.path.basename(file_path)
        filename_bytes = original_filename.encode("utf-8")
        salt_name = os.urandom(16)
        fernet_key_name = derive_fernet_key(key, salt_name)
        fernet_obj_name = Fernet(fernet_key_name)
        encrypted_filename = fernet_obj_name.encrypt(filename_bytes)
        salt_name_enc = base64.urlsafe_b64encode(salt_name).decode("utf-8")
    except (UnicodeEncodeError, Exception) as e:
        logging.error(f"Ошибка шифрования имени файла {file_path}: {e}")
        return

    # Формирование содержимого зашифрованного файла
    final_file_content = (
        f"SALT_NAME:{salt_name_enc}\n"
        f"FERNET_NAME:{encrypted_filename.decode('utf-8')}\n"
        f"SALT_CONTENT:{salt_content_enc}\n"
        f"FERNET_CONTENT:{encrypted_content.decode('utf-8')}"
    )

    # Генерация нового имени файла на основе хэша
    short_name = hashlib.sha256(original_filename.encode("utf-8")).hexdigest() + ".enc"
    folder = os.path.dirname(file_path)
    new_file_path = os.path.join(folder, short_name)

    # Запись зашифрованного файла
    try:
        with open(new_file_path, "w", encoding="utf-8") as f:
            f.write(final_file_content)
        # Проверка успешности записи перед удалением оригинала
        if os.path.exists(new_file_path) and os.path.getsize(new_file_path) > 0:
            secure_delete(file_path)
            print(f"Файл '{original_filename}' зашифрован как '{short_name}' и оригинал безопасно удален.")
        else:
            raise IOError("Ошибка записи зашифрованного файла.")
    except (IOError, OSError) as e:
        logging.error(f"Ошибка сохранения зашифрованного файла {new_file_path}: {e}")
        if os.path.exists(new_file_path):
            os.remove(new_file_path)  # Очистка при неудачной записи

def decrypt_file(file_path, key):
    """Дешифрование файла .enc и восстановление оригинального имени и содержимого."""
    if not validate_file(file_path):
        print(f"Пропуск {file_path}: файл не существует или пуст.")
        return
    folder = os.path.dirname(file_path)

    # Чтение зашифрованного файла
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (IOError, OSError, UnicodeDecodeError) as e:
        logging.error(f"Ошибка чтения файла {file_path}: {e}")
        return

    # Парсинг структуры файла
    try:
        lines = content.splitlines()
        if len(lines) < 4:
            raise ValueError("Некорректная структура файла.")
        fields = dict(line.split(":", 1) for line in lines)
        if not all(k in fields for k in ["SALT_NAME", "FERNET_NAME", "SALT_CONTENT", "FERNET_CONTENT"]):
            raise ValueError("Отсутствуют обязательные поля в файле.")
    except (ValueError, Exception) as e:
        logging.error(f"Ошибка парсинга структуры файла {file_path}: {e}")
        return

    # Дешифрование имени файла
    try:
        salt_name = base64.urlsafe_b64decode(fields["SALT_NAME"].encode("utf-8"))
        fernet_key_name = derive_fernet_key(key, salt_name)
        fernet_obj_name = Fernet(fernet_key_name)
        decrypted_filename_bytes = fernet_obj_name.decrypt(fields["FERNET_NAME"].encode("utf-8"))
        original_filename = decrypted_filename_bytes.decode("utf-8")
        # Проверка валидности имени файла
        if not original_filename or '\\' in original_filename or '/' in original_filename:
            raise ValueError("Некорректное расшифрованное имя файла.")
    except (InvalidToken, UnicodeDecodeError, ValueError) as e:
        logging.error(f"Ошибка дешифрования имени файла {file_path}: {e}")
        return

    # Дешифрование содержимого
    try:
        salt_content = base64.urlsafe_b64decode(fields["SALT_CONTENT"].encode("utf-8"))
        fernet_key_content = derive_fernet_key(key, salt_content)
        fernet_obj_content = Fernet(fernet_key_content)
        decrypted_content_bytes = fernet_obj_content.decrypt(fields["FERNET_CONTENT"].encode("utf-8"))
    except (InvalidToken, Exception) as e:
        logging.error(f"Ошибка дешифрования содержимого {file_path}: {e}")
        return

    # Запись расшифрованного файла
    new_file_path = os.path.join(folder, original_filename)
    try:
        with open(new_file_path, "wb") as f:
            f.write(decrypted_content_bytes)
        # Проверка успешности записи перед удалением зашифрованного файла
        if os.path.exists(new_file_path) and os.path.getsize(new_file_path) > 0:
            secure_delete(file_path)
            print(f"Файл '{os.path.basename(file_path)}' расшифрован как '{original_filename}' и зашифрованный файл безопасно удален.")
        else:
            raise IOError("Ошибка записи расшифрованного файла.")
    except (IOError, OSError) as e:
        logging.error(f"Ошибка сохранения расшифрованного файла {new_file_path}: {e}")
        if os.path.exists(new_file_path):
            os.remove(new_file_path)  # Очистка при неудачной записи

def process_directory(folder, key, operation, recursive=False):
    """Обработка всех файлов в директории (и поддиректориях при рекурсии)."""
    if operation not in ["encrypt", "decrypt"]:
        print("Некорректная операция. Используйте 'encrypt' или 'decrypt'.")
        return

    extension = ".txt" if operation == "encrypt" else ".enc"
    files = []
    for root, _, filenames in os.walk(folder):
        for filename in filenames:
            if filename.lower().endswith(extension):
                files.append(os.path.join(root, filename))
        if not recursive:
            break

    if not files:
        print(f"Файлы с расширением {extension} в папке не найдены.")
        return

    for file_path in tqdm(files, desc=f"{operation.capitalize()}ing файлов"):
        if operation == "encrypt":
            encrypt_file(file_path, key)
        else:
            decrypt_file(file_path, key)

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption/Decryption")

        self.key_label = tk.Label(root, text="Secret Key:")
        self.key_label.pack()

        self.key_entry = tk.Entry(root, show="*")
        self.key_entry.pack()

        self.folder_label = tk.Label(root, text="Folder Path:")
        self.folder_label.pack()

        self.folder_entry = tk.Entry(root)
        self.folder_entry.pack()

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_folder)
        self.browse_button.pack()

        self.recursive_var = tk.BooleanVar()
        self.recursive_check = tk.Checkbutton(root, text="Recursive", variable=self.recursive_var)
        self.recursive_check.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt Files", command=self.encrypt_files)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt Files", command=self.decrypt_files)
        self.decrypt_button.pack()

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        self.folder_entry.delete(0, tk.END)
        self.folder_entry.insert(0, folder_selected)

    def encrypt_files(self):
        key = self.key_entry.get()
        folder = self.folder_entry.get()
        recursive = self.recursive_var.get()
        if self.validate_input(key, folder):
            process_directory(folder, key, "encrypt", recursive)

    def decrypt_files(self):
        key = self.key_entry.get()
        folder = self.folder_entry.get()
        recursive = self.recursive_var.get()
        if self.validate_input(key, folder):
            process_directory(folder, key, "decrypt", recursive)

    def validate_input(self, key, folder):
        if not key or len(key) < MIN_KEY_LENGTH:
            messagebox.showerror("Error", f"Secret key must be at least {MIN_KEY_LENGTH} characters long!")
            return False
        if not os.path.isdir(folder):
            messagebox.showerror("Error", "The specified folder does not exist!")
            return False
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
