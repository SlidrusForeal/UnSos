import sys
import base64
import random
import string
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QTextEdit, QVBoxLayout, QLineEdit
import ast
import marshal
import types


def _gen_key(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def _enc(text, key):
    encoded_bytes = base64.b64encode(text.encode("utf-8"))
    encoded_text = encoded_bytes.decode("utf-8")
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encoded_text))


def _dec(text, key):
    decoded_text = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
    return base64.b64decode(decoded_text).decode("utf-8")


class _App(QWidget):
    def __init__(self):
        super().__init__()
        self._ui()

    def _ui(self):
        self.setWindowTitle("Шифратор")
        self.setGeometry(100, 100, 400, 300)

        self._l1 = QLabel("Введите сообщение:")
        self._t1 = QTextEdit()

        self._l2 = QLabel("Ключ шифрования:")
        self._t2 = QLineEdit()

        self._b1 = QPushButton("Зашифровать")
        self._b2 = QPushButton("Расшифровать")
        self._l3 = QLabel("Результат:")
        self._t3 = QTextEdit()
        self._t3.setReadOnly(True)

        self._b1.clicked.connect(self._e)
        self._b2.clicked.connect(self._d)

        layout = QVBoxLayout()
        layout.addWidget(self._l1)
        layout.addWidget(self._t1)
        layout.addWidget(self._l2)
        layout.addWidget(self._t2)
        layout.addWidget(self._b1)
        layout.addWidget(self._b2)
        layout.addWidget(self._l3)
        layout.addWidget(self._t3)

        self.setLayout(layout)

    def _e(self):
        text = self._t1.toPlainText()
        key = self._t2.text()
        if not key:
            key = _gen_key()
            self._t2.setText(key)
        self._t3.setPlainText(_enc(text, key))

    def _d(self):
        text = self._t1.toPlainText()
        key = self._t2.text()
        try:
            self._t3.setPlainText(_dec(text, key))
        except Exception:
            self._t3.setPlainText("Ошибка расшифровки")


def _obfuscate():
    with open(__file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    compiled_code = compile(tree, "<ast>", "exec")
    obfuscated = marshal.dumps(compiled_code)
    with open("obfuscated.py", "wb") as f:
        f.write(obfuscated)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = _App()
    window.show()
    sys.exit(app.exec())
