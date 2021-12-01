from flask import Flask, render_template, request, url_for
import re
import base64

app = Flask(__name__)

LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def encrypt_rot13(message):
    charsA = LETTERS
    cipher = ""
    for char in message:
        if char in charsA:
            index = LETTERS.find(char)
            if index >= 13:
                tmp = 25 - index
                val = 13 - tmp - 1
            else:
                val = index + 13
            cipher += LETTERS[val]
    return cipher


def decrypt_rot13(ciphertext):
    charsA = LETTERS
    plain = ""
    for char in ciphertext:
        if char in charsA:
            index = LETTERS.find(char)
            if index >= 13:
                tmp = 25 - index
                val = 13 - tmp - 1
            else:
                val = index + 13
            plain += LETTERS[val]
    return plain


def encrypt_caesar(message, k):
    message = message.replace(" ", "")
    result = ""
    k = int(k)
    size = len(message)
    for i in range(0,size):
        char = message[i]
        if (char.isupper()):
            result = result + chr((ord(char) + k - 65) % 26 + 65)
        else:
            result = result + chr((ord(char) + k - 97) % 26 + 97)
    return result


def decrypt_caesar(message, k):
    message = message.replace(" ", "")
    result = ""
    k = int(k)
    size = len(message)
    for i in range(0, size):
        char = message[i]
        if (char.isupper()):
            result = result + chr((ord(char) - k - 65) % 26 + 65)
        else:
            result = result + chr((ord(char) - k - 97) % 26 + 97)
    return result


def encrypt_reverse(message):
    i = len(message) - 1
    translated = ''
    while i >= 0:
        translated = translated + message[i]
        i = i - 1
    return translated


def decrypt_reverse(translated):
    i = len(translated) - 1
    decrypted = ''
    while i >= 0:
        decrypted = decrypted + translated[i]
        i = i - 1
    return decrypted


def encrypt_vigenere(plaintext, key):
 key_length = len(key)
 key_as_int = [ord(i) for i in key]
 plaintext_int = [ord(i) for i in plaintext]
 ciphertext = ''
 for i in range(len(plaintext_int)):
  value = (plaintext_int[i] + key_as_int[i % key_length]) % 26
  ciphertext += chr(value + 65)
 return ciphertext


def decrypt_vigenere(ciphertext, key):
 key_length = len(key)
 key_as_int = [ord(i) for i in key]
 ciphertext_int = [ord(i) for i in ciphertext]
 plaintext = ''
 for i in range(len(ciphertext_int)):
  value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
  plaintext += chr(value + 65)
 return plaintext


#Hàm khởi tạo cho mã Affine
# Return Greatest Common Divisor of a and b
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

# Tính nghịch đảo của a với m
def inverseMod(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

# Có 2 MODE là ENCRYPT và DECRYPT với key cho trước
# Ký tự trong bảng chữ cái T.A in hoa
def affine_cipher(message, MODE, key):
    message = message.upper()
    translated = ''
    modInverseOfKeyA = inverseMod(key[0], len(LETTERS))
    if modInverseOfKeyA == None:
        return None
    for symbol in message:
        if symbol in LETTERS:
            symIndex = LETTERS.find(symbol)
            if MODE.upper() == 'ENCRYPT':
                translated += LETTERS[(symIndex * key[0] + key[1]) % len(LETTERS)]
            elif MODE.upper() == 'DECRYPT':
                translated += LETTERS[(symIndex - key[1]) * modInverseOfKeyA % len(LETTERS)]
        else:
            translated += symbol
    return translated
#End Affine


def encrypt_base64(plain):
    plain_bytes = plain.encode("ascii")
    #Chuyển đổi sang base64 (nhóm 6 bit)
    cipher_bytes = base64.b64encode(plain_bytes)
    cipher = cipher_bytes.decode("ascii")
    return cipher


def decrypt_base64(cipher):
    cipher_bytes = cipher.encode("ascii")
    plain_bytes = base64.b64decode(cipher_bytes)
    plain = plain_bytes.decode("ascii")
    return plain


@app.route("/")
def Home():
    return render_template('index.html')

@app.route("/ROT13_encrypt", methods = ['POST','GET'])
def ROT13_encrypt():
    if request.method == 'POST':
        text = request.form['plaintxt']
        if not text:
            error_message = 'Please type in plaintext'
            return render_template('ROT13_encrypt.html', title='ROT13', text=text, error=error_message)
        elif not re.match("^[A-Z]+$", text):
            error_message = 'Please type in only UPPERCASE and not number!'
            return render_template('ROT13_encrypt.html', title='ROT13', text=text,error=error_message)
        else:
            cipher = encrypt_rot13(text)
            return render_template('ROT13_encrypt.html', title='ROT13', text=text, data=cipher)

    return render_template('ROT13_encrypt.html', title='ROT13')

@app.route("/ROT13_decrypt", methods = ['POST', 'GET'])
def ROT13_decrypt():
    if request.method == 'POST':
        text = request.form['ciphertxt']
        if not text:
            error_message = 'Please type in ciphertext'
            return render_template('ROT13_decrypt.html', title='ROT13', text=text, error=error_message)
        elif not re.match("^[A-Z]+$", text):
            error_message = 'Please type in only UPPERCASE and not number!'
            return render_template('ROT13_decrypt.html', title='ROT13', text=text, error=error_message)
        else:
            plain = decrypt_rot13(text)
            return render_template('ROT13_decrypt.html', title='ROT13', text=text, data=plain)
    return render_template('ROT13_decrypt.html', title='ROT13')

@app.route("/Affine_encrypt", methods = ['POST','GET'])
def Affine_encrypt():
    if request.method == 'POST':
        text = request.form['plaintxt']
        if not text:
            error_message = 'Please type in plaintext'
            return render_template('affine_encrypt.html', title='Affine', text=text, error=error_message)
        elif not re.match("^[A-Z]+$", text):
            error_message = 'Please type in only UPPERCASE and not number!'
            return render_template('affine_encrypt.html', title='Affine', text=text,error=error_message)
        else:
            key = (7,3)
            mode = "encrypt"
            cipher = affine_cipher(text,mode,key)
            return render_template('affine_encrypt.html', title='Affine', data=cipher)

    return render_template('affine_encrypt.html', title='Affine')

@app.route("/Affine_decrypt", methods = ['POST', 'GET'])
def Affine_decrypt():
    if request.method == 'POST':
        text = request.form['ciphertxt']
        if not text:
            error_message = 'Please type in ciphertext'
            return render_template('affine_decrypt.html', title='Affine', text=text, error=error_message)
        elif not re.match("^[A-Z]+$", text):
            error_message = 'Please type in only UPPERCASE and not number!'
            return render_template('affine_decrypt.html', title='Affine', text=text, error=error_message)
        else:
            key = (7, 3)
            mode = "decrypt"
            cipher = affine_cipher(text, mode, key)
            return render_template('affine_decrypt.html', title='Affine', data=cipher)

    return render_template('affine_decrypt.html', title='Affine')

@app.route("/Base64_encrypt", methods = ['POST','GET'])
def Base64_encrypt():
    if request.method == 'POST':
        text = request.form['plaintxt']
        if not text:
            error_message = 'Please type in plaintext'
            return render_template('base64_encrypt.html', title='Base64', text=text, error=error_message)
        else:
            cipher = encrypt_base64(text)
            return render_template('base64_encrypt.html', title='Base64', text=text,data=cipher)
    return render_template('base64_encrypt.html', title='Base64')

@app.route("/Base64_decrypt", methods = ['POST','GET'])
def Base64_decrypt():
    if request.method == 'POST':
        text = request.form['ciphertxt']
        if not text:
            error_message = 'Please type in ciphertext'
            return render_template('base64_decrypt.html', title='Base64', text=text, error=error_message)
        else:
            plain = decrypt_base64(text)
            return render_template('base64_decrypt.html', title='Base64', text=text,data=plain)
    return render_template('base64_decrypt.html', title='Base64')

@app.route("/Reverse_encrypt", methods = ['POST','GET'])
def Reverse_encrypt():
    if request.method == 'POST':
        text = request.form['plaintxt']
        if not text:
            error_message = 'Please type in plaintext'
            return render_template('reverse_encrypt.html', title='Reverse', text=text, error=error_message)
        elif not re.match("^[a-zA-Z]+$", text):
            error_message = 'Please type in only character not number!'
            return render_template('reverse_encrypt.html', title='Reverse', text=text,error=error_message)
        else:
            cipher = encrypt_reverse(text)
            return render_template('reverse_encrypt.html', title='Reverse', text=text,data=cipher)

    return render_template('reverse_encrypt.html', title='Reverse')

@app.route("/Reverse_decrypt", methods = ['POST','GET'])
def Reverse_decrypt():
    if request.method == 'POST':
        text = request.form['ciphertxt']
        if not text:
            error_message = 'Please type in plaintext'
            return render_template('reverse_decrypt.html', title='Reverse', text=text, error=error_message)
        elif not re.match("^[a-zA-Z]+$", text):
            error_message = 'Please type in only character not number!'
            return render_template('reverse_decrypt.html', title='Reverse', text=text,error=error_message)
        else:
            plain = decrypt_reverse(text)
            return render_template('reverse_decrypt.html', title='Reverse', text=text,data=plain)
    return render_template('reverse_decrypt.html', title='Reverse')

@app.route("/Vigenere_encrypt", methods = ['POST', 'GET'])
def Vigenere_encrypt():
    if request.method == 'POST':
        text = request.form['plaintxt']
        key = request.form['keytxt']
        error_message = ''
        if (not text) and (not key):
            error_message = 'Please type in plaintext and key'
            return render_template('vigenere_encrypt.html', title='Vignere', text=text, key=key, error=error_message)
        elif not re.match("^[A-Z]+$", text):
            error_message = 'Please type in only UPPERCASE characters and not number!'
            return render_template('vigenere_encrypt.html', title='Vignere', text=text, key=key, error=error_message)
        elif not re.match("^[A-Z]+$", key):
            error_message = 'Please type in UPPERCASE characters for key'
            return render_template('vigenere_encrypt.html', title='Vignere', text=text, key=key, error=error_message)
        else:
            cipher = encrypt_vigenere(text,key)
            return render_template('vigenere_encrypt.html', title='Vignere', text=text, key=key, data=cipher)
    return render_template('vigenere_encrypt.html', title='Vignere')

@app.route("/Vigenere_decrypt", methods = ['POST', 'GET'])
def Vigenere_decrypt():
    if request.method == 'POST':
        text = request.form['ciphertxt']
        key = request.form['keytxt']
        error_message = ''
        if (not text) and (not key):
            error_message = 'Please type in ciphertext and key'
            return render_template('vigenere_decrypt.html', title='Vignere', text=text, key=key, error=error_message)
        elif not re.match("^[A-Z]+$", text):
            error_message = 'Please type in only UPPERCASE characters and not number!'
            return render_template('vigenere_decrypt.html', title='Vignere', text=text, key=key, error=error_message)
        elif not re.match("^[A-Z]+$", key):
            error_message = 'Please type in UPPERCASE characters for key'
            return render_template('vigenere_decrypt.html', title='Vignere', text=text, key=key, error=error_message)
        else:
            plain = decrypt_vigenere(text, key)
            return render_template('vigenere_decrypt.html', title='Vignere', text=text, key=key, data=plain)
    return render_template('vigenere_decrypt.html', title='Vignere')

@app.route("/Caesar_encrypt", methods = ['POST', 'GET'])
def Caesar_encrypt():
    if request.method == 'POST':
        text = request.form['plaintxt']
        key = request.form['keytxt']
        error_message = ''
        if (not text) and (not key):
            error_message = 'Please type in plaintext and key'
            return render_template('caesar_encrypt.html', title='Caesar', text=text, key=key, error=error_message)
        elif not re.match("^[a-zA-Z]+$", text):
            error_message='Please type in only UPPERCASE and not number!'
            return render_template('caesar_encrypt.html', title='Caesar', text=text, key=key,error=error_message)
        elif not re.match("^[0-9]+$",key):
            error_message='Please type in number for key'
            return render_template('caesar_encrypt.html', title='Caesar', text=text, key=key, error=error_message)
        else:
            cipher = encrypt_caesar(text,key)
            return render_template('caesar_encrypt.html', title='Caesar', text=text, key=key,data=cipher)
    return render_template('caesar_encrypt.html', title='Caesar')

@app.route("/Caesar_decrypt", methods=['POST', 'GET'])
def Caesar_decrypt():
    if request.method == 'POST':
        text = request.form['ciphertxt']
        key = request.form['keytxt']
        error_message = ''
        if (not text) and (not key):
            error_message = 'Please type in plaintext and key'
            return render_template('caesar_decrypt.html', title='Caesar', text=text, key=key, error=error_message)
        elif not re.match("^[a-zA-Z]+$", text):
            error_message = 'Please type in only UPPERCASE and not number!'
            return render_template('caesar_decrypt.html', title='Caesar', text=text, key=key, error=error_message)
        elif not re.match("^[0-9]+$", key):
            error_message = 'Please type in number for key'
            return render_template('caesar_decrypt.html', title='Caesar', text=text, key=key, error=error_message)
        else:
            plain = decrypt_caesar(text, key)
            return render_template('caesar_decrypt.html', title='Caesar', text=text, key=key, data=plain)
    return render_template('caesar_decrypt.html', title='Caesar')


if __name__ == '__main__':
    app.run(debug=True)