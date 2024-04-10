from Crypto.Cipher import ARC4
def decrypt_rc4(key, ciphertext):
  cipher = ARC4.new(key.encode('utf-8'))
  decrypted = cipher.decrypt(bytes.fromhex(ciphertext))
  return decrypted.decode('utf-8')

if __name__ == "__main__":
  encrypted_flag ="e6c7bead19a7b55225aa9beddebb26253fd78eee2a4ae1d64d52a07afcc7e3c7"
  decrypted_key = "s1mpl3p4ss"

decrypted_flag=decrypt_rc4(decryption_key, encrypted_flag) 
print(f"The decrypted flag is: HQ8{{{decrypted_flag}}}")
