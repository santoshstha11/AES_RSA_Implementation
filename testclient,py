import unittest
from client import encrypt_data, decrypt_data, encrypt_key, decrypt_key, generate_key

class TestClient(unittest.TestCase):
    def setUp(self):
        self.key = generate_key("password", b"salt")
        self.msg = "Hello from the client!"
        self.public_key = RSA.generate(2048)
        self.private_key = self.public_key.publickey()

    def test_encrypt_decrypt_data(self):
        encrypted_data = encrypt_data(self.msg.encode('utf-8'), self.key)
        decrypted_data = decrypt_data(encrypted_data, self.key)
        self.assertEqual(self.msg.encode('utf-8'), decrypted_data)

    def test_encrypt_decrypt_key(self):
        encrypted_key = encrypt_key(self.key, self.public_key)
        decrypted_key = decrypt_key(encrypted_key, self.private_key)
        self.assertEqual(self.key, decrypted_key)

if __name__ == '__main__':
    unittest.main()
