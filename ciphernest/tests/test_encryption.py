import unittest
from ciphernest.encryption import SymmetricEncryption


class TestEncryption(unittest.TestCase):

    def test_encrypt_decrypt(self):
        key = SymmetricEncryption.generate_key()
        message = b"test message"

        encrypted = SymmetricEncryption.encrypt(message, key)
        decrypted = SymmetricEncryption.decrypt(encrypted, key)

        self.assertEqual(message, decrypted)


if __name__ == "__main__":
    unittest.main()
