import unittest
from pythonbeid.card_reader import CardReader

class TestCardReader(unittest.TestCase):
    def test_read_informations(self):
        cr = CardReader()
        info = cr.read_informations()
        self.assertIsNotNone(info)

if __name__ == '__main__':
    unittest.main()
