import struct

class SHA1:
    """
    Реалізація геш-функції SHA-1 згідно з FIPS 180-2.
    Стандарт: https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
    """
    
    def __init__(self):
        # Ініціалізація змінних (h0-h4)
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0
        
    @staticmethod
    def left_rotate(n, b):
        """Циклічний зсув вліво на b бітів для 32-бітного слова."""
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
    def padding(self, message):
        """
        Додавання padding до повідомлення згідно зі стандартом SHA-1.
        Формат: message + 1 + zeros + length (64 біти)
        """
        # Перетворення повідомлення у байти
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        ml = len(message) * 8  # довжина в бітах
        
        # Додавання біта '1'
        message += b'\x80'
        
        # Додавання нулів до довжини 448 mod 512
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        
        # Додавання довжини повідомлення як 64-бітне big-endian число
        message += struct.pack('>Q', ml)
        
        return message
    
    def process_chunk(self, chunk):
        """Обробка одного 512-бітного (64-байтного) чанку."""
        # Розбиття чанку на 16 32-бітних слів
        w = list(struct.unpack('>16L', chunk))
        
        # Розширення до 80 слів
        for i in range(16, 80):
            w.append(self.left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))
        
        # Ініціалізація змінних a-e
        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4
        
        # Головний цикл
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:  # 60-79
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            temp = (self.left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = self.left_rotate(b, 30)
            b = a
            a = temp
        
        # Оновлення значень h0-h4
        self.h0 = (self.h0 + a) & 0xffffffff
        self.h1 = (self.h1 + b) & 0xffffffff
        self.h2 = (self.h2 + c) & 0xffffffff
        self.h3 = (self.h3 + d) & 0xffffffff
        self.h4 = (self.h4 + e) & 0xffffffff
    
    def hash(self, message):
        """
        Обчислення SHA-1 гешу для повідомлення.
        Повертає геш у вигляді шістнадцяткового рядка.
        """
        # Скидання стану
        self.__init__()
        
        # Додавання padding
        padded = self.padding(message)
        
        # Обробка чанків по 64 байти
        for i in range(0, len(padded), 64):
            chunk = padded[i:i+64]
            self.process_chunk(chunk)
        
        # Формування фінального гешу
        result = struct.pack('>5L', self.h0, self.h1, self.h2, self.h3, self.h4)
        return result.hex()

# ========== ТЕСТУВАННЯ SHA-1 ==========
def test_sha1():
    """Тестові вектори з FIPS 180-2"""
    sha = SHA1()
    
    # Тест 1: Пустий рядок
    assert sha.hash("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    
    # Тест 2: "abc"
    assert sha.hash("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    
    # Тест 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    test_str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    assert sha.hash(test_str) == "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    
    # Тест 4: 1 мільйон символів 'a'
    million_a = "a" * 1000000
    assert sha.hash(million_a) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    
    print("Всі тести SHA-1 пройдені успішно!")
    return True

if __name__ == "__main__":
    test_sha1()
    
    # Демонстрація роботи
    sha = SHA1()
    test_messages = [
        "Hello, World!",
        "Кирилиця теж працює",
        "1234567890",
        "The quick brown fox jumps over the lazy dog"
    ]
    
    print("\nДемонстрація SHA-1:")
    for msg in test_messages:
        print(f"'{msg}' -> {sha.hash(msg)}")
