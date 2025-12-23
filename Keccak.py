class Keccak:
    """
    Реалізація геш-функції Keccak (основа SHA-3) згідно з FIPS 202.
    Стандарт: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    
    Параметри:
    - r: bitrate (розмір блоку)
    - c: capacity (місткість)
    - output_len: довжина вихідного гешу (у байтах)
    """
    
    # Константи для раундів
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]
    
    # Матриця зсувів для ρ-етапу
    RHO = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]
    
    def __init__(self, r=1088, c=512, output_len=32):
        """
        Ініціалізація Keccak з параметрами:
        - r = 1088, c = 512 для Keccak-256 (аналог SHA3-256)
        - output_len: 32 байти для 256-бітного виходу
        """
        self.r = r  # bitrate (у бітах)
        self.c = c  # capacity (у бітах)
        self.output_len = output_len  # довжина гешу у байтах
        self.state = [[0] * 5 for _ in range(5)]  # стан 5x5 64-бітних слів
        self.w = 64  # розмір слова (біт)
        
    @staticmethod
    def rot64(x, n):
        """Циклічний зсув 64-бітного слова вліво."""
        return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)
    
    def theta(self):
        """θ-етап: лінійне перемішування."""
        C = [0] * 5
        D = [0] * 5
        
        # Обчислення C[x] = XOR всіх A[x,y]
        for x in range(5):
            C[x] = self.state[x][0]
            for y in range(1, 5):
                C[x] ^= self.state[x][y]
        
        # Обчислення D[x] = C[x-1] XOR rot(C[x+1], 1)
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ self.rot64(C[(x + 1) % 5], 1)
        
        # Застосування D до стану
        for x in range(5):
            for y in range(5):
                self.state[x][y] ^= D[x]
    
    def rho_pi(self):
        """ρ та π-етапи: нелінійне перемішування та перестановка."""
        B = [[0] * 5 for _ in range(5)]
        
        # ρ: циклічний зсув
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = self.rot64(self.state[x][y], self.RHO[x][y])
        
        # π: копіювання назад у стан
        for x in range(5):
            for y in range(5):
                self.state[x][y] = B[x][y]
    
    def chi(self):
        """χ-етап: нелінійна підстановка."""
        B = [[0] * 5 for _ in range(5)]
        
        # Копіювання стану
        for x in range(5):
            for y in range(5):
                B[x][y] = self.state[x][y]
        
        # Застосування χ
        for x in range(5):
            for y in range(5):
                self.state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
    
    def iota(self, round_idx):
        """ι-етап: додавання константи раунду."""
        self.state[0][0] ^= self.RC[round_idx]
    
    def keccak_f(self):
        """Функція перестановки f (24 раунди)."""
        for i in range(24):
            self.theta()
            self.rho_pi()
            self.chi()
            self.iota(i)
    
    def padding(self, message_bytes, suffix=0x01):
        """
        Додавання padding для Keccak (паттерн 10*1).
        Suffix:
          - 0x01 для SHA3 (після повідомлення додається '011')
          - 0x06 для SHA3, 0x1F для Keccak
        """
        # Додавання suffix (доменне розділення)
        message_bytes += bytes([suffix])
        
        # Обчислення кількості байтів для додавання
        block_bytes = self.r // 8
        pad_len = block_bytes - (len(message_bytes) % block_bytes)
        
        if pad_len == 0:
            pad_len = block_bytes
        
        # Додавання паттерну 10*1
        padding = bytes([0x00] * (pad_len - 1) + [0x80])
        return message_bytes + padding
    
    def absorb(self, padded_message):
        """Фаза поглинання (absorbing phase)."""
        block_bytes = self.r // 8
        
        for i in range(0, len(padded_message), block_bytes):
            block = padded_message[i:i + block_bytes]
            
            # XOR блоку зі станом
            for j in range(len(block) // 8):
                x = j % 5
                y = j // 5
                word = int.from_bytes(block[j*8:(j+1)*8], 'little')
                self.state[x][y] ^= word
            
            # Застосування перестановки
            self.keccak_f()
    
    def squeeze(self):
        """Фаза віджимання (squeezing phase)."""
        output = b''
        block_bytes = self.r // 8
        
        while len(output) < self.output_len:
            # Читання зі стану
            block = b''
            for j in range(block_bytes // 8):
                x = j % 5
                y = j // 5
                block += self.state[x][y].to_bytes(8, 'little')
            
            output += block[:min(len(block), self.output_len - len(output))]
            
            if len(output) < self.output_len:
                self.keccak_f()
        
        return output[:self.output_len]
    
    def hash(self, message, suffix=0x06):
        """
        Обчислення гешу Keccak.
        Параметри за замовчуванням відповідають SHA3-256.
        """
        # Скидання стану
        self.state = [[0] * 5 for _ in range(5)]
        
        # Перетворення повідомлення у байти
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        
        # Додавання padding
        padded = self.padding(message_bytes, suffix)
        
        # Фази поглинання та віджимання
        self.absorb(padded)
        return self.squeeze().hex()

# ========== СПЕЦИФІЧНІ ВАРІАНТИ ==========
class SHA3_256(Keccak):
    """SHA3-256: r=1088, c=512, output_len=32"""
    def __init__(self):
        super().__init__(r=1088, c=512, output_len=32)
    
    def hash(self, message):
        return super().hash(message, suffix=0x06)

class SHA3_512(Keccak):
    """SHA3-512: r=576, c=1024, output_len=64"""
    def __init__(self):
        super().__init__(r=576, c=1024, output_len=64)
    
    def hash(self, message):
        return super().hash(message, suffix=0x06)

class Keccak256(Keccak):
    """Оригінальний Keccak-256 (використовується в Ethereum)"""
    def __init__(self):
        super().__init__(r=1088, c=512, output_len=32)
    
    def hash(self, message):
        return super().hash(message, suffix=0x01)

# ========== ТЕСТУВАННЯ KECCAK/SHA3 ==========
def test_keccak():
    """Тестові вектори з FIPS 202 та інші стандартні тести."""
    
    # Тести для SHA3-256
    sha3 = SHA3_256()
    
    # Тест 1: Пустий рядок
    assert sha3.hash("") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    
    # Тест 2: "abc"
    assert sha3.hash("abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    
    # Тест 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    test_str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    expected = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    assert sha3.hash(test_str) == expected
    
    print("Всі тести SHA3-256 пройдені успішно!")
    
    # Тест для Keccak-256 (Ethereum)
    keccak = Keccak256()
    assert keccak.hash("") == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    
    # Відомий тест для "hello world"
    assert keccak.hash("hello world") == "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
    
    print("Всі тести Keccak-256 пройдені успішно!")
    return True

if __name__ == "__main__":
    test_keccak()
    
    # Демонстрація роботи
    print("\nДемонстрація SHA3-256:")
    sha3 = SHA3_256()
    test_messages = [
        "Hello, World!",
        "Кирилиця теж працює",
        "1234567890",
        "The quick brown fox jumps over the lazy dog"
    ]
    
    for msg in test_messages:
        print(f"'{msg}' -> {sha3.hash(msg)}")
    
    print("\nДемонстрація Keccak-256 (Ethereum):")
    keccak = Keccak256()
    for msg in test_messages:
        print(f"'{msg}' -> {keccak.hash(msg)}")
