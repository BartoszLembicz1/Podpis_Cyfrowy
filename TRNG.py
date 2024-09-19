from pynput.mouse import Listener
import numpy as np
import matplotlib.pyplot as plt
import sys

def chaotic_map(x, r, k=30, c=0.5):
    f_x = x  # Prosta funkcja f(x) = x
    return ((k + r) * f_x) / (k * c + r * f_x)  # Funkcja mapy chaotycznej

def on_move(x, y):
    global continuous_data, x_previous, y_previous, target_bits
    if len(continuous_data) >= target_bits:
        return False  # Zatrzymaj nasłuchiwanie, gdy osiągnięto cel ilości bitów

    if x_previous is not None and y_previous is not None:
        dx = x - x_previous  # Obliczenie różnicy poziomej pozycji myszy
        dy = y - y_previous  # Obliczenie różnicy pionowej pozycji myszy
        num_iterations = int(abs(dx))  # Liczba iteracji na podstawie różnicy w położeniu x
        x_0 = dy / 900  # Normalizacja początkowej wartości x_0
        
        x_current = x_0
        r = dx - 22.6  # Dostosowanie wartości r, aby była > -22.5, zapewniając zachowanie chaotyczne
        
        for _ in range(num_iterations):
            x_next = chaotic_map(x_current, r)
            continuous_data.append(x_next)
            x_current = x_next
            
    x_previous, y_previous = x, y

continuous_data = []
x_previous = y_previous = None
target_bits = 1000000

with Listener(on_move=on_move) as listener:
    listener.join()

# Histogram i entropia dla danych bezpośrednio z chaotic_map
probabilities_raw, _ = np.histogram(continuous_data, bins=50, range=(min(continuous_data), max(continuous_data)), density=True)
entropy_raw = -np.sum(probabilities_raw * np.log2(probabilities_raw + np.finfo(float).eps))

plt.figure(figsize=(12, 6))
plt.hist(continuous_data, bins=50, density=True, color='red', edgecolor='black')
plt.yscale('log')
plt.title('Histogram Bezpośrednio z Chaotic Map')
plt.xlabel('Wartości wyjściowe z Chaotic Map')
plt.ylabel('Logarytmiczne Prawdopodobieństwo')
plt.figtext(0.5, 0.01, f'Entropia danych: {entropy_raw:.4f} bitów', ha="center", fontsize=12, bbox={"facecolor":"orange", "alpha":0.5, "pad":5})
plt.show()

# Przeskalowanie danych i kwantyzacja do wartości 8-bitowych (1-255)
scaled_data = np.array(continuous_data)
scaled_data = 1/255 + (scaled_data * (254/255))
quantized_values = (scaled_data * 255 - 1).astype(np.uint8)

seed = int.from_bytes(quantized_values.tobytes(), 'big')
sys.set_int_max_str_digits(100000000)
with open("seed.txt", 'w') as seed_file:
        seed_file.write(str(seed))

# Histogram i entropia po przeskalowaniu i kwantyzacji
probabilities_quantized, _ = np.histogram(quantized_values, bins=255, range=(1, 255), density=True)
entropy_quantized = -np.sum(probabilities_quantized * np.log2(probabilities_quantized + np.finfo(float).eps))

plt.figure(figsize=(12, 6))
plt.hist(quantized_values, bins=255, range=(1, 255), density=True, color='blue', edgecolor='black')
plt.yscale('log')
plt.title('Histogram Po Przeskalowaniu i Kwantyzacji')
plt.xlabel('Wartość 8-bitowa')
plt.ylabel('Logarytmiczne Prawdopodobieństwo')
plt.figtext(0.5, 0.01, f'Entropia danych: {entropy_quantized:.4f} bitów', ha="center", fontsize=12, bbox={"facecolor":"orange", "alpha":0.5, "pad":5})
plt.show()
