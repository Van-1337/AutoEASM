import concurrent.futures
import math
import time

def process_element(element):
    # Здесь разместите вашу логику обработки элемента
    # Например:
    result = element ** 2  # Пример обработки
    time.sleep(1)
    return result

def process_chunk(chunk):
    return [process_element(element) for element in chunk]

def split_array(array, num_chunks):
    chunk_size = math.ceil(len(array) / num_chunks)
    return [array[i*chunk_size : (i+1)*chunk_size] for i in range(num_chunks)]

def main():
    array = list(range(100))  # Пример массива
    num_threads = 4  # Количество потоков

    chunks = split_array(array, num_threads)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Отправляем каждый кусок на обработку в отдельном потоке
        future_to_chunk = {executor.submit(process_chunk, chunk): chunk for chunk in chunks}
        for future in concurrent.futures.as_completed(future_to_chunk):
            chunk_result = future.result()
            results.extend(chunk_result)

    print("Результаты обработки:", results)

if __name__ == "__main__":
    main()
