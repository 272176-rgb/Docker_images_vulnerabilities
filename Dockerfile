# Wybierz obraz bazowy Pythona
FROM python:3.9-slim

# Ustaw katalog roboczy w kontenerze
WORKDIR /app

# Skopiuj plik requirements.txt do katalogu roboczego
COPY requirements.txt /app/

# Zainstaluj zależności
RUN pip install --no-cache-dir -r requirements.txt

# Skopiuj wszystkie pliki projektu do katalogu roboczego
COPY . /app/

# Określ port, na którym aplikacja będzie nasłuchiwać
EXPOSE 8080

# Określ komendę uruchamiającą aplikację
CMD ["python", "app.py"]
