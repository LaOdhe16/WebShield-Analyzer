FROM python:3.10-slim

# Set working directory di dalam kontainer
WORKDIR /app

# Install dependensi sistem yang diperlukan 
RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

# file requirements.txt ke dalam kontainer
COPY requirements.txt .

# Install library python
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Expose port yang digunakan Flask
EXPOSE 5000

# Jalankan aplikasi 
CMD ["python", "app.py"]