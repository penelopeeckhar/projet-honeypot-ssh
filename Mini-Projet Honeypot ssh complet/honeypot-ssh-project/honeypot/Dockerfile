FROM python:3.11-slim

# Installer les dépendances système + commandes pour le honeypot
RUN apt-get update && apt-get install -y \
    libseccomp-dev \
    libcap-dev \
    gcc \
    coreutils \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de travail
WORKDIR /app

# Copier les fichiers de requirements
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier les fichiers de l'application
COPY honeypot.py .
COPY seccomp-profile.json .

# Créer le répertoire pour les logs
RUN mkdir -p /var/log/honeypot

# Exposer le port SSH (2222)
EXPOSE 2222

# Lancer le honeypot
CMD ["python", "-u", "honeypot.py"]
