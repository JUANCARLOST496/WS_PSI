#!/bin/bash

set -e

echo "Actualizando sistema..."
sudo apt update && sudo apt upgrade -y

echo "Instalando paquetes necesarios..."
sudo apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

echo "Añadiendo clave GPG de Docker..."
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "Agregando repositorio oficial de Docker..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "Actualizando repositorios..."
sudo apt update

echo "Instalando Docker y Docker Compose..."
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "Añadiendo usuario actual al grupo docker..."
sudo usermod -aG docker $USER

echo "Para aplicar los cambios de grupo, cierra y vuelve a abrir la sesión o ejecuta:"
echo "  newgrp docker"

echo "Verificando instalación..."
docker --version
docker compose version

echo "Instalación completada exitosamente."
