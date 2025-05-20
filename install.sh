ORIG_DIR="$(pwd)"
DEST_DIR="../"

# Copiar Dockerfile
cp "$ORIG_DIR/Dockerfile" "$DEST_DIR" && echo "Dockerfile copiado a $DEST_DIR"

# Copiar docker-compose.yml
cp "$ORIG_DIR/docker-compose.yml" "$DEST_DIR" && echo "docker-compose.yml copiado a $DEST_DIR"