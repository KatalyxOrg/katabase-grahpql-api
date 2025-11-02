#!/bin/bash

# Script de sauvegarde de la base de données Katabase GraphQL API
# Usage: ./backup.sh [nom_optionnel]

set -e

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME=${1:-"katabasegql_api_backup_${DATE}"}

echo "🗄️ Début de la sauvegarde de la base de données..."
echo "📅 Date: $(date)"
echo "📁 Nom de la sauvegarde: ${BACKUP_NAME}"

# Création du répertoire de sauvegarde s'il n'existe pas
mkdir -p "$BACKUP_DIR"

# Sauvegarde de la base de données
echo "💾 Création de la sauvegarde..."
pg_dump \
  --host="$PGHOST" \
  --username="$PGUSER" \
  --dbname="$PGDATABASE" \
  --format=custom \
  --no-owner \
  --no-privileges \
  --verbose \
  --file="$BACKUP_DIR/${BACKUP_NAME}.dump"

# Création d'une sauvegarde SQL lisible
echo "📄 Création de la sauvegarde SQL..."
pg_dump \
  --host="$PGHOST" \
  --username="$PGUSER" \
  --dbname="$PGDATABASE" \
  --no-owner \
  --no-privileges \
  --clean \
  --if-exists \
  --verbose \
  --file="$BACKUP_DIR/${BACKUP_NAME}.sql"

# Compression des fichiers
echo "🗜️ Compression des sauvegardes..."
gzip "$BACKUP_DIR/${BACKUP_NAME}.sql"

# Vérification de la sauvegarde
if [ -f "$BACKUP_DIR/${BACKUP_NAME}.dump" ] && [ -f "$BACKUP_DIR/${BACKUP_NAME}.sql.gz" ]; then
    echo "✅ Sauvegarde créée avec succès:"
    echo "   - ${BACKUP_NAME}.dump (format binaire)"
    echo "   - ${BACKUP_NAME}.sql.gz (format SQL compressé)"
    
    # Affichage de la taille des fichiers
    ls -lh "$BACKUP_DIR/${BACKUP_NAME}".* | awk '{print "   - "$9" ("$5")"}'
else
    echo "❌ Erreur lors de la création de la sauvegarde"
    exit 1
fi

# Nettoyage des anciennes sauvegardes (garde les 7 dernières)
echo "🧹 Nettoyage des anciennes sauvegardes..."
cd "$BACKUP_DIR"
ls -t katabasegql_api_backup_*.dump 2>/dev/null | tail -n +8 | xargs -r rm -f
ls -t katabasegql_api_backup_*.sql.gz 2>/dev/null | tail -n +8 | xargs -r rm -f

echo "🎉 Sauvegarde terminée avec succès!"