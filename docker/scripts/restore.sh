#!/bin/bash

# Script de restauration de la base de données Katabase GraphQL API
# Usage: ./restore.sh <nom_de_la_sauvegarde>

set -e

if [ $# -eq 0 ]; then
    echo "❌ Erreur: Nom de la sauvegarde requis"
    echo "Usage: ./restore.sh <nom_de_la_sauvegarde>"
    echo ""
    echo "Sauvegardes disponibles:"
    ls -la /backups/katabasegql_api_backup_*.dump 2>/dev/null | awk '{print "  - "$9}' | sed 's|.*/||' | sed 's|\.dump||' || echo "  Aucune sauvegarde trouvée"
    exit 1
fi

BACKUP_NAME="$1"
BACKUP_DIR="/backups"
DUMP_FILE="$BACKUP_DIR/${BACKUP_NAME}.dump"
SQL_FILE="$BACKUP_DIR/${BACKUP_NAME}.sql.gz"

echo "🔄 Début de la restauration de la base de données..."
echo "📅 Date: $(date)"
echo "📁 Sauvegarde: ${BACKUP_NAME}"

# Vérification de l'existence du fichier de sauvegarde
if [ ! -f "$DUMP_FILE" ] && [ ! -f "$SQL_FILE" ]; then
    echo "❌ Erreur: Fichier de sauvegarde non trouvé"
    echo "Recherché: $DUMP_FILE ou $SQL_FILE"
    exit 1
fi

# Confirmation avant restauration
echo "⚠️  ATTENTION: Cette opération va écraser la base de données actuelle!"
echo "Voulez-vous continuer? (oui/non)"
read -r confirmation

if [ "$confirmation" != "oui" ]; then
    echo "🚫 Restauration annulée"
    exit 0
fi

# Sauvegarde préventive avant restauration
echo "💾 Création d'une sauvegarde préventive..."
./backup.sh "pre_restore_$(date +%Y%m%d_%H%M%S)"

# Restauration
if [ -f "$DUMP_FILE" ]; then
    echo "🔄 Restauration depuis le fichier dump..."
    pg_restore \
        --host="$PGHOST" \
        --username="$PGUSER" \
        --dbname="$PGDATABASE" \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        --verbose \
        "$DUMP_FILE"
elif [ -f "$SQL_FILE" ]; then
    echo "🔄 Restauration depuis le fichier SQL..."
    gunzip -c "$SQL_FILE" | psql \
        --host="$PGHOST" \
        --username="$PGUSER" \
        --dbname="$PGDATABASE"
fi

echo "✅ Restauration terminée avec succès!"
echo "🔍 Vérification de la connexion à la base de données..."

# Test de connexion
if psql --host="$PGHOST" --username="$PGUSER" --dbname="$PGDATABASE" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Base de données accessible"
else
    echo "❌ Problème de connexion à la base de données"
    exit 1
fi