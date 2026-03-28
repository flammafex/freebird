#!/usr/bin/env bash
#
# Freebird Backup & Recovery Script
#
# Usage:
#   ./scripts/backup-restore.sh backup              # Create backup
#   ./scripts/backup-restore.sh restore <backup>    # Restore from backup
#   ./scripts/backup-restore.sh list                # List available backups
#   ./scripts/backup-restore.sh verify <backup>     # Verify backup integrity
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
COMPRESS="${COMPRESS:-true}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Create backup directory
mkdir -p "$BACKUP_DIR"

# ============================================================================
# BACKUP FUNCTION
# ============================================================================
backup() {
    print_header "Freebird Backup"

    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_path="$BACKUP_DIR/freebird-backup-$timestamp"

    echo "Backup directory: $backup_path"
    mkdir -p "$backup_path"

    # Backup metadata
    cat > "$backup_path/BACKUP.info" << EOF
Backup Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Freebird Project: $PROJECT_ROOT
Docker Compose Status: $(docker-compose version 2>/dev/null || echo "unknown")")
EOF

    print_header "Backing up Issuer Keys"

    # Backup issuer data from container volume
    if docker volume inspect issuer-data &>/dev/null; then
        mkdir -p "$backup_path/issuer-keys"
        print_success "Found issuer-data volume"

        # Extract keys from volume
        docker run --rm \
            -v issuer-data:/source \
            -v "$backup_path/issuer-keys:/backup" \
            alpine:latest \
            sh -c "cp -r /source/keys/* /backup/ 2>/dev/null || true"

        # Verify key files exist
        if [[ -f "$backup_path/issuer-keys/issuer_sk.bin" ]]; then
            print_success "Backed up issuer_sk.bin"
        else
            print_warning "issuer_sk.bin not found"
        fi

        if [[ -f "$backup_path/issuer-keys/key_rotation_state.json" ]]; then
            print_success "Backed up key_rotation_state.json"
        else
            print_warning "key_rotation_state.json not found"
        fi
    else
        print_warning "issuer-data volume not found"
    fi

    print_header "Backing up Issuer State"

    # Backup invitation state
    if docker volume inspect issuer-data &>/dev/null; then
        mkdir -p "$backup_path/issuer-state"

        docker run --rm \
            -v issuer-data:/source \
            -v "$backup_path/issuer-state:/backup" \
            alpine:latest \
            sh -c "cp -r /source/state/* /backup/ 2>/dev/null || true"

        if [[ -f "$backup_path/issuer-state/invitations.json" ]]; then
            print_success "Backed up invitations.json"
        else
            print_warning "invitations.json not found"
        fi
    fi

    print_header "Backing up Redis Data"

    # Trigger Redis save
    if docker-compose exec -T redis redis-cli BGSAVE &>/dev/null; then
        print_success "Triggered Redis background save"
        sleep 2  # Wait for save to complete
    else
        print_warning "Could not trigger Redis save"
    fi

    # Backup Redis dump
    mkdir -p "$backup_path/redis"
    if docker volume inspect redis-data &>/dev/null; then
        docker run --rm \
            -v redis-data:/source \
            -v "$backup_path/redis:/backup" \
            alpine:latest \
            sh -c "cp /source/dump.rdb /backup/ 2>/dev/null || true"

        if [[ -f "$backup_path/redis/dump.rdb" ]]; then
            print_success "Backed up Redis dump.rdb"
        else
            print_warning "Redis dump.rdb not found"
        fi
    fi

    print_header "Creating Backup Archive"

    # Create tar archive
    local archive_name="freebird-backup-$timestamp"
    if [[ "$COMPRESS" == "true" ]]; then
        archive_name="$archive_name.tar.gz"
        tar -czf "$BACKUP_DIR/$archive_name" -C "$BACKUP_DIR" "freebird-backup-$timestamp"
        print_success "Created compressed archive: $archive_name"
    else
        archive_name="$archive_name.tar"
        tar -cf "$BACKUP_DIR/$archive_name" -C "$BACKUP_DIR" "freebird-backup-$timestamp"
        print_success "Created archive: $archive_name"
    fi

    # Calculate backup size
    local backup_size=$(du -sh "$BACKUP_DIR/$archive_name" | cut -f1)
    print_success "Backup size: $backup_size"

    # Cleanup extracted directory
    rm -rf "$backup_path"

    print_header "Backup Summary"
    echo "Location: $BACKUP_DIR/$archive_name"
    echo "Size: $backup_size"
    echo "Timestamp: $timestamp"

    # Cleanup old backups
    print_header "Cleaning Up Old Backups"
    local old_backups=$(find "$BACKUP_DIR" -name "freebird-backup-*.tar*" -mtime +$BACKUP_RETENTION_DAYS 2>/dev/null | wc -l)
    if [[ $old_backups -gt 0 ]]; then
        find "$BACKUP_DIR" -name "freebird-backup-*.tar*" -mtime +$BACKUP_RETENTION_DAYS -delete
        print_success "Removed $old_backups old backup(s)"
    fi

    echo ""
    print_success "Backup completed successfully!"
}

# ============================================================================
# LIST BACKUPS FUNCTION
# ============================================================================
list_backups() {
    print_header "Available Backups"

    if [[ ! -d "$BACKUP_DIR" ]]; then
        print_error "Backup directory not found: $BACKUP_DIR"
        return 1
    fi

    local backups=($(find "$BACKUP_DIR" -name "freebird-backup-*.tar*" -type f 2>/dev/null | sort -r))

    if [[ ${#backups[@]} -eq 0 ]]; then
        print_warning "No backups found"
        return 0
    fi

    echo ""
    echo "Found ${#backups[@]} backup(s):"
    echo ""
    printf "%-40s %10s %20s\n" "Backup File" "Size" "Created"
    echo "-----------------------------------------------------------"

    for backup in "${backups[@]}"; do
        local size=$(du -sh "$backup" | cut -f1)
        local created=$(stat -f %Sm -t %Y-%m-%d\ %H:%M:%S "$backup" 2>/dev/null || stat -c %y "$backup" 2>/dev/null | cut -d. -f1)
        local filename=$(basename "$backup")
        printf "%-40s %10s %20s\n" "$filename" "$size" "$created"
    done
}

# ============================================================================
# VERIFY BACKUP FUNCTION
# ============================================================================
verify_backup() {
    local backup_file="$1"

    if [[ ! -f "$backup_file" ]]; then
        # Try to find backup in backup directory
        backup_file="$BACKUP_DIR/$backup_file"
        if [[ ! -f "$backup_file" ]]; then
            print_error "Backup file not found: $1"
            return 1
        fi
    fi

    print_header "Verifying Backup"
    echo "File: $(basename "$backup_file")"

    # Check file integrity
    if tar -tzf "$backup_file" &>/dev/null || tar -tf "$backup_file" &>/dev/null; then
        print_success "Archive integrity verified"
    else
        print_error "Archive is corrupted"
        return 1
    fi

    # List contents
    print_header "Backup Contents"

    if [[ "$backup_file" == *.tar.gz ]]; then
        tar -tzf "$backup_file" | head -20
    else
        tar -tf "$backup_file" | head -20
    fi

    # Check for critical files
    print_header "Critical Files"

    local has_issuer_key=false
    local has_redis_dump=false

    if tar -tzf "$backup_file" 2>/dev/null | grep -q "issuer_sk.bin"; then
        print_success "Contains issuer_sk.bin"
        has_issuer_key=true
    elif tar -tf "$backup_file" 2>/dev/null | grep -q "issuer_sk.bin"; then
        print_success "Contains issuer_sk.bin"
        has_issuer_key=true
    else
        print_warning "Missing issuer_sk.bin"
    fi

    if tar -tzf "$backup_file" 2>/dev/null | grep -q "dump.rdb"; then
        print_success "Contains Redis dump"
        has_redis_dump=true
    elif tar -tf "$backup_file" 2>/dev/null | grep -q "dump.rdb"; then
        print_success "Contains Redis dump"
        has_redis_dump=true
    else
        print_warning "Missing Redis dump"
    fi

    echo ""
    if [[ "$has_issuer_key" == true ]] && [[ "$has_redis_dump" == true ]]; then
        print_success "Backup contains all critical components"
        return 0
    else
        print_warning "Backup is incomplete"
        return 1
    fi
}

# ============================================================================
# RESTORE FUNCTION
# ============================================================================
restore() {
    local backup_file="$1"

    if [[ ! -f "$backup_file" ]]; then
        # Try to find backup in backup directory
        backup_file="$BACKUP_DIR/$backup_file"
        if [[ ! -f "$backup_file" ]]; then
            print_error "Backup file not found: $1"
            return 1
        fi
    fi

    print_header "Freebird Restore"
    echo "Source: $(basename "$backup_file")"

    # Confirm restore
    read -p "WARNING: This will overwrite current data. Continue? (yes/no) " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Restore cancelled"
        return 0
    fi

    # Create temporary directory
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    print_header "Extracting Backup"

    # Extract backup
    if [[ "$backup_file" == *.tar.gz ]]; then
        tar -xzf "$backup_file" -C "$temp_dir"
    else
        tar -xf "$backup_file" -C "$temp_dir"
    fi
    print_success "Backup extracted"

    # Find extracted directory
    local extracted_dir=$(ls -d "$temp_dir"/freebird-backup-* 2>/dev/null | head -1)
    if [[ -z "$extracted_dir" ]]; then
        print_error "Could not find extracted backup directory"
        return 1
    fi

    print_header "Stopping Services"

    # Stop containers
    docker-compose down || true
    print_success "Services stopped"

    print_header "Restoring Issuer Keys"

    # Restore issuer keys
    if [[ -d "$extracted_dir/issuer-keys" ]]; then
        docker run --rm \
            -v issuer-data:/data \
            -v "$extracted_dir/issuer-keys:/backup" \
            alpine:latest \
            sh -c "cp -r /backup/* /data/keys/ 2>/dev/null || true"
        print_success "Restored issuer keys"
    fi

    print_header "Restoring Issuer State"

    # Restore issuer state
    if [[ -d "$extracted_dir/issuer-state" ]]; then
        docker run --rm \
            -v issuer-data:/data \
            -v "$extracted_dir/issuer-state:/backup" \
            alpine:latest \
            sh -c "cp -r /backup/* /data/state/ 2>/dev/null || true"
        print_success "Restored issuer state"
    fi

    print_header "Restoring Redis Data"

    # Restore Redis dump
    if [[ -f "$extracted_dir/redis/dump.rdb" ]]; then
        docker run --rm \
            -v redis-data:/data \
            -v "$extracted_dir/redis:/backup" \
            alpine:latest \
            sh -c "cp /backup/dump.rdb /data/"
        print_success "Restored Redis data"
    fi

    print_header "Starting Services"

    # Start services
    docker-compose up -d
    print_success "Services started"

    # Wait for services to be ready
    echo "Waiting for services to be ready..."
    sleep 10

    # Verify restoration
    print_header "Verifying Restoration"

    if curl -sf http://localhost:8081/.well-known/issuer &>/dev/null; then
        print_success "Issuer is responding"
    else
        print_warning "Issuer may not be ready yet"
    fi

    if curl -sf http://localhost:8082/v1/check &>/dev/null; then
        print_success "Verifier is responding"
    else
        print_warning "Verifier may not be ready yet"
    fi

    echo ""
    print_success "Restore completed!"
    echo ""
    echo "Next steps:"
    echo "  1. Verify services are running: docker-compose logs -f"
    echo "  2. Check admin API: curl http://localhost:8081/.well-known/issuer"
    echo "  3. Test token issuance/verification"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    local command="${1:-}"

    case "$command" in
        backup)
            backup
            ;;
        list)
            list_backups
            ;;
        verify)
            if [[ -z "${2:-}" ]]; then
                print_error "Please specify backup file: verify <backup>"
                return 1
            fi
            verify_backup "$2"
            ;;
        restore)
            if [[ -z "${2:-}" ]]; then
                print_error "Please specify backup file: restore <backup>"
                return 1
            fi
            restore "$2"
            ;;
        *)
            echo "Freebird Backup & Recovery Utility"
            echo ""
            echo "Usage:"
            echo "  $0 backup              Create a new backup"
            echo "  $0 list                List available backups"
            echo "  $0 verify <backup>     Verify backup integrity"
            echo "  $0 restore <backup>    Restore from backup"
            echo ""
            echo "Examples:"
            echo "  $0 backup"
            echo "  $0 list"
            echo "  $0 verify freebird-backup-20240101-120000.tar.gz"
            echo "  $0 restore freebird-backup-20240101-120000.tar.gz"
            echo ""
            return 1
            ;;
    esac
}

main "$@"
