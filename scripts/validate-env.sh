#!/bin/bash
set -e

ERRORS=0

check_length() {
    local var_name=$1
    local min_len=$2
    local val=${!var_name:-}
    if [ -n "$val" ] && [ ${#val} -lt $min_len ]; then
        echo "WARNING: $var_name is set but shorter than $min_len characters"
        ERRORS=$((ERRORS + 1))
    fi
}

check_not_default() {
    local var_name=$1
    local default_val=$2
    local val=${!var_name:-}
    if [ "$val" = "$default_val" ]; then
        echo "WARNING: $var_name is set to insecure default value: $default_val"
        ERRORS=$((ERRORS + 1))
    fi
}

check_length "ADMIN_API_KEY" 32
check_not_default "ADMIN_API_KEY" "dev-admin-key-must-be-at-least-32-characters-long"

if [ "${REQUIRE_TLS:-false}" = "false" ]; then
    echo "WARNING: REQUIRE_TLS is false. Set to true in production."
    ERRORS=$((ERRORS + 1))
fi

if [ -z "${REDIS_URL:-}" ]; then
    echo "WARNING: REDIS_URL is not set. In-memory storage will be used (data lost on restart)."
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -gt 0 ]; then
    echo "Found $ERRORS configuration warning(s)."
    exit 1
fi

echo "Configuration validation passed."