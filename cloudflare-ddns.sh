#!/bin/bash

# Script version for comparison
TOOL_VERSION="2.0.1"
TOOL_VERSION_DATE="2025-07-16"        # Date of the version update
IPV6_ONLY=false


# Constants
INSTALL_DIR="/usr/local/bin/cloudflare-ddns"
SCRIPT_NAME="cloudflare-ddns"
CONFIG_NAME="config.toml"
CONFIG_DIR="/etc/cloudflare-ddns"
CONFIG_FILE="$CONFIG_DIR/config.toml"
LOGFILE="/var/log/cloudflare-ddns.log"
CRON_EXPRESSION="*/5 * * * *"
CRON_JOB="$CRON_EXPRESSION $INSTALL_DIR/$SCRIPT_NAME --run >> $LOGFILE 2>&1"
DEBUG_LEVEL=0  # Default debug level is 0 (no debug)
VERBOSE=true   # Default to verbose mode
CONFIG_FILE="$INSTALL_DIR/$CONFIG_NAME" # Default config file path
MAX_LOG_SIZE=1048576 # 1MB

# Log levels
LOG_LEVELS=("DEBUG" "INFO" "WARN" "ERROR" "SUCCESS")

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
RESET='\033[0m'

# Trap errors and clean up
trap 'echo -e "${RED}An error occurred. Exiting...${RESET}" >&2; exit 1' ERR
trap 'echo -e "${RED}Script interrupted by signal. Exiting...${RESET}" >&2; exit 1' SIGINT SIGTERM

# Required dependencies
REQUIRED_CMDS=("curl" "dig" "jq" "grep" "gawk" "sed" "getopt")

# Function to perform log rotation
function rotate_log() {
    if [ -f "$LOGFILE" ]; then
        log_size=$(stat -c%s "$LOGFILE")
        if (( log_size > MAX_LOG_SIZE )); then
            mv "$LOGFILE" "$LOGFILE.$(date '+%Y%m%d%H%M%S')"
            touch "$LOGFILE"
            chmod 644 "$LOGFILE"
        fi
    fi
}


# General logging function with log levels and debug levels
function logger() {
    local level="$1"
    shift
    local message
    local msg_debug_level=1  # Default debug level

    # Check if message includes debug level
    if [[ "$level" == "DEBUG" && "$1" =~ ^[0-9]+$ ]]; then
        msg_debug_level="$1"
        shift
    fi

    message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color
    local output_stream="stdout"

    case "$level" in
        DEBUG)
            if [ "$DEBUG_LEVEL" -lt "$msg_debug_level" ]; then
                return
            fi
            color="$YELLOW"
            output_stream="stderr"
            ;;
        INFO)
            color="$BLUE"
            ;;
        WARN)
            color="$MAGENTA"
            ;;
        ERROR)
            color="$RED"
            output_stream="stderr"
            ;;
        SUCCESS)
            color="$GREEN"
            ;;
        *)
            color="$RESET"
            ;;
    esac

    # Format the log message
    local formatted_message="$timestamp [$level] - $message"
    echo -e "$formatted_message" >> "$LOGFILE"

    if [ "$VERBOSE" = true ]; then
        if [ "$output_stream" = "stderr" ]; then
            echo -e "${color}$formatted_message${RESET}" >&2
        else
            echo -e "${color}$formatted_message${RESET}"
        fi
    fi
}


# Function to check if required dependencies are installed
function check_dependencies() {
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            logger ERROR "Required dependency '$cmd' is not installed."
            exit 1
        fi
    done

    # Check if curl has SSL support
    if ! curl --version | grep -q "SSL"; then
        logger ERROR "Curl does not have SSL support. Please install a version of curl with SSL support."
        exit 1
    fi

    # Check if curl has SMTP support
    if ! curl --version | grep -q "smtp"; then
        logger ERROR "Curl does not have SMTP support. Please install a version of curl with SMTP support."
        exit 1
    fi
}


# Function to retry a command multiple times
function retry() {
    local max_retries=$1
    shift
    local count=0
    local delay=5

    until "$@"; do
        exit_code=$?
        count=$((count + 1))
        if [ $count -lt $max_retries ]; then
            logger WARN "Command failed. Attempt $count/$max_retries."
            logger WARN "Retrying in $delay seconds..."
            sleep $delay
        else
            logger ERROR "Command failed after $max_retries attempts."
            return $exit_code
        fi
    done
    return 0
}


# Reusable function for `curl` requests
function curl_request() {
    local method=$1
    local url=$2
    local data=$3
    local max_retries=3
    local timeout=15  # Timeout in seconds

    # Build curl command
    local curl_cmd="curl -s --max-time $timeout -w '\n%{http_code}' -X \"$method\" \"$url\" -H \"Authorization: Bearer $CLOUDFLARE_API_KEY\" -H \"Content-Type: application/json\" --data '$data'"

    if [ "$DEBUG_LEVEL" -ge 2 ]; then
        curl_cmd="curl -v --max-time $timeout -w '\n%{http_code}' -X \"$method\" \"$url\" -H \"Authorization: Bearer $CLOUDFLARE_API_KEY\" -H \"Content-Type: application/json\" --data '$data'"
        # Mask the API key in the logged command
        local masked_curl_cmd=$(echo "$curl_cmd" | sed "s/$CLOUDFLARE_API_KEY/*****REDACTED*****/g")
        logger DEBUG 2 "Executing curl command:\n$masked_curl_cmd"
    fi

    # Function to perform the curl command
    function perform_curl() {
        response=$(eval "$curl_cmd")
        curl_exit_code=$?

        if [ $curl_exit_code -ne 0 ]; then
            logger WARN "Curl command failed with exit code $curl_exit_code."
            return $curl_exit_code
        fi

        # Split the response into body and status code
        body=$(echo "$response" | head -n -1)  # Everything except the last line
        status_code=$(echo "$response" | tail -n1)  # The last line

        if [ "$DEBUG_LEVEL" -ge 2 ]; then
            logger DEBUG 2 "API Response Body:\n$body"
            logger DEBUG 2 "HTTP Status Code: $status_code"
        fi

        # Check for HTTP errors
        if [[ $status_code -lt 200 || $status_code -ge 300 ]]; then
            logger WARN "Received HTTP status code $status_code."
            return 1
        fi

        # Output the body and status code
        echo -e "$body\n$status_code"
    }

    # Use the retry mechanism
    local result
    if ! result=$(retry $max_retries perform_curl); then
        logger ERROR "Failed to perform curl request after $max_retries attempts."
        return 1
    fi

    echo "$result"
    return 0
}


# Function to fetch external IP addresses
function get_external_ip() {
    local ip_type=$1  # "ipv4" or "ipv6"
    local external_ip

    if [ "$ip_type" == "ipv4" ]; then
        # Try DNS lookup first, silencing errors and grabbing last line
        external_ip=$(dig +short +time=5 +tries=3 myip.opendns.com @resolver1.opendns.com \
                      2>/dev/null | tail -n1)
        # Fallback to HTTP if dig gave nothing valid
        if ! [[ "$external_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            logger WARN "DNS lookup failed or no IPv4 found. Falling back to HTTP lookup."
            external_ip=$(curl -s https://ipv4.icanhazip.com | tr -d '[:space:]')
        fi
    elif [ "$ip_type" == "ipv6" ]; then
        # Try DNS lookup first (IPv6)
        external_ip=$(dig -6 +short +time=5 +tries=3 myip.opendns.com aaaa @resolver1.opendns.com \
                      2>/dev/null | tail -n1)
        # Fallback to HTTP if dig gave nothing valid
        if ! [[ "$external_ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
            logger WARN "DNS lookup failed or no IPv6 found. Falling back to HTTP lookup."
            external_ip=$(curl -s https://ipv6.icanhazip.com | tr -d '[:space:]')
        fi
    else
        logger ERROR "Invalid IP type specified: $ip_type"
        return 1
    fi

    # Final validation
    if [[ "$ip_type" == "ipv4" ]]; then
        if ! [[ "$external_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            logger WARN "No external IPv4 address found."
            return 1
        fi
    else
        if ! [[ "$external_ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
            logger WARN "No external IPv6 address found."
            return 1
        fi
    fi

    echo "$external_ip"
    return 0
}



# Function to fetch DNS records from Cloudflare
function get_cloudflare_records() {
    local response=$(curl -s --max-time 15 -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?name=$RECORD_NAME" \
        -H "Authorization: Bearer $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json")

    if [ $? -ne 0 ]; then
        logger ERROR "Failed to fetch DNS records from Cloudflare."
        return 1
    fi

    echo "$response"
    return 0
}


# Function to validate SMTP configuration
function validate_smtp_config() {
    if [ "$SMTP_ENABLED" != "true" ]; then
        logger DEBUG 1 "SMTP is not enabled. Skipping SMTP configuration validation."
        return 0
    fi

    if [ -z "$SMTP_SERVER" ] || [ -z "$SMTP_PORT" ]; then
        logger ERROR "SMTP server or port is not set in the configuration."
        return 1
    fi

    # Ensure only one of smtp_use_tls or smtp_use_ssl is true
    if [ "$SMTP_USE_TLS" == "true" ] && [ "$SMTP_USE_SSL" == "true" ]; then
        logger ERROR "Both smtp_use_tls and smtp_use_ssl cannot be true at the same time."
        return 1
    fi

    logger INFO "Validating SMTP configuration..."

    # Prepare the curl command
    local curl_cmd="curl --connect-timeout 10"

    # Set URL based on SSL/TLS settings
    if [ "$SMTP_USE_SSL" == "true" ]; then
        smtp_url="smtps://$SMTP_SERVER:$SMTP_PORT"
    else
        smtp_url="smtp://$SMTP_SERVER:$SMTP_PORT"
    fi

    curl_cmd+=" --url \"$smtp_url\""

    # Use STARTTLS if required
    if [ "$SMTP_USE_TLS" == "true" ]; then
        curl_cmd+=" --starttls smtp"
    fi

    # Include credentials if required
    if [ "$SMTP_CREDENTIALS_REQUIRED" == "true" ]; then
        if [ -z "$SMTP_USERNAME" ] || [ -z "$SMTP_PASSWORD" ]; then
            logger ERROR "SMTP credentials are required but not provided."
            return 1
        fi
        curl_cmd+=" --user \"$SMTP_USERNAME:$SMTP_PASSWORD\""
    fi

    if [ "$DEBUG_LEVEL" -ge 2 ]; then
        curl_cmd+=" -v"
        logger DEBUG 2 "SMTP Validation curl command: $curl_cmd"
    fi

    # Attempt to connect and send EHLO command
    smtp_response=$(echo -e "EHLO localhost\nQUIT" | eval "$curl_cmd" 2>&1)
    exit_code=$?

    logger DEBUG 2 "SMTP Response:\n$smtp_response"

    if [ $exit_code -eq 0 ]; then
        logger INFO "SMTP configuration validated successfully."
        return 0
    else
        logger ERROR "Failed to validate SMTP configuration. Unable to connect to SMTP server."
        return 1
    fi
}


# Function to send email alerts
function send_email() {
    local subject="$1"
    local body="$2"

    if [ "$SMTP_ENABLED" != "true" ]; then
        logger DEBUG 1 "SMTP is not enabled. Skipping email alert."
        return 0
    fi

    if [ -z "$ALERT_EMAIL" ] || [ -z "$MAIL_FROM" ]; then
        logger ERROR "Alert email address or mail from address is not set. Cannot send email."
        return 1
    fi

    logger INFO "Sending email alert to $ALERT_EMAIL..."

    if curl --version | grep -q "Protocols:.*smtp"; then
        # Use curl to send the email
        local curl_cmd="curl -s"

        # Set URL based on SSL/TLS settings
        if [ "$SMTP_USE_SSL" == "true" ]; then
            smtp_url="smtps://$SMTP_SERVER:$SMTP_PORT"
        else
            smtp_url="smtp://$SMTP_SERVER:$SMTP_PORT"
        fi

        curl_cmd+=" --url \"$smtp_url\" --mail-from \"$MAIL_FROM\" --mail-rcpt \"$ALERT_EMAIL\""

        # Use STARTTLS if required
        if [ "$SMTP_USE_TLS" == "true" ]; then
            curl_cmd+=" --starttls smtp"
        fi

        if [ "$SMTP_CREDENTIALS_REQUIRED" == "true" ]; then
            if [ -z "$SMTP_USERNAME" ] || [ -z "$SMTP_PASSWORD" ]; then
                logger ERROR "SMTP credentials are required but not provided."
                return 1
            fi
            curl_cmd+=" --user \"$SMTP_USERNAME:$SMTP_PASSWORD\""
        fi

        if [ "$DEBUG_LEVEL" -ge 2 ]; then
            curl_cmd+=" -v"
            # Mask SMTP credentials in the logged command
            local masked_curl_cmd=$(echo "$curl_cmd" | sed "s/$SMTP_USERNAME/*****/g; s/$SMTP_PASSWORD/*****/g")
            logger DEBUG 2 "SMTP curl command: $masked_curl_cmd"
        fi

        # Prepare email content
        local email_content="Subject: $subject\r\nFrom: $MAIL_FROM\r\nTo: $ALERT_EMAIL\r\n\r\n$body"

        # Send the email
        result=$(echo -e "$email_content" | eval "$curl_cmd -T - 2>&1")
        exit_code=$?

        if [ "$DEBUG_LEVEL" -ge 2 ]; then
            logger DEBUG 2 "SMTP Response:\n$result"
        fi

        if [ $exit_code -eq 0 ]; then
            logger SUCCESS "Email alert sent successfully to $ALERT_EMAIL using curl."
        else
            logger ERROR "Failed to send email alert using curl."
        fi
    else
        # Fallback to sendmail
        logger WARN "Curl does not have SMTP support. Using sendmail instead."

        if ! command -v sendmail &> /dev/null; then
            logger ERROR "Neither curl with SMTP support nor sendmail is available."
            return 1
        fi

        {
            echo "Subject: $subject"
            echo "To: $ALERT_EMAIL"
            echo "From: $MAIL_FROM"
            echo ""
            echo "$body"
        } | sendmail -t

        if [ $? -eq 0 ]; then
            logger SUCCESS "Email alert sent successfully to $ALERT_EMAIL using sendmail."
        else
            logger ERROR "Failed to send email alert using sendmail."
        fi
    fi
}


# Function to update a DNS record
function update_dns_record() {
    local record_type=$1  # "A" or "AAAA"
    local external_ip=$2
    local record_id=$3
    local current_dns_ip=$4

    if [[ "$external_ip" == "$current_dns_ip" ]]; then
        logger SUCCESS "No IP change required for $record_type record ($RECORD_NAME)."
        return 0
    fi

    # Fetch existing DNS record data
    record_details=$(curl -s --max-time 15 -X GET "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
        -H "Authorization: Bearer $CLOUDFLARE_API_KEY" \
        -H "Content-Type: application/json")

    if [ $? -ne 0 ]; then
        logger ERROR "Failed to retrieve existing DNS record details for $RECORD_NAME."
        return 1
    fi

    # Extract existing fields to retain
    proxied=$(echo "$record_details" | jq -r '.result.proxied')
    ttl=$(echo "$record_details" | jq -r '.result.ttl')
    comment=$(echo "$record_details" | jq -r '.result.comment')

    # Prepare data for update, including existing fields
    data=$(jq -n \
        --arg type "$record_type" \
        --arg name "$RECORD_NAME" \
        --arg content "$external_ip" \
        --argjson ttl "$ttl" \
        --argjson proxied "$proxied" \
        --arg comment "$comment" \
        '{
            type: $type,
            name: $name,
            content: $content,
            ttl: $ttl,
            proxied: $proxied,
            comment: $comment
        }')

    # Update the DNS record
    update_data=$(curl_request "PUT" "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" "$data")
    if [ $? -ne 0 ]; then
        logger ERROR "Failed to update $record_type record for $RECORD_NAME."
        return 1
    fi

    update_body=$(echo "$update_data" | head -n -1)
    update_status_code=$(echo "$update_data" | tail -n1)
    update_success=$(echo "$update_body" | jq -r '.success')

    if [[ "$update_status_code" == 200 && "$update_success" == "true" ]]; then
        logger SUCCESS "$record_type record for $RECORD_NAME updated to $external_ip."

        # Collect the update message
        UPDATES_MADE+="The $record_type record for $RECORD_NAME has been updated to $external_ip.\n"

        return 0
    else
        logger ERROR "$record_type record update failed for $RECORD_NAME. Response: $update_body"
        return 1
    fi
}

# Function to perform the DNS update operation
function update_dns() {
    logger INFO "Starting DNS update process for $RECORD_NAME (ipv6-only=${IPV6_ONLY})"

    local errors=()
    local cloudflare_records
    local record_types

    # Initialize UPDATES_MADE variable
    UPDATES_MADE=""

    # Fetch DNS records from Cloudflare
    cloudflare_records=$(get_cloudflare_records)
    if [ $? -ne 0 ]; then
        logger ERROR "Failed to retrieve DNS records for $RECORD_NAME from Cloudflare."
        return 1
    fi

    # Determine which record types exist
    record_types=$(echo "$cloudflare_records" | jq -r '.result[].type')

    if [ -z "$record_types" ]; then
        logger WARN "No DNS records found for $RECORD_NAME."
        return 1
    fi

    # If ipv6-only mode, drop A records
    if [ "$IPV6_ONLY" = true ]; then
        record_types=$(echo "$record_types" | grep -w "AAAA" || true)
        if [ -z "$record_types" ]; then
            logger WARN "IPv6-only mode and no AAAA records found for $RECORD_NAME. Skipping update."
            return 1
        fi
    fi

    # Check for existence of A and AAAA records
    has_a_record=$(echo "$record_types" | grep -w "A")
    has_aaaa_record=$(echo "$record_types" | grep -w "AAAA")

    if [ -z "$has_a_record" ] && [ "$IPV6_ONLY" != true ]; then
        logger INFO "No A record found for $RECORD_NAME. Skipping A record update."
    fi

    if [ -z "$has_aaaa_record" ]; then
        logger INFO "No AAAA record found for $RECORD_NAME. Skipping AAAA record update."
    fi

    # Process each record type
    for record_type in $record_types; do
        case "$record_type" in
            A)
                logger INFO "Processing A (IPv4) record..."
                record_info=$(echo "$cloudflare_records" | jq -r '.result[] | select(.type=="A") | "\(.id)|\(.content)"')
                record_id=$(echo "$record_info" | cut -d'|' -f1)
                current_dns_ip=$(echo "$record_info" | cut -d'|' -f2)
                logger INFO "Current Cloudflare A record IP: $current_dns_ip"

                external_ipv4=$(get_external_ip "ipv4")
                if [ $? -ne 0 ]; then
                    logger WARN "External IPv4 address not found. Skipping A record update."
                    continue
                fi

                update_dns_record "A" "$external_ipv4" "$record_id" "$current_dns_ip" || errors+=("A record")
                ;;
            AAAA)
                logger INFO "Processing AAAA (IPv6) record..."
                record_info=$(echo "$cloudflare_records" | jq -r '.result[] | select(.type=="AAAA") | "\(.id)|\(.content)"')
                record_id=$(echo "$record_info" | cut -d'|' -f1)
                current_dns_ip=$(echo "$record_info" | cut -d'|' -f2)
                logger INFO "Current Cloudflare AAAA record IP: $current_dns_ip"

                external_ipv6=$(get_external_ip "ipv6")
                if [ $? -ne 0 ]; then
                    logger WARN "External IPv6 address not found. Skipping AAAA record update."
                    continue
                fi

                update_dns_record "AAAA" "$external_ipv6" "$record_id" "$current_dns_ip" || errors+=("AAAA record")
                ;;
            *)
                logger INFO "Skipping unsupported record type: $record_type"
                ;;
        esac
    done

    # After processing all records, send email if updates were made
    if [ -n "$UPDATES_MADE" ]; then
        local subject="Cloudflare DDNS Update: $RECORD_NAME Records Updated"
        local body="The following DNS records for $RECORD_NAME have been updated:\n$UPDATES_MADE"
        send_email "$subject" "$body"
    fi

    # Report overall success or failure
    if [ ${#errors[@]} -ne 0 ]; then
        logger ERROR "Failed to update the following records: ${errors[*]}"
        return 1
    else
        logger SUCCESS "DNS update process completed successfully for $RECORD_NAME."
        return 0
    fi
}



# Function to validate the configuration
function validate_config() {
    local errors=()

    # Validate Cloudflare configurations
    if [[ -z "$CLOUDFLARE_ZONE_ID" ]]; then
        errors+=("cloudflare_zone_id is missing.")
    fi

    if [[ -z "$CLOUDFLARE_API_KEY" ]]; then
        errors+=("cloudflare_api_key is missing.")
    fi

    if [[ -z "$CLOUDFLARE_EMAIL" ]]; then
        errors+=("cloudflare_email is missing.")
    fi

    if [[ -z "$RECORD_NAME" ]]; then
        errors+=("record_name is missing.")
    elif ! [[ "$RECORD_NAME" =~ ^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        errors+=("record_name '$RECORD_NAME' is not a valid domain name.")
    fi

    # If there are errors, display them and exit
    if [ ${#errors[@]} -ne 0 ]; then
        logger ERROR "Configuration validation failed with the following errors:"
        for error in "${errors[@]}"; do
            logger ERROR "- $error"
        done
        exit 1
    fi

    logger INFO "Configuration validation passed."
}


# Function to load the configuration
function load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        logger ERROR "Configuration file not found at $CONFIG_FILE."
        exit 1
    fi

    # Function to extract value from config file
    function get_config_value() {
        local key="$1"
        local value
        value=$(grep -E "^\s*$key\s*=" "$CONFIG_FILE" | sed -E 's/^[^=]+=\s*//; s/\s*(#.*)?$//')
        # Remove surrounding quotes if present
        value=$(echo "$value" | sed -E 's/^"(.*)"$/\1/')
        echo "$value"
    }

    # Load configurations
    CLOUDFLARE_ZONE_ID=$(get_config_value "cloudflare_zone_id")
    CLOUDFLARE_API_KEY=$(get_config_value "cloudflare_api_key")
    CLOUDFLARE_EMAIL=$(get_config_value "cloudflare_email")
    RECORD_NAME=$(get_config_value "record_name")

    # Load SMTP settings
    SMTP_ENABLED=$(get_config_value "smtp_enabled")
    SMTP_SERVER=$(get_config_value "smtp_server")
    SMTP_PORT=$(get_config_value "smtp_port")
    SMTP_CREDENTIALS_REQUIRED=$(get_config_value "smtp_credentials_required")
    SMTP_USERNAME=$(get_config_value "smtp_username")
    SMTP_PASSWORD=$(get_config_value "smtp_password")
    ALERT_EMAIL=$(get_config_value "alert_email")
    MAIL_FROM=$(get_config_value "mail_from")
    SMTP_USE_TLS=$(get_config_value "smtp_use_tls")
    SMTP_USE_SSL=$(get_config_value "smtp_use_ssl")

    # Default to false if not specified
    [ -z "$SMTP_ENABLED" ] && SMTP_ENABLED="false"
    SMTP_ENABLED=$(echo "$SMTP_ENABLED" | tr '[:upper:]' '[:lower:]')
    [ -z "$SMTP_CREDENTIALS_REQUIRED" ] && SMTP_CREDENTIALS_REQUIRED="false"
    SMTP_CREDENTIALS_REQUIRED=$(echo "$SMTP_CREDENTIALS_REQUIRED" | tr '[:upper:]' '[:lower:]')
    [ -z "$SMTP_USE_TLS" ] && SMTP_USE_TLS="false"
    SMTP_USE_TLS=$(echo "$SMTP_USE_TLS" | tr '[:upper:]' '[:lower:]')
    [ -z "$SMTP_USE_SSL" ] && SMTP_USE_SSL="false"
    SMTP_USE_SSL=$(echo "$SMTP_USE_SSL" | tr '[:upper:]' '[:lower:]')

    # Validate the configuration
    validate_config

    # Print all variables (excluding sensitive ones) when debug level >= 1
    if [ "$DEBUG_LEVEL" -ge 1 ]; then
        logger DEBUG 1 "Loaded configuration:"
        local censored_api_key="${CLOUDFLARE_API_KEY:0:4}******"
        local censored_smtp_password="${SMTP_PASSWORD:0:4}******"
        logger DEBUG 1 "CLOUDFLARE_ZONE_ID: $CLOUDFLARE_ZONE_ID"
        logger DEBUG 1 "CLOUDFLARE_API_KEY: $censored_api_key"
        logger DEBUG 1 "CLOUDFLARE_EMAIL: $CLOUDFLARE_EMAIL"
        logger DEBUG 1 "RECORD_NAME: $RECORD_NAME"
        logger DEBUG 1 "SMTP_ENABLED: $SMTP_ENABLED"
        logger DEBUG 1 "SMTP_SERVER: $SMTP_SERVER"
        logger DEBUG 1 "SMTP_PORT: $SMTP_PORT"
        logger DEBUG 1 "SMTP_CREDENTIALS_REQUIRED: $SMTP_CREDENTIALS_REQUIRED"
        logger DEBUG 1 "SMTP_USERNAME: $SMTP_USERNAME"
        logger DEBUG 1 "SMTP_PASSWORD: $censored_smtp_password"
        logger DEBUG 1 "ALERT_EMAIL: $ALERT_EMAIL"
        logger DEBUG 1 "MAIL_FROM: $MAIL_FROM"
        logger DEBUG 1 "SMTP_USE_TLS: $SMTP_USE_TLS"
        logger DEBUG 1 "SMTP_USE_SSL: $SMTP_USE_SSL"
    fi
}


# Function to install the script and configuration
function install_script() {
    logger INFO "Installing script to $INSTALL_DIR..."

    # Ensure the install directory exists
    sudo mkdir -p "$INSTALL_DIR"

    # Copy self to /usr/local/bin/cloudflare-ddns
    sudo cp "$0" "$INSTALL_DIR/$SCRIPT_NAME"
    sudo chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    logger SUCCESS "Installed script as $INSTALL_DIR/$SCRIPT_NAME"

    # Ensure config directory exists
    logger INFO "Creating config directory $CONFIG_DIR"
    sudo mkdir -p "$CONFIG_DIR"

    # Copy example config into place if missing
    if [[ ! -f "$CONFIG_FILE" ]]; then
        sudo cp "./config.toml.example" "$CONFIG_FILE"
        sudo chmod 600 "$CONFIG_FILE"
        logger SUCCESS "Created config file at $CONFIG_FILE"
    else
        logger SUCCESS "Config file already exists at $CONFIG_FILE"
    fi
}


# Function to check if the cron job already exists
function check_cron_job() {
    # Only add the line if it's not already present
    if crontab -l 2>/dev/null | grep -F "$CRON_JOB" &>/dev/null; then
        logger SUCCESS "Cron job is already set up."
    else
        logger INFO "Adding cron job: $CRON_JOB"
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
        logger SUCCESS "Cron job added."
    fi
}


# Function to install the entire system
function install_system() {
    logger INFO "Checking for required dependencies..."
    check_dependencies
    logger SUCCESS "All dependencies are satisfied."

    install_script
    check_cron_job

    logger SUCCESS "Installation complete."
}


# Function to display the help menu
function display_help() {
    cat << EOF
Cloudflare DDNS Update Script - Version $SCRIPT_VERSION

Usage: $0 [OPTIONS]

Options:
  -i, --install          Install the script and set up the environment.
  -d, --debug            Run the script in debug mode (equivalent to --debug-level 1).
      --debug-level N    Set the debug level (0-2). Level 2 includes detailed curl output.
  -h, --help             Display this help message and exit.
  -v, --version          Display the script version and exit.
  -V, --verbose          Toggle verbose output (on by default).
  -c, --config FILE      Specify a custom configuration file.
      --run              Run the DNS update process (default action).

Examples:
  Install the script:
    $0 --install

  Run the script with debug output:
    $0 --debug

  Run the script with maximum debug output:
    $0 --debug-level 2

  Use a custom configuration file:
    $0 --config /path/to/config.toml
r
  For full information on how to use this script, please refer to the README.
EOF
}


# Main entry point to the script
function main() {
    # Default action
    ACTION="run"

    # Parse command-line arguments
    TEMP=$(getopt -o idhvVc: -l install,debug,debug-level:,help,version,verbose,config:,run,ipv6-only -- "$@")
    if [ $? != 0 ] ; then
        echo "Terminating..." >&2
        exit 1
    fi
    eval set -- "$TEMP"

    while true; do
        case "$1" in
            -i|--install)
                ACTION="install"
                shift
                ;;
            -d|--debug)
                DEBUG_LEVEL=1
                shift
                ;;
            --debug-level)
                DEBUG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                display_help
                exit 0
                ;;
            -v|--version)
                echo "Cloudflare DDNS Update Script - Version $TOOL_VERSION"
                exit 0
                ;;
            -V|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --run)
                ACTION="run"
                shift
                ;;
                --ipv6-only)
                IPV6_ONLY=true
                shift
                ;;
            --)
                shift
                break
                ;;
            *)
                echo "Invalid option: $1" >&2
                display_help
                exit 1
                ;;
        esac
    done

    case "$ACTION" in
        install)
            install_system
            ;;
        run)
            rotate_log
            check_dependencies
            load_config

            if [ "$SMTP_ENABLED" == "true" ]; then
                validate_smtp_config || logger WARN "SMTP configuration validation failed. Continuing without email alerts."
            fi

            # Proceed with updating DNS
            if update_dns; then
                exit 0
            else
                exit 1
            fi
            ;;
        *)
            echo "Unknown action: $ACTION" >&2
            display_help
            exit 1
            ;;
    esac
}


# Execute the main function
main "$@"
