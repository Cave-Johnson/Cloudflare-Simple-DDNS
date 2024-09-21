# Cloudflare DDNS Update Script

A robust Bash script for updating Cloudflare DNS records with your current external IP address, supporting both IPv4 and IPv6. The script includes email notifications, detailed logging, and configurable options to suit various environments.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Examples](#examples)
- [Logging](#logging)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **IPv4 and IPv6 Support**: Automatically updates both A (IPv4) and AAAA (IPv6) DNS records.
- **Email Notifications**: Sends email alerts when IP addresses are updated.
- **SMTP Support**: Supports SMTP with SSL/TLS (ports 25, 465, 587) and authentication.
- **Robust Logging**: Detailed logs with adjustable verbosity and debug levels.
- **Retry Mechanism**: Retries failed operations to handle transient network issues.
- **Cron Integration**: Easy setup with cron for regular execution.
- **Configuration Validation**: Validates configurations before execution to prevent errors.

---

## Prerequisites

Ensure your system meets the following requirements:

- **Operating System**: Unix-like OS (Linux, macOS, etc.)
- **Bash**: Version 4.0 or higher
- **Dependencies**:
  - `curl` (with SMTP and SSL support)
  - `dig`
  - `jq`
  - `grep`
  - `gawk`
  - `sed`
  - `getopt`
- **Permissions**:
  - Ability to install scripts to `/opt` directory (or modify the script for a different location)
  - Ability to set up cron jobs for scheduled execution

---

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Cave-Johnson/Cloudflare-Simple-DDNS
   ```

2. **Navigate to the Script Directory**:

   ```bash
   cd cloudflare-ddns
   ```

3. **Make the Script Executable**:

   ```bash
   chmod +x cloudflare-ddns.sh
   ```

4. **Run the Installer**:

   The installer will copy the script to `/opt/cloudflare-ddns/`, create a default configuration file, and set up a cron job.

   ```bash
   sudo ./cloudflare-ddns.sh --install
   ```

   **Note**: You may need `sudo` permissions to install the script and set up the cron job.

5. **Configure the Script**:

   Edit the configuration file located at `/opt/cloudflare-ddns/config.toml` with your preferred text editor:

   ```bash
   sudo nano /opt/cloudflare-ddns/config.toml
   ```

---

## Configuration

The script uses a configuration file in TOML format (`config.toml`). Below is an example of the configuration file with explanations for each option.

### **Example `config.toml`**

```toml
# Cloudflare settings
cloudflare_zone_id = "your-cloudflare-zone-id"        # Your Cloudflare Zone ID
cloudflare_api_key = "your-cloudflare-api-key"        # Your Cloudflare API Token with DNS edit permissions
cloudflare_email   = "your-email@example.com"         # Your Cloudflare account email
record_name        = "subdomain.example.com"          # The DNS record to update

# SMTP settings
smtp_enabled              = true                      # Enable SMTP email notifications (true/false)
smtp_server               = "smtp.example.com"        # SMTP server address
smtp_port                 = 465                       # SMTP server port (25, 465, 587)
smtp_credentials_required = true                      # Does your SMTP server require authentication?
smtp_username             = "your_smtp_username"      # SMTP username
smtp_password             = "your_smtp_password"      # SMTP password
alert_email               = "recipient@example.com"   # Email address to send alerts to
mail_from                 = "sender@example.com"      # Email address the alerts are sent from
smtp_use_tls              = false                     # Use STARTTLS (usually port 587)
smtp_use_ssl              = true                      # Use SSL/TLS (usually port 465)
```

The script has been tested with AWS SES, however other SMTP servers should work as well.

### **Configuration Options**

#### **Cloudflare Settings**

- `cloudflare_zone_id`: Your Cloudflare Zone ID. You can find this in your Cloudflare dashboard under the Overview tab.
- `cloudflare_api_key`: Your Cloudflare API Token with permissions to edit DNS records. For security, use a scoped API Token rather than your Global API Key.
- `cloudflare_email`: Your Cloudflare account email address.
- `record_name`: The DNS record you wish to update (e.g., `subdomain.example.com`).

#### **SMTP Settings**

- `smtp_enabled`: Set to `true` to enable email notifications.
- `smtp_server`: The address of your SMTP server.
- `smtp_port`: The port your SMTP server listens on (usually 25, 465, or 587).
- `smtp_credentials_required`: Set to `true` if your SMTP server requires authentication.
- `smtp_username`: Your SMTP username (if authentication is required).
- `smtp_password`: Your SMTP password (if authentication is required).
- `alert_email`: The email address to send alerts to.
- `mail_from`: The email address that appears in the "From" field of the alert emails.
- `smtp_use_tls`: Set to `true` to use STARTTLS (typically port 587).
- `smtp_use_ssl`: Set to `true` to use SSL/TLS encryption (typically port 465).

**Note**: Only one of `smtp_use_tls` or `smtp_use_ssl` should be set to `true`. If both are `false`, the script will attempt an unencrypted connection (not recommended).

---

## Usage

The script can be run manually or set up to run automatically via cron.

### **Command-Line Options**

```bash
./cloudflare-ddns.sh [OPTIONS]
```

#### **Options**

- `-i, --install`          : Install the script and set up the environment.
- `-d, --debug`            : Run the script in debug mode (equivalent to `--debug-level 1`).
- `--debug-level N`        : Set the debug level (0-2). Level 2 includes detailed curl output.
- `-h, --help`             : Display the help message and exit.
- `-v, --version`          : Display the script version and exit.
- `-V, --verbose`          : Toggle verbose output (on by default).
- `-c, --config FILE`      : Specify a custom configuration file.
- `--run`                  : Run the DNS update process (default action).

### **Examples**

- **Install the script**:

  ```bash
  sudo ./cloudflare-ddns.sh --install
  ```

- **Run the script manually with debug output**:

  ```bash
  ./cloudflare-ddns.sh --debug
  ```

- **Run the script with maximum debug output**:

  ```bash
  ./cloudflare-ddns.sh --debug-level 2
  ```

- **Use a custom configuration file**:

  ```bash
  ./cloudflare-ddns.sh --config /path/to/config.toml
  ```

### **Cron Setup**

The installer sets up a cron job that runs the script every 5 minutes. To modify the frequency:

1. Edit the crontab:

   ```bash
   crontab -e
   ```

2. Modify the cron expression as desired. For example, to run the script every hour:

   ```cron
   0 * * * * /opt/cloudflare-ddns/cloudflare-ddns.sh --run >> /var/log/cloudflare-ddns.log 2>&1
   ```

---

## Logging

- **Log File Location**: `/var/log/cloudflare-ddns.log`
- **Log Rotation**: The script automatically rotates the log file when it exceeds 1MB.
- **Debug Levels**:
  - **Level 0**: No debug messages (default).
  - **Level 1**: Basic debug messages.
  - **Level 2**: Detailed debug messages, including curl command outputs.

---

## Troubleshooting

### **Common Issues**

#### **1. Script Fails to Update DNS Records**

- **Cause**: Incorrect Cloudflare API credentials or permissions.
- **Solution**:
  - Verify your `cloudflare_zone_id`, `cloudflare_api_key`, and `cloudflare_email` in `config.toml`.
  - Ensure the API token has permissions to edit DNS records.

#### **2. Email Notifications Not Working**

- **Cause**: Incorrect SMTP configuration.
- **Solution**:
  - Verify SMTP settings in `config.toml`, especially `smtp_server`, `smtp_port`, `smtp_username`, and `smtp_password`.
  - Ensure only one of `smtp_use_tls` or `smtp_use_ssl` is set to `true`.
  - Check network connectivity to the SMTP server.
  - Run the script with `--debug-level 2` to get detailed output.

#### **3. Dependencies Not Installed**

- **Cause**: Missing required commands (`curl`, `dig`, `jq`, etc.).
- **Solution**:
  - Install missing dependencies using your package manager.
  - For example, on Ubuntu/Debian:

    ```bash
    sudo apt-get install curl dnsutils jq grep gawk sed getopt
    ```

### **Enabling Detailed Debugging**

Run the script with debug level 2 to get detailed output, including curl commands and responses:

```bash
./cloudflare-ddns.sh --debug-level 2
```

Check the log file for detailed information:

```bash
tail -f /var/log/cloudflare-ddns.log
```

---

## Security Considerations

- **Protect Your Configuration File**:

  Ensure that `config.toml` is secured with appropriate permissions to prevent unauthorized access to sensitive information:

  ```bash
  sudo chmod 600 /opt/cloudflare-ddns/config.toml
  ```

- **Use Scoped API Tokens**:

  When creating your Cloudflare API token, limit its permissions to only what is necessary (DNS edit permissions for specific zones).

- **Avoid Logging Sensitive Information**:

  The script masks sensitive data in logs. Be cautious if modifying the script to avoid exposing API keys or passwords.

---

## Contributing

Contributions are welcome! If you have suggestions for improvements or have found bugs, please open an issue or submit a pull request.

**To contribute:**

1. Fork the repository.
2. Create a new branch for your feature or bug fix:

   ```bash
   git checkout -b feature/my-feature
   ```

3. Make your changes.
4. Commit your changes with descriptive messages.
5. Push to your fork:

   ```bash
   git push origin feature/my-feature
   ```

6. Open a pull request on GitHub.

---

## License

This project is licensed under the [GNU General Public License (GPL) v3](LICENSE).

---

**Disclaimer**: Use this script at your own risk. The author is not responsible for any damages or issues caused by using this script.

---

## Contact

For support or questions, please open an issue on the [GitHub repository](https://github.com/Cave-Johnson/Cloudflare-Simple-DDNS/issues).

---

Thank you for using the Cloudflare DDNS Update Script! If you find it useful, consider giving the repository a star ⭐ on GitHub.