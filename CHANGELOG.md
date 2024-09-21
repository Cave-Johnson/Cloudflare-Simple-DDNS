# Change Log for Cloudflare DDNS Update Script

This change log outlines the major changes and enhancements made to the Cloudflare DDNS Update Script, documenting feature additions, bug fixes, and improvements over time.

---

## **Version 1.10.0** - *2024-09-21*

### **New Features**

1. **Consolidated Email Notifications**:
   - Now sends a **single email** per execution, even if both **A** and **AAAA** records are updated.
   - The email contains a summary of all DNS records that were updated during the script execution.

2. **Enhanced IPv4 and IPv6 Support**:
   - Automatically detects and updates both **A** (IPv4) and **AAAA** (IPv6) records if they exist for the domain.
   - Added logging to notify the user if an **A** or **AAAA** record is missing or unable to resolve.

3. **Improved Logging System**:
   - Introduced **log rotation** for the log file (`/var/log/cloudflare-ddns.log`) when it exceeds **1MB**.
   - Added new **log levels** (`DEBUG`, `INFO`, `WARN`, `ERROR`, `SUCCESS`), making logs more informative and categorized.
   - Implemented **debug levels** (0-2) to control the verbosity of logging. At debug level 2, all curl requests and responses are logged.

4. **Enhanced Curl Request Logging**:
   - All **curl API requests** (both for Cloudflare and SMTP) now provide detailed output at **debug level 2**.
   - Masked sensitive data (API keys and passwords) in curl command logs for security purposes.

5. **Retry Mechanism for DNS Updates**:
   - Added a **retry mechanism** for failed curl requests when updating DNS records, with configurable retry limits.

### **Bug Fixes**

1. **Fixed Parsing of Configuration File**:
   - Resolved an issue where comments in the configuration file were being incorrectly parsed as part of the variable values.
   - Improved the `get_config_value` function to handle both quoted and unquoted values correctly.

2. **Resolved Email Notification Failures**:
   - Fixed an issue where the script was incorrectly sending a `VRFY` command when trying to send emails via SMTP.
   - Now correctly sends the email content using the `-T` option with curl and supports both **STARTTLS** and **SSL/TLS** for SMTP connections.

3. **Improved Domain Name Validation**:
   - Fixed an issue where domain names with extra characters (e.g., trailing quotes) were being marked as invalid during configuration validation.

4. **Fixed TLS/SSL Configuration for SMTP**:
   - Correctly handles **TLS** and **SSL** settings for SMTP by ensuring either `smtp_use_tls` or `smtp_use_ssl` is set correctly based on the port and connection method.

### **Improvements**

1. **Cleaner Cron Job Integration**:
   - The installation process automatically sets up a **cron job** that runs every 5 minutes, with an option for easy modification.
   - The cron job runs the script non-interactively, and output is logged to `/var/log/cloudflare-ddns.log`.

2. **Simplified Installation and Configuration**:
   - Introduced an **installation process** that sets up the script in `/opt/cloudflare-ddns/` and automatically creates a default configuration file.
   - Simplified **configuration validation** to catch errors before the script runs, reducing runtime failures.

---

## **Version 1.0.0** - *Initial Release*

### **Features**

1. **Automatic Cloudflare DNS Updates**:
   - Detects changes to the external IP address and updates the corresponding **A** (IPv4) DNS record on Cloudflare.
   
2. **Basic Logging**:
   - Logs actions and results to `/var/log/cloudflare-ddns.log`.

3. **Cron Integration**:
   - Basic setup to run the script via cron for automated IP updates.

4. **Configuration via TOML**:
   - Users can provide Cloudflare API credentials and DNS records via a TOML configuration file.

---

### **Future Plans**

- **IPv6-Only Support**: Add support for IPv6-only environments.
- **Multiple Domain Handling**: Extend support to handle multiple domains or subdomains within the same configuration.
- **Detailed Alert Customization**: Allow users to configure which events (success, failure, etc.) trigger email notifications.
- **Interactive Setup**: Improve installation by adding an interactive setup wizard for easier configuration of the script and cron jobs.

---

This change log will continue to track ongoing updates and improvements as the script evolves. Please feel free to contribute by submitting issues or pull requests to the project’s [GitHub repository](https://github.com/yourusername/cloudflare-ddns).