Analyze the following scan results and extract ALL detected technologies, services, and software versions.

SCAN RESULTS:
{results_str}

INSTRUCTIONS:
1. Look for service banners, version strings, and headers (e.g., "Apache/2.4.41", "OpenSSH 8.2p1").
2. Ignore generic terms like "tcp", "udp", "port", "up", "filtered".
3. Ignore subdomain names (e.g., "mysql.domain.com" does NOT mean MySQL is running there).
4. Return a simple comma-separated list of technology:version pairs.
5. If nothing specific is found, return "None".

EXAMPLE OUTPUT:
Apache 2.4.41, OpenSSH 8.2, PHP 7.4.3, nginx 1.18.0

YOUR OUTPUT:
