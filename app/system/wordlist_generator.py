"""
Wordlist Generator - LLM-Powered Custom Wordlists
==================================================

Generates target-specific wordlists using LLM intelligence.
Stores generated wordlists in workspace/wordlists/.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


class WordlistGenerator:
    """
    Generate custom wordlists using LLM intelligence.
    
    Creates target-specific wordlists based on:
    - Detected technologies
    - Industry/sector
    - OSINT findings
    - Common patterns
    """
    
    # Base wordlists to include
    BASE_DIRECTORIES = [
        # Common
        "admin", "login", "dashboard", "api", "v1", "v2", "v3",
        "wp-admin", "wp-content", "wp-includes",
        "index", "home", "about", "contact", "search",
        "static", "assets", "images", "img", "css", "js",
        "upload", "uploads", "files", "media", "content",
        "test", "dev", "staging", "backup", "old", "new",
        
        # API
        "api", "rest", "graphql", "swagger", "docs", "documentation",
        "health", "status", "version", "info", "config", "settings",
        
        # Auth
        "auth", "oauth", "login", "logout", "register", "signup", "signin",
        "forgot", "reset", "password", "token", "session", "user", "users",
        "account", "profile", "me", "admin", "administrator",
        
        # Backend
        "server", "backend", "internal", "private", "secure", "hidden",
        "debug", "console", "shell", "phpmyadmin", "adminer",
    ]
    
    # Tech-specific paths
    TECH_PATHS = {
        "wordpress": [
            "wp-admin", "wp-login.php", "wp-content", "wp-includes",
            "wp-json", "xmlrpc.php", "wp-cron.php", "readme.html",
            "license.txt", "wp-config.php.bak", "wp-config.php~"
        ],
        "drupal": [
            "admin", "node", "user", "sites/all", "sites/default",
            "CHANGELOG.txt", "INSTALL.txt", "update.php"
        ],
        "joomla": [
            "administrator", "components", "modules", "plugins",
            "templates", "configuration.php", "htaccess.txt"
        ],
        "laravel": [
            ".env", "storage", "public", "artisan", "vendor",
            "bootstrap/cache", "config", "database", "routes"
        ],
        "django": [
            "admin", "static", "media", "api", "settings.py",
            "manage.py", "urls.py", "wsgi.py"
        ],
        "nodejs": [
            "node_modules", "package.json", "package-lock.json",
            ".env", "config", "public", "build", "dist"
        ],
        "php": [
            "index.php", "config.php", "info.php", "phpinfo.php",
            "test.php", "admin.php", "login.php", ".htaccess"
        ],
        "git": [
            ".git", ".git/config", ".git/HEAD", ".gitignore",
            ".git/logs/HEAD", ".git-credentials"
        ],
        "api": [
            "api", "v1", "v2", "v3", "graphql", "rest",
            "swagger", "swagger.json", "openapi.json", "docs"
        ]
    }
    
    def __init__(self, workspace_path: Path = None):
        self.workspace = workspace_path or Path(__file__).parent.parent.parent / "workspace"
        self.wordlist_dir = self.workspace / "wordlists"
        self.wordlist_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_directory_wordlist(
        self, 
        target: str, 
        tech_stack: List[str] = None,
        include_base: bool = True,
        extra_words: List[str] = None
    ) -> str:
        """
        Generate a directory wordlist based on target info.
        
        Args:
            target: Target domain/name
            tech_stack: Detected technologies (wordpress, laravel, etc.)
            include_base: Include base common directories
            extra_words: Additional custom words to include
            
        Returns:
            Path to generated wordlist
        """
        words = set()
        
        # Add base directories
        if include_base:
            words.update(self.BASE_DIRECTORIES)
        
        # Add tech-specific paths
        if tech_stack:
            for tech in tech_stack:
                tech_lower = tech.lower()
                for key, paths in self.TECH_PATHS.items():
                    if key in tech_lower or tech_lower in key:
                        words.update(paths)
        
        # Add extra words
        if extra_words:
            words.update(extra_words)
        
        # Add target-based variations
        target_clean = target.replace(".", "_").replace("-", "_")
        words.update([
            target_clean, 
            f"{target_clean}_admin",
            f"{target_clean}_api",
            f"api_{target_clean}",
        ])
        
        # Sort and save
        sorted_words = sorted(words)
        
        filename = f"{self._sanitize_filename(target)}_dirs.txt"
        filepath = self.wordlist_dir / filename
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(sorted_words))
        
        return str(filepath)
    
    def generate_password_wordlist(
        self,
        target: str,
        context: Dict[str, Any] = None,
        base_passwords: bool = True
    ) -> str:
        """
        Generate password wordlist based on OSINT and target info.
        
        Args:
            target: Target domain/company
            context: OSINT context (employees, dates, etc.)
            base_passwords: Include common passwords
            
        Returns:
            Path to generated wordlist
        """
        passwords = set()
        context = context or {}
        
        # Base common passwords
        if base_passwords:
            passwords.update([
                "password", "Password1", "Password123", "admin", "Admin123",
                "letmein", "welcome", "Welcome1", "123456", "12345678",
                "qwerty", "abc123", "monkey", "master", "dragon",
                "111111", "baseball", "iloveyou", "trustno1", "sunshine"
            ])
        
        # Target-based passwords
        target_parts = target.replace(".", " ").replace("-", " ").split()
        for part in target_parts:
            if len(part) > 2:
                passwords.update([
                    part, part.capitalize(), part.upper(),
                    f"{part}123", f"{part}!", f"{part}2024", f"{part}2025",
                    f"{part.capitalize()}123", f"{part.capitalize()}!",
                ])
        
        # Year-based
        current_year = datetime.now().year
        for year in range(current_year - 2, current_year + 2):
            passwords.update([
                str(year), f"password{year}", f"Password{year}",
                f"{target_parts[0] if target_parts else 'admin'}{year}"
            ])
        
        # Save
        sorted_passwords = sorted(passwords, key=len)
        
        filename = f"{self._sanitize_filename(target)}_passwords.txt"
        filepath = self.wordlist_dir / filename
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(sorted_passwords))
        
        return str(filepath)
    
    def generate_subdomain_wordlist(
        self,
        target: str,
        include_common: bool = True
    ) -> str:
        """Generate subdomain wordlist."""
        subdomains = set()
        
        if include_common:
            subdomains.update([
                "www", "mail", "ftp", "localhost", "webmail", "smtp",
                "pop", "ns1", "ns2", "dns", "dns1", "dns2",
                "admin", "portal", "vpn", "gateway", "web",
                "dev", "staging", "test", "beta", "demo", "sandbox",
                "api", "app", "m", "mobile", "docs", "help", "support",
                "blog", "shop", "store", "cdn", "static", "media",
                "login", "secure", "sso", "auth", "oauth",
                "internal", "intranet", "extranet", "remote",
                "db", "mysql", "postgres", "mongo", "redis", "cache",
                "git", "gitlab", "jenkins", "ci", "build",
            ])
        
        filename = f"{self._sanitize_filename(target)}_subdomains.txt"
        filepath = self.wordlist_dir / filename
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))
        
        return str(filepath)
    
    def generate_with_llm(
        self,
        target: str,
        wordlist_type: str,
        context: Dict[str, Any] = None
    ) -> str:
        """
        Generate wordlist using LLM for more intelligent suggestions.
        
        Args:
            target: Target domain
            wordlist_type: Type of wordlist (directories, passwords, subdomains)
            context: Additional context (tech stack, industry, etc.)
            
        Returns:
            Path to generated wordlist
        """
        from app.agent.prompts import format_prompt
        from app.llm.client import OllamaClient
        
        context = context or {}
        
        try:
            prompt = f"""Generate a {wordlist_type} wordlist for penetration testing.

Target: {target}
Context: {context}

Generate 50-100 relevant entries specific to this target.
Consider:
- Industry-specific terms
- Common patterns for this type of target
- Technology-specific paths/names
- Variations and common typos

Return ONLY the wordlist entries, one per line, no explanations."""

            llm = OllamaClient()
            response = llm.generate(prompt, timeout=30, stream=False)
            
            # Parse response into lines
            lines = [l.strip() for l in response.split('\n') if l.strip()]
            
            # Combine with base wordlist
            if wordlist_type == "directories":
                base_path = self.generate_directory_wordlist(target, context.get("tech_stack"))
                with open(base_path, 'r') as f:
                    existing = set(f.read().split('\n'))
                lines = list(existing | set(lines))
            
            # Save
            filename = f"{self._sanitize_filename(target)}_{wordlist_type}_llm.txt"
            filepath = self.wordlist_dir / filename
            
            with open(filepath, 'w') as f:
                f.write('\n'.join(sorted(lines)))
            
            return str(filepath)
            
        except Exception as e:
            print(f"  ⚠️ LLM wordlist generation failed: {e}")
            # Fallback to basic generation
            if wordlist_type == "directories":
                return self.generate_directory_wordlist(target, context.get("tech_stack"))
            elif wordlist_type == "passwords":
                return self.generate_password_wordlist(target, context)
            else:
                return self.generate_subdomain_wordlist(target)
    
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize string for use as filename."""
        return "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
    
    def list_generated(self) -> List[str]:
        """List all generated wordlists."""
        if self.wordlist_dir.exists():
            return [f.name for f in self.wordlist_dir.glob("*.txt")]
        return []


# Singleton
_generator: Optional[WordlistGenerator] = None


def get_wordlist_generator() -> WordlistGenerator:
    """Get or create wordlist generator singleton."""
    global _generator
    if _generator is None:
        _generator = WordlistGenerator()
    return _generator
