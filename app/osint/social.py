"""
SNODE OSINT - Social/Username Functions
========================================

Username search across platforms (sherlock-style).
Based on clatscope username_check functionality.
"""
import requests
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common sites to check usernames
SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://instagram.com/{}",
    "Reddit": "https://reddit.com/user/{}",
    "TikTok": "https://tiktok.com/@{}",
    "YouTube": "https://youtube.com/@{}",
    "LinkedIn": "https://linkedin.com/in/{}",
    "Pinterest": "https://pinterest.com/{}",
    "Twitch": "https://twitch.tv/{}",
    "Snapchat": "https://snapchat.com/add/{}",
    "Medium": "https://medium.com/@{}",
    "DeviantArt": "https://deviantart.com/{}",
    "Flickr": "https://flickr.com/people/{}",
    "Vimeo": "https://vimeo.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Telegram": "https://t.me/{}",
    "Discord": "https://discord.com/users/{}",
    "Patreon": "https://patreon.com/{}",
    "Fiverr": "https://fiverr.com/{}",
    "ProductHunt": "https://producthunt.com/@{}",
    "GitLab": "https://gitlab.com/{}",
    "Bitbucket": "https://bitbucket.org/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    "Keybase": "https://keybase.io/{}",
    "Mastodon": "https://mastodon.social/@{}",
    "Linktree": "https://linktr.ee/{}"
}


def check_username_single(site_name: str, url_template: str, username: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Check if username exists on a single site.
    
    Returns:
        {
            "site": site name,
            "url": full URL,
            "exists": bool,
            "status_code": HTTP status
        }
    """
    url = url_template.format(username)
    result = {
        "site": site_name,
        "url": url,
        "exists": False,
        "status_code": None
    }
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resp = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        result["status_code"] = resp.status_code
        
        # 200 usually means account exists
        # Some sites return 200 for non-existent accounts too, but this is a basic check
        if resp.status_code == 200:
            result["exists"] = True
            
    except requests.exceptions.Timeout:
        result["status_code"] = "timeout"
    except Exception:
        result["status_code"] = "error"
    
    return result


def username_search(username: str, sites: Dict[str, str] = None, max_workers: int = 10, timeout: int = 5) -> Dict[str, Any]:
    """
    Search for username across multiple platforms.
    
    Sherlock-style username enumeration.
    
    Args:
        username: Username to search
        sites: Dict of {site_name: url_template}, uses default if None
        max_workers: Number of concurrent threads
        timeout: Request timeout per site
        
    Returns:
        {
            "username": username,
            "found_on": [{site, url}, ...],
            "not_found": [site names],
            "errors": [site names],
            "total_checked": int
        }
    """
    if sites is None:
        sites = SITES
    
    result = {
        "username": username,
        "found_on": [],
        "not_found": [],
        "errors": [],
        "total_checked": len(sites)
    }
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_username_single, name, url, username, timeout): name
            for name, url in sites.items()
        }
        
        for future in as_completed(futures):
            site_name = futures[future]
            try:
                check_result = future.result()
                if check_result["exists"]:
                    result["found_on"].append({
                        "site": check_result["site"],
                        "url": check_result["url"]
                    })
                elif check_result["status_code"] in ["timeout", "error"]:
                    result["errors"].append(site_name)
                else:
                    result["not_found"].append(site_name)
            except Exception:
                result["errors"].append(site_name)
    
    return result


def quick_username_check(username: str, priority_sites: List[str] = None) -> List[Dict[str, str]]:
    """
    Quick check for most popular sites only.
    
    Returns list of sites where username was found.
    """
    if priority_sites is None:
        priority_sites = ["GitHub", "Twitter", "Instagram", "Reddit", "LinkedIn", "TikTok"]
    
    sites_to_check = {k: v for k, v in SITES.items() if k in priority_sites}
    result = username_search(username, sites=sites_to_check, timeout=3)
    return result["found_on"]


def extract_social_handles(text: str) -> Dict[str, List[str]]:
    """
    Extract social media handles from text.
    
    Returns dict of {platform: [handles]}
    """
    import re
    
    patterns = {
        "twitter": r'@([a-zA-Z0-9_]{1,15})',
        "instagram": r'(?:instagram\.com/|@)([a-zA-Z0-9_.]{1,30})',
        "github": r'github\.com/([a-zA-Z0-9_-]+)',
        "linkedin": r'linkedin\.com/in/([a-zA-Z0-9_-]+)',
    }
    
    found = {}
    for platform, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            found[platform] = list(set(matches))
    
    return found
