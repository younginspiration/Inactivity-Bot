import requests
import json
import os
import time
import logging
import datetime
import pytz
from dotenv import load_dotenv
from typing import Dict, List, Tuple, Set, Optional, Any, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('activity_bot.log')
    ]
)
logger = logging.getLogger('ActivityBot')

# Debug: Print the current working directory
logger.info(f"Current working directory: {os.getcwd()}")

# Load environment variables
loaded = load_dotenv()
logger.info(f"Environment loaded: {loaded}")

# Debug: Check for relevant environment variables
if 'BOT_USERNAME' in os.environ and 'BOT_PASSWORD' in os.environ:
    logger.info("Environment variables loaded successfully.")
else:
    logger.warning("BOT_USERNAME or BOT_PASSWORD not found in environment variables.")

class ActivityBot:
    
    # Configuration
    API_URL = "https://testwiki.wiki/api.php"
    BOT_USERNAME = os.environ.get("BOT_USERNAME")
    BOT_PASSWORD = os.environ.get("BOT_PASSWORD")

    # Inactivity thresholds
    WARNING_THRESHOLD = 75  # days
    RIGHTS_REMOVAL_THRESHOLD = 90  # days
    WARNING_COOLDOWN = 14  # days
    REPORT_RETENTION = 20  # days
    
    # New specialized thresholds
    INTERFACE_ADMIN_THRESHOLD = 30  # days
    ABUSEFILTER_ADMIN_THRESHOLD = 90  # days
    NEW_RIGHTS_GRACE_PERIOD = 7  # days
    ABUSEFILTER_ADMIN_WARNING_THRESHOLD = 75  # Days before warning abuse filter admins
    
    # User groups to monitor
    MONITORED_GROUPS = ["sysop", "bureaucrat", "interface-admin", "abusefilter-admin"]
    
    # Rights classifications 
    BOT_REMOVABLE_RIGHTS = ["sysop", "bureaucrat", "interface-admin", "abusefilter-admin"]
    
    # Users to exclude from inactivity checks, usually stewards, and bots operated by MediaWiki and Steward
    EXCLUDED_USERS = [
        "EPIC", "Dmehus", "Drummingman", "Justarandomamerican", 
        "MacFan4000", "Abuse filter", "FuzzyBot", "MacFanBot", "DodoBot", "BusMuster",
    ]
    
    # Token management
    TOKEN_REFRESH_INTERVAL = 15 * 60  # 15 minutes in seconds
    
    # Page size management
    MAX_PAGE_SIZE = 100 * 1024  # 100KB
    
    # Message templates
    WARNING_MESSAGE = (
        "Hello {{BASEPAGENAME}}! This is an automated message to inform you that you have not made any edits "
        "or log actions in the past {days_inactive} days. According to the [[TW:IP|inactivity policy]], "
        "user rights may be removed after 90 days of inactivity. If you wish to retain your user rights, "
        "please make an edit or log action within the next {days_remaining} days. Thank you! ~~~~"
    )
    
    RIGHTS_REMOVAL_MESSAGE = (
        "Hello {{BASEPAGENAME}}! This is an automated message to inform you that due to {days_inactive} days of inactivity, "
        "the following user rights have been removed from your account: {rights_removed} "
        "According to the [[TW:IP|inactivity policy]], user rights are removed after 3 months of inactivity. "
        "If you wish to regain these rights, please request it at [[Test_Wiki:Request_for_permissions|Request for permissions]]. Thank you for your understanding! ~~~~"
    )
    
    # New specialized message templates
    INTERFACE_ADMIN_REMOVAL_MESSAGE = (
        "Hello {{BASEPAGENAME}}! This is an automated message to inform you that due to {days_inactive} days without making any edits "
        "to the MediaWiki namespace or CSS/JS files, your interface-admin right has been removed. "
        "According to the policy, interface-admin rights require activity in these specific areas at least once every 30 days. "
        "If you wish to regain this right, please request it at [[Test_Wiki:Request_for_permissions|Request for permissions]] "
        "Thank you for your understanding! ~~~~"
    )
    
    ABUSEFILTER_ADMIN_REMOVAL_MESSAGE = (
        "Hello! This is an automated message to inform you that due to {days_inactive} days without making any edits "
        "related to abuse filters, your AbuseFilter Administrator right has been removed. "
        "According to the policy, AbuseFilter Administrator rights require activity in the abuse filter area at least once every 3 months. "
        "If you wish to regain this right, please request it at [[Test_Wiki:Request_for_permissions|Request for permissions]] "
        "Thank you for your understanding! ~~~~"
    )

    ABUSEFILTER_ADMIN_WARNING_MESSAGE = (
        "Hello {{BASEPAGENAME}}! This is an automated message to inform you that"
        "you have not made any edits to abuse filters in the past"
        "{days_inactive} days. According to the [[TW:IP|inactivity policy]],"
        "if you do not make any edits to abuse filters within the next {days_until_removal} days,"
        "your abusefilter-admin right will be removed."
        "Thank you for your understanding! ~~~~"
    )
    def __init__(self):
        if not self.BOT_USERNAME or not self.BOT_PASSWORD:
            logger.error("Bot credentials (username/password) are missing. Please check your environment variables.")
            raise ValueError("Bot credentials are missing.")
        else:
            logger.info("Bot credentials loaded successfully.")

        # Initialize the bot with session and tokens.
        self.session = requests.Session()
        self.tokens = {}
        self.token_timestamp = {}  # Store when tokens were last refreshed
        self.users_by_group = {}
        self.warned_users = self._load_json("warned_users.json", {})
        self.reported_users = self._load_json("reported_users.json", {})
        self.actions_taken = {"warned": [], "removed": [], "flagged": []}
        self.timezone = pytz.UTC  # Use UTC as the standard timezone
        self.today = datetime.datetime.now(self.timezone).strftime("%Y-%m-%d")

    @staticmethod
    def _load_json(filename: str, default: Any) -> Any:
        # Load data from JSON file or return default if file doesn't exist.
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
        return default
    
    def _save_json(self, filename: str, data: Any) -> None:
        # Save data to JSON file.
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving {filename}: {e}")
    
    def login(self) -> bool:
        # Log in to the MediaWiki API.
        # Add this before the login attempt (temporarily for debugging)
        print(f"Username being used: {self.BOT_USERNAME}")
        print(f"Password length: {len(self.BOT_PASSWORD) if self.BOT_PASSWORD else 0}")
        # Get login token
        params = {
            "action": "query",
            "meta": "tokens",
            "type": "login",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()  # Raise exception for non-200 responses
            data = response.json()
            
            if "query" not in data or "tokens" not in data["query"] or "logintoken" not in data["query"]["tokens"]:
                logger.error(f"Invalid login token response: {data}")
                return False
                
            login_token = data["query"]["tokens"]["logintoken"]
            logger.info(f"Obtained login token: {login_token[:5]}...{login_token[-3:]}")
            
            # Login with token
            params = {
                "action": "login",
                "lgname": self.BOT_USERNAME,
                "lgpassword": self.BOT_PASSWORD,
                "lgtoken": login_token,
                "format": "json"
            }
            
            response = self.session.post(self.API_URL, data=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("login", {}).get("result") == "Success":
                logger.info(f"Successfully logged in as {data['login']['lgusername']}")
                self._refresh_all_tokens()
                return True
            else:
                logger.error(f"Login failed: {data}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Login request error: {e}")
            return False
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def _refresh_all_tokens(self) -> bool:
        """Refresh all tokens used by the bot and track when they were last refreshed"""
        success = True
        
        # Refresh CSRF token
        if not self._refresh_token("csrf"):
            success = False
            
        # Refresh userrights token
        if not self._refresh_token("userrights"):
            success = False
            
        return success
    
    def _refresh_token(self, token_type: str) -> bool:
        """Refresh a specific token"""
        token_types = {
            "csrf": {"action": "query", "meta": "tokens", "type": None},
            "userrights": {"action": "query", "meta": "tokens", "type": "userrights"}
        }
        
        if token_type not in token_types:
            logger.error(f"Unknown token type: {token_type}")
            return False
            
        token_config = token_types[token_type]
        params = {
            "action": token_config["action"],
            "meta": token_config["meta"],
            "format": "json"
        }
        
        if token_config["type"]:
            params["type"] = token_config["type"]
            
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            if token_type == "csrf":
                if "query" in data and "tokens" in data["query"] and "csrftoken" in data["query"]["tokens"]:
                    self.tokens["csrf"] = data["query"]["tokens"]["csrftoken"]
                    self.token_timestamp["csrf"] = time.time()
                    logger.info(f"Refreshed CSRF token: {self.tokens['csrf'][:5]}...{self.tokens['csrf'][-3:]}")
                    return True
            elif token_type == "userrights":
                if "query" in data and "tokens" in data["query"] and "userrightstoken" in data["query"]["tokens"]:
                    self.tokens["userrights"] = data["query"]["tokens"]["userrightstoken"]
                    self.token_timestamp["userrights"] = time.time()
                    logger.info(f"Refreshed userrights token: {self.tokens['userrights'][:5]}...{self.tokens['userrights'][-3:]}")
                    return True
                    
            logger.error(f"Failed to refresh {token_type} token. Response: {data}")
            return False
            
        except requests.RequestException as e:
            logger.error(f"Token refresh request error for {token_type}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error refreshing {token_type} token: {e}")
            return False
    
    def _ensure_token_fresh(self, token_type: str) -> bool:
        """Ensure a token is fresh, refreshing it if necessary"""
        if (token_type not in self.tokens or 
            token_type not in self.token_timestamp or 
            time.time() - self.token_timestamp.get(token_type, 0) > self.TOKEN_REFRESH_INTERVAL):
            logger.info(f"{token_type} token expired or missing - refreshing")
            return self._refresh_token(token_type)
        return True
    
    def get_users_by_group(self) -> None:
        # Get all users in monitored groups.
        for group in self.MONITORED_GROUPS:
            params = {
                "action": "query",
                "list": "allusers",
                "augroup": group,
                "aulimit": "500",
                "format": "json"
            }
            
            try:
                response = self.session.get(url=self.API_URL, params=params)
                response.raise_for_status()
                data = response.json()
                
                if "query" in data and "allusers" in data["query"]:
                    users = [user["name"] for user in data["query"]["allusers"]]
                    self.users_by_group[group] = users
                    logger.info(f"Found users in group '{group}': {len(users)}")
                else:
                    logger.error(f"Invalid response format for group '{group}': {data}")
                    self.users_by_group[group] = []
                
            except requests.RequestException as e:
                logger.error(f"Request error getting users in group '{group}': {e}")
                self.users_by_group[group] = []
            except Exception as e:
                logger.error(f"Error getting users in group '{group}': {e}")
                self.users_by_group[group] = []
    
    def _parse_timestamp(self, timestamp: str) -> datetime.datetime:
        """Parse MediaWiki API timestamp format to datetime object with UTC timezone"""
        dt = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        return pytz.utc.localize(dt)
    
    def get_user_last_activity(self, username: str) -> Tuple[str, int]:
        # Get the date of the user's last activity and days since then
        params = {
            "action": "query",
            "list": "usercontribs",
            "ucuser": username,
            "uclimit": 1,
            "ucprop": "timestamp",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            contribs = data.get("query", {}).get("usercontribs", [])
            
            # Check the logs
            params = {
                "action": "query",
                "list": "logevents",
                "leprop": "timestamp",
                "leuser": username,
                "lelimit": 1,
                "format": "json"
            }
            
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            log_data = response.json()
            logs = log_data.get("query", {}).get("logevents", [])
            
            last_timestamp = None
            
            if contribs and logs:
                contrib_date = self._parse_timestamp(contribs[0]["timestamp"])
                log_date = self._parse_timestamp(logs[0]["timestamp"])
                last_date = max(contrib_date, log_date)
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                last_date_for_calc = last_date
            elif contribs:
                last_date = self._parse_timestamp(contribs[0]["timestamp"])
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                last_date_for_calc = last_date
            elif logs:
                last_date = self._parse_timestamp(logs[0]["timestamp"])
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                last_date_for_calc = last_date
            else:
                # No activity found
                return "No activity found", 999
            
            # Calculate days since last activity
            now = datetime.datetime.now(pytz.UTC)
            days_inactive = (now - last_date_for_calc).days
            
            return last_timestamp, days_inactive
            
        except requests.RequestException as e:
            logger.error(f"Request error getting last activity for {username}: {e}")
            return "Error", 0
        except Exception as e:
            logger.error(f"Error getting last activity for {username}: {e}")
            return "Error", 0

    def get_user_interface_activity(self, username: str) -> Tuple[str, int]:
        """
        Check a user's interface-related activity (edits to MediaWiki namespace or CSS/JS files)
        Returns last activity date and days since then
        """
        # Check MediaWiki namespace edits
        params = {
            "action": "query",
            "list": "usercontribs",
            "ucuser": username,
            "ucnamespace": "8",  # MediaWiki namespace
            "uclimit": 1,
            "ucprop": "timestamp",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            mediawiki_contribs = data.get("query", {}).get("usercontribs", [])
            
            # Check CSS/JS edits in user namespace
            params = {
                "action": "query",
                "list": "usercontribs",
                "ucuser": username,
                "ucnamespace": "2",  # User namespace
                "ucprop": "timestamp|title",
                "uclimit": 100,  # Get more to filter CSS/JS files
                "format": "json"
            }
            
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Filter for CSS/JS edits only
            user_css_js_contribs = []
            for contrib in data.get("query", {}).get("usercontribs", []):
                if contrib["title"].lower().endswith(".css") or contrib["title"].lower().endswith(".js"):
                    user_css_js_contribs.append(contrib)
            
            last_timestamp = None
            
            # Find the most recent edit across both types
            if mediawiki_contribs and user_css_js_contribs:
                mediawiki_date = self._parse_timestamp(mediawiki_contribs[0]["timestamp"])
                user_css_js_date = self._parse_timestamp(user_css_js_contribs[0]["timestamp"])
                last_date = max(mediawiki_date, user_css_js_date)
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                last_date_for_calc = last_date
            elif mediawiki_contribs:
                last_date = self._parse_timestamp(mediawiki_contribs[0]["timestamp"])
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                last_date_for_calc = last_date
            elif user_css_js_contribs:
                last_date = self._parse_timestamp(user_css_js_contribs[0]["timestamp"])
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                last_date_for_calc = last_date
            else:
                # No interface activity found
                return "No interface activity found", 999
            
            # Calculate days since last activity
            now = datetime.datetime.now(pytz.UTC)
            days_inactive = (now - last_date_for_calc).days
            
            return last_timestamp, days_inactive
            
        except requests.RequestException as e:
            logger.error(f"Request error getting interface activity for {username}: {e}")
            return "Error", 999
        except Exception as e:
            logger.error(f"Error getting interface activity for {username}: {e}")
            return "Error", 999

    def get_user_abusefilter_activity(self, username: str) -> Tuple[str, int]:
        """
        Check a user's abuse filter activity using only the log entries
        Returns last activity date and days since then
        """
        # Use Special:Log with type=abusefilter parameter directly
        params = {
            "action": "query",
            "list": "logevents",
            "letype": "abusefilter",
            "leuser": username,
            "lelimit": 1,
            "leprop": "timestamp",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            filter_logs = data.get("query", {}).get("logevents", [])
            
            if filter_logs:
                last_date = self._parse_timestamp(filter_logs[0]["timestamp"])
                last_timestamp = last_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                
                # Calculate days since last activity
                now = datetime.datetime.now(pytz.UTC)
                days_inactive = (now - last_date).days
                
                return last_timestamp, days_inactive
            else:
                # No abuse filter activity found
                return "No abuse filter activity found", 999
                
        except requests.RequestException as e:
            logger.error(f"Request error getting abuse filter activity for {username}: {e}")
            return "Error", 999
        except Exception as e:
            logger.error(f"Error getting abuse filter activity for {username}: {e}")
            return "Error", 999

    def check_rights_grant_date(self, username, right):
        """
        Check when a user was granted specific rights.
        Returns (is_new_right, days_since_grant) tuple.

        Args:
            username (str): Username to check
            right (str): Right to check for

        Returns:
            tuple: (is_new_right, days_since_grant) where is_new_right is bool and
                   days_since_grant is int or None if not found
        """
        self._ensure_token_fresh('userrights')
        params = {
            "action": "query",
            "list": "logevents",
            "letype": "rights",
            "letitle": f"User:{username}",
            "leprop": "timestamp|details",
            "format": "json",
            "token": self.tokens['userrights']
        }

        try:
            response = self.session.get(url=self.API_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            if 'error' in data:
                logger.error(f"API error while checking rights for {username}: {data['error']}")
                return False, None

            log_entries = data.get('query', {}).get('logevents', [])
            if not log_entries:
                logger.info(f"No rights log entries found for {username}")
                return False, None

            for entry in log_entries:
                params = entry.get('params', {})
                new_groups = params.get('newgroups', [])
                old_groups = params.get('oldgroups', [])

                if right in new_groups and right not in old_groups:
                    timestamp = entry.get('timestamp')
                    if not timestamp:
                        continue

                    try:
                        # Make sure we're working with a datetime object
                        if isinstance(timestamp, str):
                            grant_date = self._parse_timestamp(timestamp)
                        else:
                            grant_date = timestamp

                        if not isinstance(self.today, datetime.datetime):
                            # Ensure self.today is also a datetime object
                            self.today = datetime.datetime.now(datetime.timezone.utc)

                        days_since_grant = (self.today - grant_date).days
                        logger.info(
                            f"{username} was granted {right} on {grant_date.strftime('%Y-%m-%d')} "
                            f"({days_since_grant} days ago)"
                        )
                        return days_since_grant <= self.NEW_RIGHTS_GRACE_PERIOD, days_since_grant
                    except (ValueError, TypeError) as e:
                        ogger.error(f"Error parsing timestamp for {username}: {str(e)}")
                        continue

            logger.info(
                f"Could not find {right} grant in {len(log_entries)} log entries for {username}. "
                f"Latest entry: {log_entries[0].get('timestamp', 'N/A') if log_entries else 'N/A'}"
            )
            return False, None

        except requests.Timeout:
            logger.error(f"Timeout while checking rights for {username}")
            return False, None
        except requests.RequestException as e:
            logger.error(f"Network error checking rights for {username}: {str(e)}")
            return False, None
        except Exception as e:
            logger.error(f"Unexpected error checking rights for {username}: {str(e)}")
            return False, None
    
    def check_recent_activity(self, username: str) -> bool:
        """
        Check if the user has been active very recently (to avoid removing rights from users
        who became active after the initial check but before rights removal)
        """
        # This is a safety check to ensure users who became active after the initial check
        # don't have their rights removed incorrectly
        last_timestamp, days_inactive = self.get_user_last_activity(username)
        
        # If the user has been active in the last day, consider them active
        return days_inactive <= 1
    
    def send_user_message(self, username: str, message: str) -> bool:
        # Ensure token is fresh before sending message
        if not self._ensure_token_fresh("csrf"):
            logger.error(f"Failed to refresh token before sending message to {username}")
            return False
            
        # Send a message to a user's talk page.
        params = {
            "action": "edit",
            "title": f"User talk:{username}",
            "section": "new",
            "summary": "Automated inactivity notification",
            "text": message,
            "token": self.tokens["csrf"],
            "format": "json",
            "bot": "1"
        }
        
        try:
            response = self.session.post(url=self.API_URL, data=params)
            response.raise_for_status()
            data = response.json()
            
            if "error" not in data:
                logger.info(f"Successfully sent message to User talk:{username}")
                return True
            else:
                logger.error(f"API error sending message to {username}: {data['error']}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Request error sending message to {username}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending message to {username}: {e}")
            return False
    
    def remove_user_rights(self, username: str, rights_to_remove: List[str]) -> bool:
        # Do a final check to see if the user has been active recently
        if self.check_recent_activity(username):
            logger.info(f"User {username} has been active recently. Not removing rights.")
            return False
            
        # Ensure token is fresh before removing rights
        if not self._ensure_token_fresh("userrights"):
            logger.error(f"Failed to refresh token before removing rights from {username}")
            return False
            
        # Remove specified rights from a user.
        # First get current user rights
        params = {
            "action": "query",
            "list": "users",
            "ususers": username,
            "usprop": "groups",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            if "query" not in data or "users" not in data["query"] or not data["query"]["users"]:
                logger.error(f"Invalid response when fetching user groups for {username}: {data}")
                return False
                
            current_rights = data["query"]["users"][0].get("groups", [])
            
            # Calculate rights to keep
            rights_to_keep = [right for right in current_rights if right not in rights_to_remove]
            
            # Remove the rights
            params = {
                "action": "userrights",
                "user": username,
                "add": "",
                "expiry": "",
                "reason": "Automatically removed due to inactivity",
                "remove": "|".join(rights_to_remove),
                "token": self.tokens["userrights"],
                "format": "json"
            }
            
            response = self.session.post(url=self.API_URL, data=params)
            response.raise_for_status()
            data = response.json()
            
            if "error" not in data:
                logger.info(f"Successfully removed rights {rights_to_remove} from {username}")
                return True
            else:
                logger.error(f"API error removing rights from {username}: {data['error']}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Request error removing rights from {username}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error removing rights from {username}: {e}")
            return False
    
    def check_user_activity(self, username: str, user_groups: List[str]) -> None:
        # Check a user's activity and take appropriate actions.
        logger.info(f"Checking activity for {username} (groups: {', '.join(user_groups)})")
        
        # Skip excluded users and the bot itself
        if username in self.EXCLUDED_USERS or username == self.BOT_USERNAME.split('@')[0]:
            return
        
        # Track rights to remove and reasons
        rights_to_remove = []
        removal_reasons = {}
        
        # Track if the user has sysop/bureaucrat rights (special rights)
        has_special_rights = "sysop" in user_groups or "bureaucrat" in user_groups
        
        # Get general last activity
        last_activity_date, days_inactive = self.get_user_last_activity(username)
        
        # Check Interface Admin activity if applicable
        if "interface-admin" in user_groups:
            # Check if this is a new right (within grace period)
            is_new_right, days_since_grant = self.check_rights_grant_date(username, "interface-admin")
            
            if is_new_right:
                logger.info(f"Skipping interface-admin check for {username} - right granted {days_since_grant} days ago (within {self.NEW_RIGHTS_GRACE_PERIOD}-day grace period)")
            else:
                # Check specific interface activity
                interface_last_date, interface_days_inactive = self.get_user_interface_activity(username)
                
                if interface_days_inactive >= self.INTERFACE_ADMIN_THRESHOLD:
                    logger.info(f"{username} has no interface activity for {interface_days_inactive} days")
                    
                    # Only remove interface-admin right
                    rights_to_remove.append("interface-admin")
                    removal_reasons["interface-admin"] = {
                        "days_inactive": interface_days_inactive,
                        "last_activity": interface_last_date
                    }
        
        # Check Abuse Filter Admin activity if applicable
        if "abusefilter-admin" in user_groups:
            af_timestamp, af_days = self.get_user_abusefilter_activity(username)


            # Warning check
            if af_days >= self.ABUSEFILTER_ADMIN_WARNING_THRESHOLD and af_days < self.ABUSEFILTER_ADMIN_THRESHOLD:
                if self._should_warn_user(username):
                    days_until_removal = self.ABUSEFILTER_ADMIN_THRESHOLD - af_days
                    self.send_user_message(
                        username,
                        self.ABUSEFILTER_ADMIN_WARNING_MESSAGE.format(
                            days_inactive=af_days,
                            days_until_removal=days_until_removal
                        )
                    )
                    self.warned_users[username] = self.today
            # Removal check
            if af_days >= self.ABUSEFILTER_ADMIN_THRESHOLD:
                if self.remove_user_rights(username, ["abusefilter"]):
                    self.send_user_message(
                        username,
                        self.ABUSEFILTER_ADMIN_REMOVAL_MESSAGE.format(days_inactive=af_days)
                    )
        
        # Check general inactivity for all users
        if days_inactive >= self.WARNING_THRESHOLD:
            # Handle warning for approaching inactivity threshold
            if days_inactive < self.RIGHTS_REMOVAL_THRESHOLD:
                logger.info(f"{username} is approaching inactivity threshold ({days_inactive} days inactive)")
                
                # Check if user was already warned within the cooldown period
                already_warned = False
                if username in self.warned_users:
                    try:
                        warning_date = datetime.datetime.strptime(self.warned_users[username]["date"], "%Y-%m-%d")
                        warning_date = pytz.UTC.localize(warning_date)  # Add UTC timezone
                        now = datetime.datetime.now(pytz.UTC)
                        days_since_warning = (now - warning_date).days
                        
                        if days_since_warning < self.WARNING_COOLDOWN:
                            already_warned = True
                            logger.info(f"Skipping warning for {username} as they've already been warned {days_since_warning} days ago (cooldown: {self.WARNING_COOLDOWN} days)")
                    except ValueError:
                           # If date parsing fails, assume the user hasn't been warned properly
                        logger.warning(f"Invalid warning date format for {username}: {self.warned_users[username]['date']}")
                
                # Send warning if needed
                if not already_warned:
                    days_remaining = self.RIGHTS_REMOVAL_THRESHOLD - days_inactive
                    warning_message = self.WARNING_MESSAGE.format(
                        days_inactive=days_inactive,
                        days_remaining=days_remaining
                    )
                    
                    # Attempt to send the warning message
                    if self.send_user_message(username, warning_message):
                        # Only mark as warned if the message was sent successfully
                        self.warned_users[username] = {
                            "date": self.today,
                            "days_inactive": days_inactive
                        }
                        self._save_json("warned_users.json", self.warned_users)
                        self.actions_taken["warned"].append(username)
                        logger.info(f"Warned {username} about upcoming inactivity removal")
                    else:
                        logger.error(f"Failed to send warning message to {username}, not marking as warned")
            
            # Handle complete inactivity threshold
            elif days_inactive >= self.RIGHTS_REMOVAL_THRESHOLD:
                logger.info(f"{username} has exceeded inactivity threshold ({days_inactive} days inactive)")
                
                # Add all applicable user rights to the removal list (if not already added for specific reasons)
                for right in user_groups:
                    if right in self.BOT_REMOVABLE_RIGHTS and right not in rights_to_remove:
                        rights_to_remove.append(right)
                        removal_reasons[right] = {
                            "days_inactive": days_inactive,
                            "last_activity": last_activity_date
                        }
        
        # If there are rights to remove, process them
        if rights_to_remove:
            logger.info(f"Rights to remove from {username}: {', '.join(rights_to_remove)}")
            
            # Remove the rights
            if self.remove_user_rights(username, rights_to_remove):
                # Send appropriate notification messages
                message_sent = False
                
                # Check if we removed interface-admin specifically
                if "interface-admin" in rights_to_remove and "interface-admin" in removal_reasons:
                    interface_message = self.INTERFACE_ADMIN_REMOVAL_MESSAGE.format(
                        days_inactive=removal_reasons["interface-admin"]["days_inactive"]
                    )
                    if self.send_user_message(username, interface_message):
                        message_sent = True
                        logger.info(f"Sent interface-admin removal message to {username}")
                    else:
                        logger.error(f"Failed to send interface-admin removal message to {username}")
                
                # Check if we removed abusefilter-admin specifically
                if "abusefilter-admin" in rights_to_remove and "abusefilter-admin" in removal_reasons:
                    filter_message = self.ABUSEFILTER_ADMIN_REMOVAL_MESSAGE.format(
                        days_inactive=removal_reasons["abusefilter-admin"]["days_inactive"]
                    )
                    if self.send_user_message(username, filter_message):
                        message_sent = True
                        logger.info(f"Sent abusefilter-admin removal message to {username}")
                    else:
                        logger.error(f"Failed to send abusefilter-admin removal message to {username}")
                
                # Send general rights removal message if no specific messages were sent
                # or if sysop/bureaucrat rights were removed
                if not message_sent or has_special_rights:
                    rights_removed_str = ", ".join(rights_to_remove)
                    removal_message = self.RIGHTS_REMOVAL_MESSAGE.format(
                        days_inactive=days_inactive,
                        rights_removed=rights_removed_str
                    )
                    if self.send_user_message(username, removal_message):
                        logger.info(f"Sent general rights removal message to {username}")
                    else:
                        logger.error(f"Failed to send general rights removal message to {username}")
                
                # Record the actions
                self.reported_users[username] = {
                    "date": self.today,
                    "days_inactive": days_inactive,
                    "rights_removed": rights_to_remove
                }
                self._save_json("reported_users.json", self.reported_users)
                self.actions_taken["removed"].append(username)
            else:
                logger.error(f"Failed to remove rights from {username}")

    def cleanup_reported_users(self) -> None:
        """Clean up old entries in the reported_users dictionary to avoid indefinite growth"""
        # Remove the strptime conversion since self.today is already a datetime object
        current_date = pytz.UTC.localize(self.today) if self.today.tzinfo is None else self.today

        users_to_remove = []

        for username, data in self.reported_users.items():
            try:
                report_date = datetime.datetime.strptime(data["date"], "%Y-%m-%d")
                report_date = pytz.UTC.localize(report_date)

                days_since_report = (current_date - report_date).days

                if days_since_report > self.REPORT_RETENTION:
                    users_to_remove.append(username)

            except (ValueError, KeyError) as e:
                logger.warning(f"Error processing reported user data for {username}: {e}")
                # Keep invalid entries to avoid data loss, they can be manually reviewed

        for username in users_to_remove:
            del self.reported_users[username]

        if users_to_remove:
            logger.info(f"Cleaned up {len(users_to_remove)} old entries from reported users")
            self._save_json("reported_users.json", self.reported_users)

    def update_activity_report(self) -> bool:
        """Update the activity report page with the latest user activity information"""
        # Ensure token is fresh before updating the report
        if not self._ensure_token_fresh("csrf"):
            logger.error("Failed to refresh token before updating activity report")
            return False
            
        # Get page content to check size before updating
        params = {
            "action": "query",
            "titles": "Activity/Reports",
            "prop": "revisions",
            "rvprop": "content|size",
            "rvslots": "main",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Extract page info
            pages = data.get("query", {}).get("pages", {})
            page_id = next(iter(pages.keys()), None)
            
            if not page_id or page_id == "-1":  # Page doesn't exist yet
                current_content = ""
                current_size = 0
                logger.info("Activity report page doesn't exist yet, creating it")
            else:
                page_data = pages[page_id]
                revisions = page_data.get("revisions", [])
                
                if not revisions:
                    current_content = ""
                    current_size = 0
                else:
                    current_size = revisions[0].get("size", 0)
                    current_content = revisions[0].get("slots", {}).get("main", {}).get("*", "")
            
            # Check if the page is too large and needs rotation
            if current_size >= self.MAX_PAGE_SIZE:
                # Archive current report
                archive_date = datetime.datetime.now(self.timezone).strftime("%Y-%m-%d")
                archive_title = f"Activity/Archive-{archive_date}"
                
                # Create archive
                params = {
                    "action": "edit",
                    "title": archive_title,
                    "text": current_content,
                    "summary": "Archiving activity report due to size",
                    "token": self.tokens["csrf"],
                    "format": "json",
                    "bot": "1"
                }
                
                archive_response = self.session.post(url=self.API_URL, data=params)
                archive_response.raise_for_status()
                archive_data = archive_response.json()
                
                if "error" in archive_data:
                    logger.error(f"Failed to create archive: {archive_data['error']}")
                    return False
                
                logger.info(f"Created archive at {archive_title}")
                
                # Reset current content
                current_content = (
                    "== Archived Reports ==\n"
                    f"* [{archive_date}](Activity/Archive-{archive_date})\n\n"
                )
            
            # Generate the report content
            report_date = datetime.datetime.now(self.timezone).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            report_content = f"== Activity Report: {report_date} ==\n"
            
            # Add warning and removal sections
            if self.actions_taken["warned"]:
                report_content += "\n=== Users Warned ===\n"
                for username in sorted(self.actions_taken["warned"]):
                    days_inactive = self.warned_users.get(username, {}).get("days_inactive", "unknown")
                    report_content += f"* [[User:{username}|{username}]] - {days_inactive} days inactive\n"
            
            if self.actions_taken["removed"]:
                report_content += "\n=== Rights Removed ===\n"
                for username in sorted(self.actions_taken["removed"]):
                    rights_removed = ", ".join(self.reported_users.get(username, {}).get("rights_removed", []))
                    days_inactive = self.reported_users.get(username, {}).get("days_inactive", "unknown")
                    report_content += f"* [[User:{username}|{username}]] - {days_inactive} days inactive - Rights removed: {rights_removed}\n"
            
            if not self.actions_taken["warned"] and not self.actions_taken["removed"]:
                report_content += "\nNo actions taken in this run.\n"
            
            # Update the report page
            params = {
                "action": "edit",
                "title": "Activity/Reports",
                "text": current_content + report_content,
                "summary": f"Updating activity report for {self.today}",
                "token": self.tokens["csrf"],
                "format": "json",
                "bot": "1"
            }
            
            response = self.session.post(url=self.API_URL, data=params)
            response.raise_for_status()
            data = response.json()
            
            if "error" not in data:
                logger.info("Successfully updated activity report")
                return True
            else:
                logger.error(f"API error updating activity report: {data['error']}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Request error updating activity report: {e}")
            return False
        except Exception as e:
            logger.error(f"Error updating activity report: {e}")
            return False
    
    def run(self) -> bool:
        """Run the activity bot checks"""
        logger.info("Starting ActivityBot run")
        
        # Login
        if not self.login():
            logger.error("Login failed, aborting run")
            return False
        
        # Get all users in monitored groups
        self.get_users_by_group()
        
        # Process each user in monitored groups
        all_processed_users = set()
        for group, users in self.users_by_group.items():
            for username in users:
                if username not in all_processed_users:
                    # Get all groups the user is in
                    user_groups = [g for g, users_in_group in self.users_by_group.items() if username in users_in_group]
                    self.check_user_activity(username, user_groups)
                    all_processed_users.add(username)
        
        # Clean up old reported users
        self.cleanup_reported_users()
        
        # Update the activity report
        self.update_activity_report()
        
        logger.info(f"ActivityBot run completed - warned: {len(self.actions_taken['warned'])}, removed: {len(self.actions_taken['removed'])}")
        return True


def main():
    """Main function to run the bot"""
    try:
        bot = ActivityBot()
        success = bot.run()
        
        if success:
            logger.info("Bot run completed successfully")
        else:
            logger.error("Bot run failed")
            
    except Exception as e:
        logger.critical(f"Unhandled exception in bot run: {e}", exc_info=True)


if __name__ == "__main__":
    main()
