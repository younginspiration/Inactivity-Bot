import requests
import json
import os
import time
import logging
import datetime
import pytz
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


class ActivityBot:

    # Configuration
    API_URL = "https://testwiki.wiki/api.php"

    # Load credentials from environment variables
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

    # User groups to monitor
    MONITORED_GROUPS = ["sysop", "bureaucrat",
        "interface-admin", "abusefilter-admin"]

    # Rights classifications
    BOT_REMOVABLE_RIGHTS = ["sysop", "bureaucrat",
        "interface-admin", "abusefilter-admin"]

    # Users to exclude from inactivity checks, usually stewards, and bots operated by MediaWiki and Steward
    EXCLUDED_USERS = [
        "EPIC", "Dmehus", "Drummingman", "Justarandomamerican",
        "MacFan4000", "Abuse filter", "FuzzyBot", "MacFanBot",
    ]

    # Token management
    TOKEN_REFRESH_INTERVAL = 15 * 60  # 15 minutes in seconds

    # Page size management
    MAX_PAGE_SIZE = 100 * 1024  # 100KB

    # Message templates
    WARNING_MESSAGE = (
    "Hello {username}! This is an automated message to inform you that you have not made any edits "
    "or log actions in the past {days_inactive} days. According to the [[TW:IP|inactivity policy]], "
    "user rights may be removed after 90 days of inactivity. If you wish to retain your user rights, "
    "please make an edit or log action within the next {days_remaining} days. Thank you! ~~~~"
)


RIGHTS_REMOVAL_MESSAGE = (
    "Hello {username}! This is an automated message to inform you that due to {days_inactive} days of inactivity, "
    "the following user rights have been removed from your account: {rights_removed} "
    "According to the [[TW:IP|inactivity policy]], user rights are removed after 3 months of inactivity. "
    "If you wish to regain these rights, please request it at [[Test_Wiki:Request_for_permissions|Request for permissions]]. Thank you for your understanding! ~~~~"
)

INTERFACE_ADMIN_REMOVAL_MESSAGE = (
    "Hello {username}! This is an automated message to inform you that due to {days_inactive} days without making any edits "
    "to the MediaWiki namespace or CSS/JS files, your interface-admin right has been removed. "
    "According to the policy, interface-admin rights require activity in these specific areas at least once every 30 days. "
    "If you wish to regain this right, please request it at [[Test_Wiki:Request_for_permissions|Request for permissions]] "
    "Thank you for your understanding! ~~~~"
)

ABUSEFILTER_ADMIN_REMOVAL_MESSAGE = (
    "Hello {username}! This is an automated message to inform you that due to {days_inactive} days without making any edits "
    "related to abuse filters, your AbuseFilter Administrator right has been removed. "
    "According to the policy, AbuseFilter Administrator rights require activity in the abuse filter area at least once every 3 months. "
    "If you wish to regain this right, please request it at [[Test_Wiki:Request_for_permissions|Request for permissions]] "
    "Thank you for your understanding! ~~~~"
)

def __init__(self):
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

        # Check if credentials are available
        if not self.BOT_USERNAME or not self.BOT_PASSWORD:
            logger.error("Bot credentials not found in environment variables")
            raise ValueError(
                "Bot credentials not found in environment variables")

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

def check_rights_grant_date(self, username: str, right: str) -> Tuple[bool, int]:
    """
    Check when a user was granted a specific right
    Returns (is_new_right, days_since_grant)
    """
    params = {
        "action": "query",
        "list": "logevents",
        "letype": "rights",
        "letitle": f"User:{username}",
        "lelimit": 50,  # Get enough to find the most recent grant
        "leprop": "timestamp|details|comment",
        "format": "json"
    }
    
    try:
        response = self.session.get(url=self.API_URL, params=params)
        response.raise_for_status()
        data = response.json()
        rights_logs = data.get("query", {}).get("logevents", [])
        
        for log in rights_logs:
            # More robust checking for rights in params, details or comment
            rights_added = []
            
            # Check params if available
            if "params" in log and isinstance(log["params"], dict):
                if "add" in log["params"] and isinstance(log["params"]["add"], list):
                    rights_added.extend(log["params"]["add"])
                elif "newgroups" in log["params"] and isinstance(log["params"]["newgroups"], list):
                    old_groups = log["params"].get("oldgroups", [])
                    new_groups = log["params"]["newgroups"]
                    rights_added.extend([g for g in new_groups if g not in old_groups])
            
            # Check details if available and params didn't work
            if not rights_added and "details" in log and isinstance(log["details"], dict):
                if "add" in log["details"] and isinstance(log["details"]["add"], list):
                    rights_added.extend(log["details"]["add"])
                elif "added" in log["details"] and isinstance(log["details"]["added"], list):
                    rights_added.extend(log["details"]["added"])
            
            # Check comment as a last resort
            if not rights_added and "comment" in log:
                comment = log["comment"].lower()
                if f"added {right}" in comment or f"granted {right}" in comment or f"+{right}" in comment:
                    rights_added.append(right)
            
            # Check if the right we're looking for was added
            if right in rights_added:
                grant_date = self._parse_timestamp(log["timestamp"])
                now = datetime.datetime.now(pytz.UTC)
                days_since_grant = (now - grant_date).days
                
                # Check if this is within the grace period
                is_new_right = days_since_grant <= self.NEW_RIGHTS_GRACE_PERIOD
                logger.info(f"User {username} was granted {right} {days_since_grant} days ago.")
                return is_new_right, days_since_grant
        
        # If we got here, we didn't find a log entry granting this right
        logger.info(f"Could not find when {username} was granted {right}.")
        # Return that it's not a new right (conservative approach)
        return False, 999
        
    except requests.RequestException as e:
        logger.error(f"Request error checking rights grant date for {username} ({right}): {e}")
        return False, 999
    except Exception as e:
        logger.error(f"Error checking rights grant date for {username} ({right}): {e}")
        return False, 999       
        
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
    
      
def send_user_message(self, username: str, message: str, **kwargs) -> bool:
       # Ensure token is fresh before sending message
       if not self._ensure_token_fresh("csrf"):
          logger.error(f"Failed to refresh token before sending message to {username}")
          return False
    
       # Format the message with username and any other kwargs
       all_kwargs = {"username": username, **kwargs}
       formatted_message = message.format(**all_kwargs)
    
       # Send a message to a user's talk page.
       params = {
         "action": "edit",
         "title": f"User talk:{username}",
         "section": "new",
         "summary": "Automated inactivity notification",
         "text": formatted_message,
         "token": self.tokens["csrf"],
         "format": "json"
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
        # Check if this is a new right (within grace period)
        is_new_right, days_since_grant = self.check_rights_grant_date(username, "abusefilter-admin")
        
        if is_new_right:
            logger.info(f"Skipping abusefilter-admin check for {username} - right granted {days_since_grant} days ago (within {self.NEW_RIGHTS_GRACE_PERIOD}-day grace period)")
        else:
            # Check specific abuse filter activity
            filter_last_date, filter_days_inactive = self.get_user_abusefilter_activity(username)
            
            if filter_days_inactive >= self.ABUSEFILTER_ADMIN_THRESHOLD:
                logger.info(f"{username} has no abuse filter activity for {filter_days_inactive} days")
                
                # Only remove abusefilter-admin right
                rights_to_remove.append("abusefilter-admin")
                removal_reasons["abusefilter-admin"] = {
                    "days_inactive": filter_days_inactive,
                    "last_activity": filter_last_date
                }
    
    # Now check general inactivity for all rights
    if days_inactive >= self.RIGHTS_REMOVAL_THRESHOLD:
        logger.info(f"{username} is inactive for {days_inactive} days (above removal threshold)")
        
        # Add all monitored groups except those already flagged for removal
        for group in user_groups:
            if group in self.BOT_REMOVABLE_RIGHTS and group not in rights_to_remove:
                rights_to_remove.append(group)
                removal_reasons[group] = {
                    "days_inactive": days_inactive,
                    "last_activity": last_activity_date
                }
    
    # If there are rights to remove, remove them and notify the user
    if rights_to_remove:
        logger.info(f"Removing rights from {username}: {', '.join(rights_to_remove)}")
        
        # Remove the rights
        if self.remove_user_rights(username, rights_to_remove):
            # Send appropriate notification based on which rights were removed
            if "interface-admin" in rights_to_remove and len(rights_to_remove) == 1:
                # Only interface-admin was removed
                self.send_user_message(username, self.INTERFACE_ADMIN_REMOVAL_MESSAGE, 
                                      days_inactive=removal_reasons["interface-admin"]["days_inactive"])
                self.actions_taken["removed"].append({
                    "username": username,
                    "rights": ["interface-admin"],
                    "reason": "No interface activity"
                })
            elif "abusefilter-admin" in rights_to_remove and len(rights_to_remove) == 1:
                # Only abusefilter-admin was removed
                self.send_user_message(username, self.ABUSEFILTER_ADMIN_REMOVAL_MESSAGE,
                                      days_inactive=removal_reasons["abusefilter-admin"]["days_inactive"])
                self.actions_taken["removed"].append({
                    "username": username,
                    "rights": ["abusefilter-admin"],
                    "reason": "No abuse filter activity"
                })
            else:
                # General inactivity or multiple rights removed
                rights_removed_str = ", ".join(rights_to_remove)
                self.send_user_message(username, self.RIGHTS_REMOVAL_MESSAGE,
                                      days_inactive=days_inactive, rights_removed=rights_removed_str)
                self.actions_taken["removed"].append({
                    "username": username,
                    "rights": rights_to_remove,
                    "reason": "General inactivity"
                })
    
    # Otherwise, check if we should warn the user
    elif days_inactive >= self.WARNING_THRESHOLD:
        # Check if the user has been warned recently
        warned_date = self.warned_users.get(username, {}).get("date", "")
        
        if warned_date:
            # Convert to datetime object
            try:
                warned_datetime = datetime.datetime.strptime(warned_date, "%Y-%m-%d").replace(tzinfo=pytz.UTC)
                days_since_warning = (datetime.datetime.now(pytz.UTC) - warned_datetime).days
                
                # Only warn again if cooldown period has passed
                if days_since_warning >= self.WARNING_COOLDOWN:
                    send_warning = True
                else:
                    logger.info(f"Skipping warning for {username} - already warned {days_since_warning} days ago (within {self.WARNING_COOLDOWN}-day cooldown)")
                    send_warning = False
            except ValueError:
                # Invalid date format, warn again
                send_warning = True
        else:
            # User has not been warned before
            send_warning = True
        
        if send_warning:
            logger.info(f"Warning {username} about {days_inactive} days of inactivity")
            
            # Calculate days remaining before rights removal
            days_remaining = self.RIGHTS_REMOVAL_THRESHOLD - days_inactive
            days_remaining = max(days_remaining, 0)  # Ensure non-negative
            
            # Send warning
            if self.send_user_message(username, self.WARNING_MESSAGE, 
                                     days_inactive=days_inactive, days_remaining=days_remaining):
                # Record the warning
                self.warned_users[username] = {
                    "date": self.today,
                    "days_inactive": days_inactive
                }
                self._save_json("warned_users.json", self.warned_users)
                
                self.actions_taken["warned"].append({
                    "username": username,
                    "days_inactive": days_inactive
                })
                                         
    def update_activity_report(self) -> bool:
        """Create or update the wiki page with activity report information"""
        if not self._ensure_token_fresh("csrf"):
            logger.error("Failed to refresh token before updating activity report")
            return False
        
        # Create report content for today's actions
        report_content = self._generate_report_content()
        
        if not report_content:
            logger.info("No actions to report today")
            return True
        
        # Get current page content
        params = {
            "action": "query",
            "titles": "Activity/Reports",
            "prop": "revisions",
            "rvprop": "content",
            "rvslots": "main",
            "format": "json"
        }
        
        try:
            response = self.session.get(url=self.API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            page_content = ""
            for page_id in data.get("query", {}).get("pages", {}):
                if "revisions" in data["query"]["pages"][page_id]:
                    page_content = data["query"]["pages"][page_id]["revisions"][0]["slots"]["main"]["*"]
                    break
            
            # If page doesn't exist, create it with header
            if not page_content:
                page_content = "= Activity Reports =\nThis page contains automatically generated activity reports from the activity monitoring bot. Reports are generated when users are warned about inactivity or have their rights removed due to inactivity. Reports older than 20 days are automatically removed.\n\n"
            
            # Clean up old reports if needed
            updated_content = self._clean_old_reports(page_content)
            
            # Add today's report at the top
            updated_content = updated_content.split("\n", 2)[0] + "\n" + updated_content.split("\n", 2)[1] + "\n" + report_content + updated_content.split("\n", 2)[2] if len(updated_content.split("\n", 2)) > 2 else updated_content + report_content
            
            # Save the updated page
            params = {
                "action": "edit",
                "title": "Activity/Reports",
                "text": updated_content,
                "summary": f"Updated activity report for {self.today}",
                "token": self.tokens["csrf"],
                "format": "json"
            }
            
            response = self.session.post(url=self.API_URL, data=params)
            response.raise_for_status()
            data = response.json()
            
            if "error" not in data:
                logger.info("Successfully updated Activity/Reports page")
                return True
            else:
                logger.error(f"API error updating Activity/Reports: {data['error']}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Request error updating Activity/Reports: {e}")
            return False
        except Exception as e:
            logger.error(f"Error updating Activity/Reports: {e}")
            return False
    
    def _generate_report_content(self) -> str:
        """Generate the content for today's activity report"""
        if not self.actions_taken["warned"] and not self.actions_taken["removed"] and not self.actions_taken["flagged"]:
            return ""
        
        content = f"== Activity Report: {self.today} ==\n"
        
        # Add warned users section if any
        if self.actions_taken["warned"]:
            content += "=== Users Warned ===\n"
            content += "{| class=\"wikitable sortable\"\n"
            content += "! User !! Days Inactive !! Groups !! Last Activity Date !! Action Taken\n"
            
            for user_data in self.actions_taken["warned"]:
                content += "|-\n"
                content += f"| [[User:{user_data['user']}|{user_data['user']}]] ([[User talk:{user_data['user']}|talk]]) "
                content += f"|| {user_data['days_inactive']} "
                content += f"|| {', '.join(user_data['groups'])} "
                content += f"|| {user_data['last_activity']} "
                content += "|| '''Warning Sent'''\n"
            
            content += "|}\n\n"
        
        # Add users with rights removed section if any
        if self.actions_taken["removed"]:
            content += "=== Users with Rights Removed ===\n"
            content += "{| class=\"wikitable sortable\"\n"
            content += "! User !! Days Inactive !! Former Groups !! Rights Removed !! Last Activity Date !! Action Taken\n"
            
            for user_data in self.actions_taken["removed"]:
                content += "|-\n"
                content += f"| [[User:{user_data['user']}|{user_data['user']}]] ([[User talk:{user_data['user']}|talk]]) "
                content += f"|| {user_data['days_inactive']} "
                content += f"|| {', '.join(user_data['groups'])} "
                content += f"|| {', '.join(user_data['removed_rights'])} "
                content += f"|| {user_data['last_activity']} "
                content += "|| '''Rights Removed'''\n"
            
            content += "|}\n\n"
        
        # Add users flagged for review if any
        if self.actions_taken["flagged"]:
            content += "=== Users Flagged for Review ===\n"
            content += "{| class=\"wikitable sortable\"\n"
            content += "! User !! Days Inactive !! Groups !! Last Activity Date !! Notes\n"
            
            for user_data in self.actions_taken["flagged"]:
                content += "|-\n"
                content += f"| [[User:{user_data['user']}|{user_data['user']}]] ([[User talk:{user_data['user']}|talk]]) "
                content += f"|| {user_data['days_inactive']} "
                content += f"|| {', '.join(user_data['groups'])} "
                content += f"|| {user_data['last_activity']} "
                content += f"|| {user_data.get('notes', '')}\n"
            
            content += "|}\n\n"
        
        # Add summary statistics
        content += "=== Summary Statistics ===\n"
        content += "{| class=\"wikitable\"\n"
        content += "! Metric !! Count\n"
        content += "|-\n"
        content += f"| Users warned || {len(self.actions_taken['warned'])}\n"
        content += "|-\n"
        content += f"| Users with rights removed || {len(self.actions_taken['removed'])}\n"
        
        if self.actions_taken["flagged"]:
            content += "|-\n"
            content += f"| Users flagged for review || {len(self.actions_taken['flagged'])}\n"
        
        total_actions = len(self.actions_taken["warned"]) + len(self.actions_taken["removed"]) + len(self.actions_taken["flagged"])
        content += "|-\n"
        content += f"| Total actions taken || {total_actions}\n"
        content += "|}\n\n"
        
        return content
    
    def _clean_old_reports(self, page_content: str) -> str:
        """Remove reports older than REPORT_RETENTION days from the page content"""
        today_dt = datetime.datetime.strptime(self.today, "%Y-%m-%d")
        
        # Process the page content
        lines = page_content.split("\n")
        result_lines = []
        
        # Track if we're in an old report section
        in_old_report = False
        skip_section = False
        
        for line in lines:
            # Check for report headers
            if line.startswith("== Activity Report: "):
                # Extract date from header
                try:
                    report_date_str = line.replace("== Activity Report: ", "").replace(" ==", "")
                    report_date = datetime.datetime.strptime(report_date_str, "%Y-%m-%d")
                    
                    # Check if report is older than retention period
                    days_old = (today_dt - report_date).days
                    if days_old > self.REPORT_RETENTION:
                        skip_section = True
                        in_old_report = True
                        logger.info(f"Removing old report from {report_date_str} ({days_old} days old)")
                        continue
                    else:
                        skip_section = False
                except Exception as e:
                    logger.error(f"Error parsing report date: {e}")
                    skip_section = False
            
            # Check if we're entering a new section after an old report
            elif in_old_report and line.startswith("== "):
                in_old_report = False
                skip_section = False
            
            # Add line if not in a section to skip
            if not skip_section:
                result_lines.append(line)
        
        return "\n".join(result_lines)
    
    def save_state(self) -> None:
        """Save the bot's state to JSON files"""
        self._save_json("warned_users.json", self.warned_users)
        self._save_json("reported_users.json", self.reported_users)
    
    def run(self) -> None:
        """Main execution method"""
        logger.info("Starting ActivityBot execution")
        
        # Login
        if not self.login():
            logger.error("Failed to login, aborting execution")
            return
        
        # Get users by group
        self.get_users_by_group()
        
        # Process each user in monitored groups
        for group, users in self.users_by_group.items():
            for username in users:
                try:
                    # Get all groups this user belongs to
                    user_groups = []
                    for g, users_in_group in self.users_by_group.items():
                        if username in users_in_group:
                            user_groups.append(g)
                    
                    # Check activity for this user
                    self.check_user_activity(username, user_groups)
                except Exception as e:
                    logger.error(f"Error processing user {username}: {e}")
        
        # Update activity report
        self.update_activity_report()
        
        # Save state
        self.save_state()
        
        logger.info("ActivityBot execution completed")
        
        # Print summary
        logger.info(f"Summary: Warned {len(self.actions_taken['warned'])} users, removed rights from {len(self.actions_taken['removed'])} users")

# Main execution
if __name__ == "__main__":
    try:
        bot = ActivityBot()
        bot.run()
    except Exception as e:
        logger.critical(f"Critical error in ActivityBot: {e}")
