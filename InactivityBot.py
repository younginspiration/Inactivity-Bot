import requests
import os
import time
import logging
import datetime
import pytz
from typing import Dict, List, Tuple, Set, Optional, Any

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
    RIGHTS_REMOVAL_THRESHOLD = 90  # days
    REPORT_RETENTION = 20  # days
    
    # Rate limiting
    API_DELAY = 0.5  # seconds between API requests
    
    # User groups to monitor and remove rights from
    MONITORED_GROUPS = ["sysop", "bureaucrat"]
    
    # Users to exclude from all checks
    EXCLUDED_USERS = {
        "EPIC", "Drummingman", "Justarandomamerican", "X",
        "MacFan4000","TheAstorPastor", "Abuse filter", "DodoBot", "FuzzyBot", "MacFanBot", "Justarandomamerican (BOT)"
    }
    
    # Token management
    TOKEN_REFRESH_INTERVAL = 15 * 60  # 15 minutes in seconds
    
    # Message template
    RIGHTS_REMOVAL_MESSAGE = (
        "Hello! This is an automated message to inform you that due to {days_inactive} days of inactivity, "
        "the following user rights have been removed from your account: {rights_removed}. "
        "According to the [[TW:IP|inactivity policy]], user rights are removed after 3 months of inactivity. "
        "If you wish to regain these rights, please request it at "
        "[[Test_Wiki:Request_for_permissions|Request for permissions]]. Thank you for your understanding! ~~~~"
    )

    def __init__(self):
        self.session = requests.Session()
        self.tokens = {}
        self.token_timestamp = {}
        self.users_by_group = {}
        self.actions_taken = {"removed": []}
        self.timezone = pytz.UTC
        self.today = datetime.datetime.now(self.timezone).strftime("%Y-%m-%d")
        
        if not self.BOT_USERNAME or not self.BOT_PASSWORD:
            logger.error("Bot credentials not found in environment variables")
            raise ValueError("Bot credentials not found in environment variables")

    def _api_request(self, method: str, params: Dict, data: Optional[Dict] = None) -> Optional[Dict]:
        """Make an API request with rate limiting and error handling."""
        time.sleep(self.API_DELAY)
        
        try:
            if method.upper() == "GET":
                response = self.session.get(url=self.API_URL, params=params)
            else:
                response = self.session.post(url=self.API_URL, data=data or params)
            
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"API request error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in API request: {e}")
            return None

    def _get_token(self, token_type: str) -> Optional[str]:
        """Get a token, either from cache or by fetching a new one."""
        token_configs = {
            "login": {"type": "login", "key": "logintoken"},
            "csrf": {"type": None, "key": "csrftoken"},
            "userrights": {"type": "userrights", "key": "userrightstoken"}
        }
        
        if token_type not in token_configs:
            logger.error(f"Unknown token type: {token_type}")
            return None
            
        config = token_configs[token_type]
        params = {
            "action": "query",
            "meta": "tokens",
            "format": "json"
        }
        
        if config["type"]:
            params["type"] = config["type"]
            
        data = self._api_request("GET", params)
        if not data:
            return None
            
        token = data.get("query", {}).get("tokens", {}).get(config["key"])
        if token:
            self.tokens[token_type] = token
            self.token_timestamp[token_type] = time.time()
            logger.info(f"Obtained {token_type} token: {token[:5]}...{token[-3:]}")
            
        return token

    def _ensure_token_fresh(self, token_type: str) -> bool:
        """Ensure a token is fresh, refreshing it if necessary."""
        if (token_type not in self.tokens or 
            token_type not in self.token_timestamp or 
            time.time() - self.token_timestamp.get(token_type, 0) > self.TOKEN_REFRESH_INTERVAL):
            logger.info(f"{token_type} token expired or missing - refreshing")
            return self._get_token(token_type) is not None
        return True

    def login(self) -> bool:
        """Log in to the MediaWiki API."""
        login_token = self._get_token("login")
        if not login_token:
            logger.error("Failed to get login token")
            return False
            
        login_params = {
            "action": "login",
            "lgname": self.BOT_USERNAME,
            "lgpassword": self.BOT_PASSWORD,
            "lgtoken": login_token,
            "format": "json"
        }
        
        data = self._api_request("POST", {}, login_params)
        if not data:
            return False
            
        if data.get("login", {}).get("result") == "Success":
            logger.info(f"Successfully logged in as {data['login']['lgusername']}")
            return self._get_token("csrf") is not None and self._get_token("userrights") is not None
        else:
            logger.error(f"Login failed: {data}")
            return False

    def _get_users_in_group(self, group: str) -> List[str]:
        """Get all users in a specific group."""
        params = {
            "action": "query",
            "list": "allusers",
            "augroup": group,
            "aulimit": "500",
            "format": "json"
        }
        
        data = self._api_request("GET", params)
        if not data:
            return []
            
        users = [user["name"] for user in data.get("query", {}).get("allusers", [])]
        users = [user for user in users if user not in self.EXCLUDED_USERS]
        
        logger.info(f"Found {len(users)} users in group '{group}' (after exclusions)")
        return users

    def _get_all_monitored_users(self) -> None:
        """Get all users in monitored groups."""
        for group in self.MONITORED_GROUPS:
            self.users_by_group[group] = self._get_users_in_group(group)

    def _parse_timestamp(self, timestamp: str) -> datetime.datetime:
        """Parse MediaWiki API timestamp format to datetime object with UTC timezone."""
        dt = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        return pytz.utc.localize(dt)

    def _get_user_activity_data(self, username: str) -> Tuple[str, int]:
        """Get the date of the user's last activity and days since then."""
        # Get latest contribution
        contrib_params = {
            "action": "query",
            "list": "usercontribs",
            "ucuser": username,
            "uclimit": 1,
            "ucprop": "timestamp",
            "format": "json"
        }
        
        contrib_data = self._api_request("GET", contrib_params)
        contribs = contrib_data.get("query", {}).get("usercontribs", []) if contrib_data else []
        
        # Get latest log action
        log_params = {
            "action": "query",
            "list": "logevents",
            "leprop": "timestamp",
            "leuser": username,
            "lelimit": 1,
            "format": "json"
        }
        
        log_data = self._api_request("GET", log_params)
        logs = log_data.get("query", {}).get("logevents", []) if log_data else []
        
        # Determine most recent activity
        timestamps = []
        if contribs:
            timestamps.append(self._parse_timestamp(contribs[0]["timestamp"]))
        if logs:
            timestamps.append(self._parse_timestamp(logs[0]["timestamp"]))
        
        if not timestamps:
            return "No activity found", 999
        
        last_activity = max(timestamps)
        last_timestamp = last_activity.strftime("%Y-%m-%d %H:%M:%S UTC")
        days_inactive = (datetime.datetime.now(pytz.UTC) - last_activity).days
        
        return last_timestamp, days_inactive

    def _is_recently_active(self, username: str) -> bool:
        """Check if the user has been active very recently (safety check)."""
        _, days_inactive = self._get_user_activity_data(username)
        return days_inactive <= 1

    def _send_message_to_user(self, username: str, message: str) -> bool:
        """Send a message to a user's talk page."""
        if not self._ensure_token_fresh("csrf"):
            return False
            
        params = {
            "action": "edit",
            "title": f"User talk:{username}",
            "section": "new",
            "summary": "Automated inactivity notification",
            "text": message,
            "token": self.tokens["csrf"],
            "format": "json"
        }
        
        data = self._api_request("POST", {}, params)
        if data and "error" not in data:
            logger.info(f"Successfully sent message to User talk:{username}")
            return True
        else:
            logger.error(f"Failed to send message to {username}")
            return False

    def _get_user_current_rights(self, username: str) -> List[str]:
        """Get current user rights."""
        params = {
            "action": "query",
            "list": "users",
            "ususers": username,
            "usprop": "groups",
            "format": "json"
        }
        
        data = self._api_request("GET", params)
        if not data:
            return []
            
        users_data = data.get("query", {}).get("users", [])
        if not users_data:
            return []
            
        return users_data[0].get("groups", [])

    def _remove_rights_from_user(self, username: str, rights_to_remove: List[str]) -> bool:
        """Remove specified rights from a user."""
        if self._is_recently_active(username):
            logger.info(f"User {username} has been active recently. Not removing rights.")
            return False
            
        if not self._ensure_token_fresh("userrights"):
            return False
            
        current_rights = self._get_user_current_rights(username)
        actual_rights_to_remove = [right for right in rights_to_remove if right in current_rights]
        
        if not actual_rights_to_remove:
            logger.info(f"No removable rights found for {username}")
            return False
            
        params = {
            "action": "userrights",
            "user": username,
            "add": "",
            "expiry": "",
            "reason": "Automatically removed due to inactivity",
            "remove": "|".join(actual_rights_to_remove),
            "token": self.tokens["userrights"],
            "format": "json"
        }
        
        data = self._api_request("POST", {}, params)
        if data and "error" not in data:
            logger.info(f"Successfully removed rights {actual_rights_to_remove} from {username}")
            return True
        else:
            logger.error(f"Failed to remove rights from {username}")
            return False

    def _process_inactive_user(self, username: str, user_groups: List[str], days_inactive: int, last_activity_date: str) -> None:
        """Process a user who exceeds the inactivity threshold."""
        logger.info(f"{username} has been inactive for {days_inactive} days, exceeding rights removal threshold")

        rights_to_remove = [right for right in user_groups if right in self.MONITORED_GROUPS]

        if rights_to_remove:
            message = self.RIGHTS_REMOVAL_MESSAGE.format(
                days_inactive=days_inactive,
                rights_removed=", ".join(rights_to_remove)
            )
            
            if self._remove_rights_from_user(username, rights_to_remove):
                if self._send_message_to_user(username, message):
                    self.actions_taken["removed"].append({
                        "user": username,
                        "days_inactive": days_inactive,
                        "removed_rights": rights_to_remove,
                        "groups": user_groups,
                        "last_activity": last_activity_date
                    })

    def _check_single_user(self, username: str, user_groups: List[str]) -> None:
        """Check a single user's activity and take appropriate actions."""
        logger.info(f"Checking activity for {username} (groups: {', '.join(user_groups)})")

        if username in self.EXCLUDED_USERS or username == self.BOT_USERNAME.split('@')[0]:
            logger.info(f"Skipping excluded user: {username}")
            return

        last_activity_date, days_inactive = self._get_user_activity_data(username)

        if days_inactive >= self.RIGHTS_REMOVAL_THRESHOLD:
            self._process_inactive_user(username, user_groups, days_inactive, last_activity_date)
        else:
            logger.info(f"{username} has been inactive for {days_inactive} days (threshold: {self.RIGHTS_REMOVAL_THRESHOLD})")

    def _process_all_users(self) -> None:
        """Process all users in monitored groups."""
        processed_users = set()
        for group, users in self.users_by_group.items():
            for username in users:
                if username in processed_users:
                    continue
                processed_users.add(username)
                
                try:
                    user_groups = [g for g, users_in_group in self.users_by_group.items() 
                                 if username in users_in_group]
                    
                    self._check_single_user(username, user_groups)
                except Exception as e:
                    logger.error(f"Error processing user {username}: {e}")

    def _get_current_report_content(self) -> str:
        """Get current activity report page content."""
        params = {
            "action": "query",
            "titles": "Test Wiki:Activity reports",
            "prop": "revisions",
            "rvprop": "content",
            "rvslots": "main",
            "format": "json"
        }
        
        data = self._api_request("GET", params)
        if not data:
            return ""
            
        for page_id in data.get("query", {}).get("pages", {}):
            if "revisions" in data["query"]["pages"][page_id]:
                return data["query"]["pages"][page_id]["revisions"][0]["slots"]["main"]["*"]
        
        return ""

    def _generate_todays_report(self) -> str:
        """Generate the content for today's activity report."""
        if not self.actions_taken["removed"]:
            return ""
        
        content = f"== Activity Report: {self.today} ==\n"
        content += "=== Users with Rights Removed ===\n"
        content += ("{| class=\"wikitable sortable\"\n"
                   "! User !! Days Inactive !! Former Groups !! Rights Removed !! Last Activity Date !! Action Taken\n")
        
        for user_data in self.actions_taken["removed"]:
            content += ("|-\n"
                       f"| [[User:{user_data['user']}|{user_data['user']}]] "
                       f"([[User talk:{user_data['user']}|talk]]) "
                       f"|| {user_data['days_inactive']} "
                       f"|| {', '.join(user_data['groups'])} "
                       f"|| {', '.join(user_data['removed_rights'])} "
                       f"|| {user_data['last_activity']} "
                       f"|| '''Rights Removed'''\n")
        
        content += "|}\n\n"
        return content

    def _clean_old_reports_from_content(self, page_content: str) -> str:
        """Remove reports older than REPORT_RETENTION days from the page content."""
        today_dt = datetime.datetime.now(pytz.UTC)
        lines = page_content.split("\n")
        result_lines = []
        skip_section = False
        
        for line in lines:
            if line.startswith("== Activity Report: "):
                try:
                    report_date_str = line.replace("== Activity Report: ", "").replace(" ==", "")
                    report_date = datetime.datetime.strptime(report_date_str, "%Y-%m-%d")
                    report_date = pytz.UTC.localize(report_date)
                    
                    days_old = (today_dt - report_date).days
                    if days_old > self.REPORT_RETENTION:
                        skip_section = True
                        logger.info(f"Removing old report from {report_date_str} ({days_old} days old)")
                        continue
                    else:
                        skip_section = False
                except Exception as e:
                    logger.error(f"Error parsing report date from line '{line}': {e}")
                    skip_section = False
            elif line.startswith("== ") and skip_section:
                skip_section = False
            
            if not skip_section:
                result_lines.append(line)
        
        return "\n".join(result_lines)

    def _save_activity_report(self) -> bool:
        """Create or update the wiki page with activity report information."""
        if not self.actions_taken["removed"]:
            logger.info("No actions to report today")
            return True
            
        if not self._ensure_token_fresh("csrf"):
            return False
        
        page_content = self._get_current_report_content()
        
        if not page_content:
            page_content = ("= Activity Reports =\n"
                          "This page contains automatically generated activity reports from the activity monitoring bot. "
                          "Reports are generated when users have their rights removed due to inactivity. "
                          f"Reports older than {self.REPORT_RETENTION} days are automatically removed.\n\n")
        
        updated_content = self._clean_old_reports_from_content(page_content)
        report_content = self._generate_todays_report()
        
        header_parts = updated_content.split("= Activity Reports =", 1)
        if len(header_parts) > 1:
            header_end = header_parts[1].split("\n\n", 1)[0]
            remaining_content = header_parts[1].split("\n\n", 1)[1] if "\n\n" in header_parts[1] else ""
            updated_content = f"= Activity Reports ={header_end}\n\n{report_content}{remaining_content}"
        else:
            updated_content = f"{updated_content}\n\n{report_content}"
        
        edit_params = {
            "action": "edit",
            "title": "Test Wiki:Activity reports",
            "text": updated_content,
            "summary": f"Updated activity report for {self.today}",
            "token": self.tokens["csrf"],
            "format": "json"
        }
        
        data = self._api_request("POST", {}, edit_params)
        if data and "error" not in data:
            logger.info("Successfully updated Test Wiki:Activity reports page")
            return True
        else:
            logger.error("Failed to update Test Wiki:Activity reports page")
            return False

    def run(self) -> None:
        """Main execution method."""
        logger.info("Starting ActivityBot execution")
        
        if not self.login():
            logger.error("Failed to login, aborting execution")
            return
        
        self._get_all_monitored_users()
        self._process_all_users()
        self._save_activity_report()
        
        logger.info(f"ActivityBot execution completed. Actions taken: {len(self.actions_taken['removed'])} rights removals")


if __name__ == "__main__":
    try:
        bot = ActivityBot()
        bot.run()
    except Exception as e:
        logger.critical(f"Critical error in ActivityBot: {e}")
        raise
