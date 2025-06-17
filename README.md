# Inactivity Bot
This bot monitors user activity on Test Wiki and automatically manages user rights based on inactivity thresholds. It tracks administrators and bureaucrats, removing rights from inactive users and notifying them of these changes.

## How It Works

* Login: The bot logs in using credentials stored in environment variables.
* Fetch Users: It retrieves a list of users in the monitored groups (sysop, bureaucrat), excluding users listed in EXCLUDED_USERS.
* Check Activity: For each user, the bot fetches the timestamp of their last edit or logged action.
* Determine Status and Take Action:
   Removal Threshold: Users inactive for more than 90 days have their rights automatically removed.
* Rights Handling:
   Removable Rights: The bot can directly remove sysop and bureaucrat rights.
* Communication:
   Notifies users when rights are removed via talk page messages
   Updates the Activity/Reports page with a comprehensive report



## Activity Reporting
The bot generates detailed activity reports including:
 * Users with rights removed due to inactivity
 * Last activity date and days of inactivity for each user
 * Former groups and specific rights removed
 * Summary of all actions taken

## Configuration

* Rights Removal Threshold: 90 days
* Report Retention: 20 days (how long reports are kept on the wiki)
* Monitored Groups: sysop, bureaucrat
* Bot-Removable Rights: sysop, bureaucrat
* EXCLUDED_USERS: "EPIC", "Drummingman", "Justarandomamerican", "X", "MacFan4000", "Abuse filter", "FuzzyBot", "MacFanBot", "Justarandomamerican (BOT)"

