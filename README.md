# Inactivity-Bot
This bot monitors user activity on Test Wiki and manages user rights based on inactivity thresholds. It specifically tracks administrators and bureaucrats, automatically removing rights from inactive users and notifying them of these changes.

How It Works
1) Login: The bot logs in using credentials stored in environment variables.
2) Fetch Users: It retrieves a list of users in the monitored groups (sysop, bureaucrat), excluding users listed in EXCLUDED_USERS.
3) Check Activity: For each user, the bot fetches the timestamp of their last edit or logged action.
4) Determine Status and Take Action:
     * Warning Threshold: Users inactive for more than 75 days receive a warning message on their talk page.
     * Removal Threshold: Users inactive for more than 90 days have their rights removed.
5) Rights Handling:
     * Removable Rights: The bot can directly remove sysop and bureaucrat rights.
6) Communication:
    * Posts warnings on user talk pages for those approaching inactivity threshold
    * Notifies users when rights are removed
    * Updates the Activity/Reports page with a comprehensive report

## Activity Reporting

The bot generates detailed activity reports including:
  * Users warned about approaching the inactivity threshold
  * Users with rights removed due to inactivity
  * Last activity date and days of inactivity for each user
  * Summary statistics of actions taken
## Configuration
  
   * Warning Threshold: 75 days
   * Rights Removal Threshold: 90 days
   * Warning Cooldown: 14 days (minimum time between warnings)
   * Report Retention: 20 days (how long reports are kept on the wiki)
   * Monitored Groups: sysop, bureaucrat
   * Bot-Removable Rights: sysop, bureaucrat
   * EXCLUDED_USERS : "EPIC", "Drummingman", "Justarandomamerican", "MacFan4000", "Abuse filter", "FuzzyBot", "MacFanBot"
