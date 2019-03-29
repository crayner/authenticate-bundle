# Authenticate Bundle Project
### Manage Lock on Login Failures

The bundle provides the ability to limit the number of failed login attempts.  This works at the user level, when the username is correctly entered, but the password is incorrect.  If the username is incorrect, the device is recorded to help stop guesswork by hackers.  When the failed login count is exceeded, then the user or device is locked for further login attempts for the time set in the manage failure settings.

#### Setting
```yaml
crayner_authenticate:
    ...
    manage_failures:
        count: 3
        wait_time: 20 # Minutes
        session: true
        user: true
```
* __count__ The number of failures required to trigger the lock.  If zero (0) then the Login failures are not managed. Defaults to 3 attempts.
* __wait_time__ The period of time in minutes that the device or user is to be parred from login. Defaults to 20 minutes
* __session__ Turn on the device/session failure settings.  Defaults to on (true).
* __user__ Turn on the user failure setting.  Defaults to on (true).

[Return Home](../README.md)
