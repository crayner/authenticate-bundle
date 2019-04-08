# Authenticate Bundle Project
### Rotate Passwords

#### Settings
```yaml
crayner_authenticate:
    ...
    rotate_password:
        keep_last_number: 0
        keep_for_days: 0
        change_every: 0
        message: 'The password has been used before.'
        translation_domain: validators
```

* __keep_last_number__ The number of previous passwords that the system stores to stop user repeat of passwords. If set to zero (0), then the rotate password functionality is turned off.  Default = 0, maximum = 30.
* __keep_for_days__ The number of days that previous passwords are kept. If set to zero (0), then the rotate password functionality is turned off. Default = 0 days, maximum = 1500 days.
* __change_every__ How often should the user be forced to change password. The value is in days. If set to zero (0), then the change password functionality is turned off.  Default = 0 days, maximum = 366 days.

[Return Home](../README.md)
