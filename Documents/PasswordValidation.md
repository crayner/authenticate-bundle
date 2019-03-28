# Authenticate Bundle Project
### Password Validation

#### Settings
```
crayner_authenticate:
    ...
    password_validation:
        min_length: 8
        max_length: ~
        case_difference: true
        special_characters: true

```
* __min_length__ The minimum length your system requires for a password.  Valid values are 1 to 150, and < max_length.  Default = 8.
* __max_length__ The maximum length your system requires for a password.  Valid values are null, 1 to 150, and > min_length.  Default = 150.
* __case_difference__ Boolean value to require difference case characters in your password. Default = true.
* __special_characters__ Boolean value to require special characters in your password.  Default = true.