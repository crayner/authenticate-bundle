# Authenticate Bundle Project
### Password Validation

#### Settings
```yaml
crayner_authenticate:
    ...
    password_validation:
        min_length: 8
        max_length: 150
        case_difference: true
        special_characters: false
        use_number: true
        error_messages:
            min_length: 'Your password needs to be {count} characters long.'
            max_length: 'Your password needs to be less than {count} characters long.'
            case_difference: 'Your password must contain upper and lower case characters.'
            special_characters: 'Your password must contain a special character. !#@$%^&*)(\][><?:;'
            use_number: 'Your password must contain a number'
            translation_domain: validators
```
* __min_length__ The minimum length your system requires for a password.  Valid values are 1 to 150, and < max_length.  Default = 8.
* __max_length__ The maximum length your system requires for a password.  Valid values are null, 1 to 150, and > min_length.  Default = 150.
* __case_difference__ Boolean value to require difference case characters in your password. Default = true.
* __special_characters__ Boolean value to require special characters in your password.  Default = true. Valid characters: ___!#@$%^&*)(\\][:><?;+-___
* __use_number__ Boolean value to require a number in your password. Default = true.
* __error_messages__ All the error messages that are presented when the password validation fails.
    * __translation_domain__ Translation is not provided by this bundle, but the validator will use the translation domain defined on this setting. Default = 'validators'
    * The ___min_length___ and ___max_length___ messages attempt to inject the appropriate figure in the error message.  The __{count}__ is the target for this information, and your error message should implement __{count}__ if you wish to take advantage of this feature. 

[Return Home](../README.md)
