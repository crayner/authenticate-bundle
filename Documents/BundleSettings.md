# Authenticate Bundle Project
### Bundle Settings

#### Internal Settings
```yaml
crayner_authenticate:
    user_class: Crayner\Authenticate\Entity\User
    mailer_available: false
    ...
```
* __user_class__ Allows you to over-write the user entity definition used by the package.  The user entity MUST implement ___Crayner\Authentication\Core\UserAuthenticationInterface___ for the bundle to allow your entity class.  Dafault = _Crayner\Authenticate\Entity\User_
* __mailer_available__ Is the mailer component available to use for password reset management. This is turned off (false) by default.
* __messages__ Error messages
    *  __current_password_wrong__  The error message to display when the new password is not valid. Default = _Your current password is not valid._
    *  __no_authenticated_user__ The error message to display when the username/email is not found. Default = _Username/Email could not be found.)
* __translation_domain__ Translation is not provided by this bundle, but the validator will use the translation domain defined on this setting. Default = _validators_

[Return Home](../README.md)
