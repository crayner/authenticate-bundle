# Authenticate Bundle Project
### Bundle Settings

#### Internal Settings
```yaml
crayner_authenticate:
    user_class: Crayner\Authenticate\Entity\User
    mailer_available: false
    ...
```
* __user_class__ Allows you to over-write the user entity definition used by the package.  The user entity MUST implement ___Crayner\Authentication\Core\UserAuthenticationInterface___ for the bundle to allow your entity class.  The setting is required.

* __mailer_available__ Is the mailer component available to use for password reset management. This is turned off (false) by default.

[Return Home](../README.md)
