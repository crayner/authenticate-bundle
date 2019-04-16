# Authenticate Bundle Project
### Symfony 4+ Authenticate Bundle Project

___Version 1.1.1___

## Features
* [Highest Available Encoder](Documents/HighestAvailabelEncoder.md)
* [Manage Lock on Login Failures](Documents/ManageFailures.md)
* [Password Validation](Documents/PasswordValidation.md)
* [Rotate Passwords](Documents/RotatePasswords.md)

I began this as a simple set of stuff that I was using in projects without the weight of FOSUserBUndle.  It now provides a series of Encoders that allow NON Sodium use of Argon2* in Symfony 4.3+.  In Version 4.3 Symfony has taken the route of not using the PHP Native encoders.  I personally don't have an opinion, not understanding why this decision was taken, but the HighestPasswordEncoder within this package supplies the options to enable PHP Native encoders for Argon2* if Sodium is not available.  Sodium should be available, as package requires _paragonie/sodium_compat_ as a fall back for _libsodium_  In any case, removal of _paragonie/sodium_compat_ and _libsodium_ will still allow Argon2* integration for PHP 7.2+.  The Argon2*PasswordEncoders supplied in this package only supply PHP Native Argon integration, and can be used in your project as any normal encoder.

## Installation
#### Applications that use Symfony Flex
Open a command console, enter your project directory and execute:

```console
$ composer require crayner/authenticate-bundle
```

#### Applications that don't use Symfony Flex
* __Step 1: Download the Bundle__

Enter your project directory and execute the following command to download the latest stable version of this bundle:

```console
$ composer require crayner/authenticate-bundle
```

_This command requires you to have Composer installed globally, as explained in the installation chapter of the Composer documentation._

* __Step 2: Enable the Bundle__

Then, enable the bundle by adding it to the list of registered bundles in the config/Bundles.php file of your project:
```php
<?php
return [
    //...
    //
    Crayner\Authenticate\CraynerAuthenticateBundle::class => ['all' => true],
];
```

#### Usage
* Highest Available Encoder Class directly in the Security settings of your App.

* __[Bundle Settings](Documents/BundleSettings.md)__
* __[Application Integration](Documents/AppIntegration.md)__
* __[Override Bundle](Documents/OverrideBundle.md)__

[MIT License](LICENSE.md)


Craig Rayner