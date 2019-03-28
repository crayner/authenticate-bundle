# Authenticate Bundle Project
### Symfony 4+ Authenticate Bundle Project

___Version 0.0.01___

## Features
* [Highest Available Encoder](Documents/HighestAvailabelEncoder.md)
* [Manage Lock on Login Failures](Documents/ManageFailures.md)

## Installation
#### Applications that use Symfony Flex
Open a command console, enter your project directory and execute:

```$ composer require crayner/authentication-bundle```

#### Applications that don't use Symfony Flex
__Step 1: Download the Bundle__

Enter your project directory and execute the following command to download the latest stable version of this bundle:

```$ composer require crayner/authentication-bundle```

_This command requires you to have Composer installed globally, as explained in the installation chapter of the Composer documentation._

__Step 2: Enable the Bundle__

Then, enable the bundle by adding it to the list of registered bundles in the config/Bundles.php file of your project:
```
<?php
return [
    //...
    //
    Crayner\Authentication\CraynerDoctrineBundle::class => ['all' => true],
];
```
#### [Bundle Settings](Documents/BundleSettings.md)

[MIT License](LICENSE.md)