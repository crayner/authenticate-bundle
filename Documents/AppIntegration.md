# Authenticate Bundle Project
### Application Integration

To use this bundle within your App, then you will need to modify settings in your Symfony App.  This bundle requires a number of dependent bundles.

#### Security
If your app is a new install with this bundle installed then the ___config/packages/security.yaml___ file may look like:
```yaml
security:
    # https://symfony.com/doc/current/security.html#where-do-users-come-from-user-providers
    providers:
        in_memory: { memory: ~ }
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            anonymous: true

            # activate different ways to authenticate

            # http_basic: true
            # https://symfony.com/doc/current/security.html#a-configuring-how-your-users-will-authenticate

            # form_login: true
            # https://symfony.com/doc/current/security/form_login_setup.html

    # Easy way to control access for large sections of your site
    # Note: Only the *first* access control that matches will be used
    access_control:
        # - { path: ^/admin, roles: ROLE_ADMIN }
        # - { path: ^/profile, roles: ROLE_USER }
``` 
An example for default installation using __crayner/authenticate-bundle__ is:
```yaml
security:
    # https://symfony.com/doc/current/security.html#where-do-users-come-from-user-providers
    encoders:
        Crayner\Authenticate\Core\SecurityUserProvider:
            id: Crayner\Authenticate\Core\HighestAvailableEncoder
    providers:
        security_user_provider:
            id: Crayner\Authenticate\Core\SecurityUserProvider
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            anonymous: ~
            form_login:
                login_path:             login
                check_path:             login
                csrf_parameter:         'authenticate[_token]'
                csrf_token_id:          authenticate
                default_target_path:    home
                use_referer:            true
                csrf_token_generator:   security.csrf.token_manager
                username_parameter:     'authenticate[_username]'
                password_parameter:     'authenticate[_password]'
                failure_path_parameter: login
                provider:               security_user_provider
            provider:                   security_user_provider
            logout:
                path:                   logout
                target:                 home
            remember_me:                false
            #                secret:               '%env(APP_SECRET)%'
            #                name:                 '%session_name%_remember_me'
            #                lifetime:             43200 # 12 hours in seconds
            #                path:                 /
            #                secure:               false
            #                remember_me_parameter: 'login[_remember_me]'
            switch_user:                true
            guard:
                authenticators:
                    - Crayner\Authenticate\Core\LoginFormAuthenticator
                entry_point: Crayner\Authenticate\Core\LoginFormAuthenticator
            context: main

    role_hierarchy: '%security.hierarchy.roles%'

    # Easy way to control access for large sections of your site
    # Note: Only the *first* access control that matches will be used
    access_control:
    # - { path: ^/admin, roles: ROLE_ADMIN }
    # - { path: ^/profile, roles: ROLE_USER }
``` 
This sets all of the security settings necessary for the __crayner/authenticate-bundle__.  Full details for the security settings can be found in the <a href="https://symfony.com/doc/current/security.html" target="_blank">Symfony Security documentation.</a>

#### Doctrine
You need to set the database url in the ___.env___ as defined the <a href="https://symfony.com/doc/current/doctrine.html" target="_blank">Symfony Doctrine documentation.</a>

If you use multiple database settings, you can define the connection to use for tables in this bundle within the ___mappings___ settings for Doctrine ORM. Just add the bundle name as one of the mappings in the entity manager definition.  Further details at: <a href="https://symfony.com/doc/current/doctrine/multiple_entity_managers.html" target="_blank" >How to Work with multiple Entity Managers and Connections</a> Within a single database definition, no changes are required in the ___config/packages/doctrine.yaml___

```yaml
doctrine:
    dbal:
        ...
    orm:
        ...
        default:
            mappings:
                CraynerAuthenticateBundle: ~
                App:
                    is_bundle: false
                    type: annotation
                    dir: '%kernel.project_dir%/src/Entity'
                    prefix: 'App\Entity'
                    alias: App
```

#### Mailer
You need to set the mailer url in the .env as defined the <a href="https://symfony.com/doc/current/email.html" target="_blank">Symfony Mailer documentation.</a>

[Return Home](../README.md)
