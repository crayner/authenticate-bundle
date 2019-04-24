# Authenticate Bundle Project
## Highest Available Encoder

The Highest Available Encoder is defined with the following defaults when flex correctly loads the crayner_authentication.yaml file in the App config/packages directory.     Features include the ability to recognise the current user encoding and upgrade the encoded password to the best available.  The encode handles the following types of encoders, from highest to lowest:
* Argon2id
* Argon2i
* BCrypt
* SHA256
* MD5
* Plain

___NB___ Symfony is moving away from native support for Argon2* support with Symfony 4.3+.  This bundle will use the LibSodium SodiumPasswordEncoder of Symfony 4.3+.  The SodiumPasswordEncoder in Symfony ignores the Argon2* options.  This bundle will default to the libsodium 

```yaml
crayner_authenticate:
    highest_available_encoder:
        # Sodium / Native Options
        mem_limit: 67108864
        ops_limit: 2
        sodium: true
        # BCrypt Options
        cost: 12
        # SHA256 / MD5 Options
        iterations_sha256: 1000
        iterations_md5: 1
        encode_as_base64: false
        password_salt_mask: '{password}{{salt}}'
        store_salt_separately: false
        # Plaintext Options
        ignore_password_case: false
        # Global Options
        maximum_available: 'argon2'
        minimum_available: 'md5'
        always_upgrade: true
```
#### Argon2i and Argon2id
* mem_limit
* ops_limit
* sodium Use Lib Sodium if true, or default to PHP Argon2* native support when false. 

Details for Argon2 can be found at <a href="https://www.php.net/manual/en/password.constants.php" target="_blank">https://www.php.net/manual/en/password.constants.php</a>

#### BCrypt
* cost

Details for Bcrypt can be found at <a href="https://www.php.net/manual/en/password.constants.php#constant.password-bcrypt" target="_blank">https://www.php.net/manual/en/password.constants.php</a>

#### SHA256
* iteration_sha256 is mapped to iterations in the SHA256Encoder
* encode_as_base64 returns the final SHA256 encoded passward in base64 format.
* password_salt_mask  This mask must contain both __{password}__ and __{salt}__ and will take the raw password with a salt provided by the user entity.  Examples of the mask include 
    * _'{salt}.{password}'_ 
    * or the default _'{password}{{salt}}'_
* store_salt_separately boolean value. If true, the storage of the salt is independent of the encoder, otherwise the salt and encoded password are merged and stored as one string using the _password_salt_mask_. Default: false   

If the password = 'your_password' and the salt = 'a_secret_salt' then the two examples shown would merge the password and salt as:
* _'a_secret_salt.your_password'_ 
* and _'your_password{a_secret_salt}'_

#### MD5
* iterations_md5 is mapped to iterations in the MD5Encoder

#### Plain Text
* ignore_password_case

#### Global Options
* maximum_available. Limit the highest available encoder
* minimum_available: Limit the lowest available encoder
* always_upgrade: If a higher encoder exists for the user password, then change the encoded password to the highest available when the user logs in.

[Return Home](../README.md)
