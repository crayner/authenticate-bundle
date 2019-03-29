# Authenticate Bundle Project
### Highest Available Encoder

The Highest Available Encoder is defined with the following defaults when flex correctly loads the crayner_authentication.yaml file in the App config/packages directory.     Features include the ability to recognise the current user encoding and upgrade the encoded password to the best available.  The encode handles the following types of encoders, from highest to lowest:
* Argon2i
* Bcrypt
* SHA256
* MD5

```yaml
crayner_authenticate:
    highest_available_encoder:
        # Argon2i Options
        memory_cost: 1024
        time_cost: 2
        threads: 4
        # BCrypt Options
        cost: 12
        # SHA256/MD5 Options
        iterations_sha256: 1000
        iterations_md5: 1
        encode_as_base64: false
        password_salt_mask: '{password}{{salt}}'
        # Global Options
        maximum_available: 'argon2i'
        minimum_available: 'md5'
        always_upgrade: true
```
#### Argon2i
* memory cost
* time_cost
* threads

Details for Argon2i can be found at <a href="https://www.php.net/manual/en/password.constants.php#constant.password-argon2i" target="_blank">https://www.php.net/manual/en/password.constants.php</a>

#### Bcrypt
* cost

Details for Bcrypt can be found at <a href="https://www.php.net/manual/en/password.constants.php#constant.password-bcrypt" target="_blank">https://www.php.net/manual/en/password.constants.php</a>

#### SHA256
* iteration_sha256 is mapped to iterations in the SHA256Encoder
* encode_as_base64 returns the final SHA256 encoded passward in base64 format.
* password_salt_mask  This mask must contain both __{password}__ and __{salt}__ and will take the raw password with a salt provided by the user entity.  Examples of the mask include 
    * _'{salt}.{password}'_ 
    * or the default _'{password}{{salt}}'_

If the password = 'your_password' and the salt = 'a_secret_salt' then the two examples shown would merge the password and salt as:
* _'a_secret_salt.your_password'_ 
* and _'your_password{a_secret_salt}'_

#### MD5
* iterations_md5 is mapped to iterations in the MD5Encoder

#### Global Options
* maximum_available. Limit the highest available encoder
* minimum_available: Limit the lowest available encoder
* always_upgrade: If a higher encoder exists for the user password, then change the encoded password to the highest available when the user logs in.

[Return Home](../README.md)
