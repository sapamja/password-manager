## Unix Password Manager.

Project page: http://sapamja.github.io/password-manager/


### AES Encryption


## Usage:

```
usage: psm.py [-h] {database,insert,finder,passkey,update} ...

Personal Password Manager:

optional arguments:
  -h, --help            show this help message and exit

sub-commands:
  {database,insert,finder,passkey,update}
                        sub-command help
    database            database related commands.
    insert              insert related commands.
    finder              find details.
    passkey             passkey create or update
    update              update user details.

Life is easier when you remember less
```

### Database command

```
usage: psm.py database [-h] (--create | --drop | --dump | --import)
                       [--path PATH] [--file FILE]
                       [--format {decrypt,encrypt}]

optional arguments:
  -h, --help            show this help message and exit
  --create              creating the database, configure table.
  --drop                drop database or destroy database.
  --dump                dump the database
  --import              import database entries.
  --path PATH, --dp PATH
                        path to dump the database (default: //var/tmp/dump/)
  --file FILE           full path to the database dump file.
  --format {decrypt,encrypt}
                        dump format, (default: encrypt).
```

### Finder command

```
usage: psm.py finder [-h] [--username USERNAME] [--email EMAIL]
                     [--unique-name unique_name] [--detail DETAIL] [--url URL]
                     [--any ANY]

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME, -un USERNAME
                        match username.
  --email EMAIL, -e EMAIL
                        match email id.
  --unique-name unique_name, -uqn unique_name
                        match unique name.
  --detail DETAIL, -d DETAIL
                        match detail.
  --url URL             match url.
  --any ANY             match any string.
```

### Update command

```
usage: psm.py update [-h] --id ID [--username USERNAME] [--password PASSWORD]
                     [--email EMAIL] [--unique-name unique_name]
                     [--detail DETAIL] [--url URL]

optional arguments:
  -h, --help            show this help message and exit
  --id ID               id which is unique
  --username USERNAME, -un USERNAME
                        update username.
  --password PASSWORD, -p PASSWORD
                        update password.
  --email EMAIL, -e EMAIL
                        update email id.
  --unique-name unique_name, -uqn unique_name
                        update unique name.
  --detail DETAIL, -d DETAIL
                        update detail.
  --url URL             update url.
```

### Insert command

```
usage: psm.py insert [-h] --username USERNAME --password PASSWORD --email
                     EMAIL --unique-name unique_name [--detail DETAIL] --url
                     URL

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME, -un USERNAME
                        login username.
  --password PASSWORD, -p PASSWORD
                        login password.
  --email EMAIL         email id.
  --unique-name unique_name, -uqn unique_name
                        unique name for the entry.
  --detail DETAIL, -d DETAIL
                        detail about the entry.
  --url URL             login url.
```

### Update or create passkey command:

```
usage: psm.py passkey [-h] [--create] [--update]

optional arguments:
  -h, --help    show this help message and exit
  --create, -c  create new passkey for the first time
  --update, -u  update passkey, this will also update the user encryption
                details
```
