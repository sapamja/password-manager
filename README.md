## Unix Password Manager.

Storing Encrypted user details including password, username, email or url with passkey.

Project page: http://sapamja.github.io/password-manager/


### Install pycrypto

While installing if you got the following error:

```
cc -fno-strict-aliasing -fno-common -dynamic -arch x86_64 -arch i386 -pipe -fno-common -fno-strict-aliasing -fwrapv -mno-fused-madd -DENABLE_DTRACE -DMACOSX -Wall -Wstrict-prototypes -Wshorten-64-to-32 -fwrapv -Wall -Wstrict-prototypes -DENABLE_DTRACE -arch x86_64 -arch i386 -pipe -std=c99 -O3 -fomit-frame-pointer -Isrc/ -I/System/Library/Frameworks/Python.framework/Versions/2.7/include/python2.7 -c src/MD2.c -o build/temp.macosx-10.9-intel-2.7/src/MD2.o
clang: error: unknown argument: '-mno-fused-madd' [-Wunused-command-line-argument-hard-error-in-future]
clang: note: this will be a hard error (cannot be downgraded to a warning) in the future
error: command 'cc' failed with exit status 1

----------------------------------------
Cleaning up...
Command /usr/bin/python -c "import setuptools, tokenize;__file__='/private/tmp/pip_build_root/pycrypto/setup.py';exec(compile(getattr(tokenize, 'open', open)(__file__).read().replace('\r\n', '\n'), __file__, 'exec'))" install --record /tmp/pip-b1pxtG-record/install-record.txt --single-version-externally-managed --compile failed with error code 1 in /private/tmp/pip_build_root/pycrypto
Storing debug log for failure in /Users/sapam/Library/Logs/pip.login
```

Install XCODE and run as below:

sudo export ARCHFLAGS="-Wno-error=unused-command-line-argument-hard-error-in-future"


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
