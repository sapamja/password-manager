#!/usr/bin/python

"""
Created By: sapamja
Date: Sun Mar 30 13:04:11 IST 2014
Email: sapamja@gmail.com
"""

# Add password verify with the old one
# Add update password
# update details

import os
import re
import sys
import json
import time
import base64
import hashlib
import binascii
import argparse
import sqlite3
import operator

from Crypto.Cipher import AES


def pp(json_docs):
    """preety print for json docs"""
    print json.dumps(json_docs, indent=4)


def get_md5(key):
    """return md5 hex for key"""
    md5 = hashlib.md5()
    md5.update(key)
    return md5.hexdigest()


def print_table(lod, args):
    """
    Input: list of dictionary or list of list.
    Args: list of headers name which is the key in dictionary
    if preetyTable is not install then the output will be json format.
    """
    try:
        from prettytable import PrettyTable
        pt = PrettyTable(border=True, horizontal_char='-',
                         field_names=[x.title() for x in args])

        [pt.align.__setitem__(x.title(), "l") for x in args]

        if isinstance(lod[0], dict):
            [pt.add_row([x[item] for item in args]) for x in lod]
        else:
            [pt.add_row([x[i] for i in range(len(lod[0]))]) for x in lod]
        return pt
    except Exception:
        pp(lod)


def yes_no(arg):
    """get input yes or no"""
    print '%s [y|n]:' % arg,
    if str(raw_input()).lower() == 'y':
        return True
    print 'Oops exiting!'
    return False


def get_input(msg=None, password=False):
    """get user raw_input"""
    if password:
        import getpass
        input_str = str(getpass.getpass(prompt='%s' % msg))
    else:
        if msg:
            print '%s:' % msg,
        input_str = str(raw_input())
    if input_str:
        return input_str
    else:
        raise Exception("Exiting: no input")


class Setting(object):

    """All the basic settings about the database will define here."""
    # database name
    db_name = 'pass_db.db'

    # database path
    db_path = '/var/tmp'

    # dump database path
    dump_path = '/%s/dump/' % db_path

    # database table name
    table_name = {'password_manager': 'password_manager',
                  'passkey_manager': 'passkey'}

    # rquired column and type for the database table
    column_table = {
        'password_manager': {
            'unique_name': 'text',
            'username': 'text',
            'password': 'text',
            'url': 'text',
            'email': 'text',
            'detail': 'text',
        },
        'passkey_manager': {
            'salt': 'text',
            'digest': 'text',
        }
    }

    # column name in order
    column_order = {
        'password_manager': ['unique_name', 'username', 'password',
                             'email', 'url', 'detail'],
        'passkey_manager': ['salt', 'digest']
    }


class Cipher(object):

    """Encryption and decryption of data"""

    def __init__(self, passkey):
        self.msg = None
        self.passkey = get_md5(passkey)
        self.encobj = AES.new(self.passkey, AES.MODE_ECB)
        self.decobj = self.encobj

    def get_password_digest(self, password, salt=None):
        if not salt:
            salt = base64.b64encode(os.urandom(32))
        digest = hashlib.sha256(salt + password).hexdigest()
        for x in range(0, 100001):
            digest = hashlib.sha256(digest).hexdigest()
        return salt, digest

    def verify_password(self, password, salt, digest):
        return self.get_password_digest(password, salt)[1] == digest

    @staticmethod
    def pad(msg):
        """AES CBC encryption required text should be multiple of 16bytes"""
        BS = 16
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        return pad(msg)

    @staticmethod
    def unpad(msg):
        """Removed the pad bytes, to regain the original text"""
        unpad = lambda s: s[0:-ord(s[-1])]
        return unpad(msg)

    def encrypt(self, msg):
        """Encrypt the original msg before storing into the database"""
        ciphertxt = self.encobj.encrypt(self.pad(str(msg)))
        return ciphertxt.encode('hex')

    def decrypt(self, ciphertxt):
        """Decrypt for human reading"""
        try:
            pad = self.decobj.decrypt(binascii.unhexlify(ciphertxt))
        except TypeError as error:
            raise TypeError(error)

        return self.unpad(pad)

class Database(Setting, Cipher):

    """Create database table, drop table"""

    def __init__(self, args):
        self.argument = args
        #super(Cipher, self).__init__(*args)

    def connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect('%s/%s' %
                                       (Setting.db_path, Setting.db_name))
            self.cursor = self.conn.cursor()
        except Exception as error:
            raise Exception(error)

    def execute(self, sql_cmd):
        """Execute sql query"""
        try:
            self.connect()
            result = self.cursor.execute(sql_cmd)
        except sqlite3.OperationalError as error:
            raise sqlite3.OperationalError(error)
        else:
            self.conn.commit()
        return result

    def _create(self, table_name, **kwargs):
        cmd = ', '.join(['%s %s' % (k, kwargs[k]) for k in
              Setting.column_order[table_name]])

        sql_cmd = ("CREATE TABLE {0}\
                   (ID INTEGER PRIMARY KEY AUTOINCREMENT,\
                   {1} )".format(table_name, cmd))
        self.execute(sql_cmd)
        print "Successfully created the database table: %s" % table_name

    def _create_table(self):
        """create table based on the config define in Setting class"""
        for tb, dic in Setting.column_table.items():
            self._create(tb, **dic)
        return True

    def _get_salt_digest(self):
        """return salt, digest from db"""
        sql_cmd = "SELECT * from passkey_manager ORDER BY ID DESC LIMIT 1"
        try:
            return self.execute(sql_cmd).fetchone()[1:]
        except:
            print 'Failed to get passkey from database'
            print 'Do, you create passkey!'
            sys.exit(1)

    @property
    def _is_password_correct(self):
        """verify the passkey type by the user with the one store in db"""
        salt, digest = self._get_salt_digest()
        if not self.verify_password(self.passkey, salt, digest):
            print 'Failed: passkey verification'
            sys.exit(1)

    def _drop(self, table_name):
        """drop datbase table"""
        return self.execute("DROP TABLE {0}".format(table_name))

    def _drop_table(self):
        """drop datbase table if passkey is verified"""
        self.passkey = get_input(msg='Password: ', password=True)
        self.verification = self._is_password_correct

        for table in Setting.table_name:
            self._drop(table)
            print "Successfully dropped the database table %s" % table
        return True

    def __call__(self):
        """Callable database class:"""
        if self.argument['drop']:
            if yes_no('Dropping the table'):
                self._drop_table()

        elif self.argument['create']:
            self._create_table()


class Finder(Database):

    """Find data"""

    def __init__(self, *args):
        super(Finder, self).__init__(*args)

    def is_exists(**kwargs):
        """check: username, password, url exists in kwargs"""
        if not kwargs.viewkeys() >= {'username', 'password', 'url'}:
            return True

    @staticmethod
    def _map_column(value):
        map_col_lod = list()
        # adding id
        _column = Setting.column_order['password_manager']
        _column.insert(0, 'id')

        for lol in value:
            map_col_lod.append(dict(zip(_column, lol)))
        return map_col_lod

    def _match_it(self):
        ret = list()
        for dic in self._result_lod:
            for x in self._match_dict.keys():
                if re.search(self._match_dict[x], str(dic[x]), re.IGNORECASE):
                    ret.append(dic)
                    break
        return ret

    def select_all(self, decrypt=True):
        sql_cmd = "SELECT * from {0}".format(
            Setting.table_name['password_manager'])
        result = self.execute(sql_cmd)
        decrypted = list()
        if decrypt:
            for c in result.fetchall():
                to_decrypt = c[1:]
                ls = [self.cipobj.decrypt(x) for x in to_decrypt]
                ls.insert(0, c[0])
                decrypted.append(ls)
        else:
            for c in result.fetchall():
                decrypted.append(c)

        return decrypted

    def __call__(self):
        # get passkey from user
        self.passkey = get_input(msg='Password: ', password=True)
        self.cipobj = Cipher(self.passkey)
        # verify passkey
        self.verification = self._is_password_correct

        result = self.select_all()
        self._result_lod = self._map_column(result)

        if not self.argument['any'] and not self.argument['all']:
            self._match_dict = dict([(x, self.argument[x])
                                     for x in Setting.column_order['password_manager']
                                     if x in self.argument.keys()
                                     and self.argument[x]])
            self._match_result = self._match_it()
        elif self.argument['any']:
            self._match_dict = dict([(x, self.argument['any'])
                                     for x in Setting.column_order['password_manager']
                                     ])
            self._match_result = self._match_it()
        else:
            self._match_result = self.select_all()

        print print_table(self._match_result, Setting.column_order['password_manager'])


class Insert(Finder):

    """Insert user data into the database"""

    def __init__(self, *args):
        super(Insert, self).__init__(*args)

    def insert_data(self, **kwargs):
        """Encrypt and insert data"""
        encrypted_dict = {key: self.cipobj.encrypt(kwargs[key])
                          for key in kwargs.keys()}
        sql_cmd = ("INSERT INTO {0} \
                  (unique_name, username, password, email, url, detail) \
                  VALUES ( '{unique_name}', '{username}', '{password}', \
                           '{email}', '{url}', '{detail}')".format(
            Setting.table_name['password_manager'],
            **encrypted_dict))

        result = self.execute(sql_cmd)
        kwargs['id'] = str(result.lastrowid)

        print 'Successfully inserted:'
        print print_table([kwargs], ["id", "unique_name",
                                     "username", "password",
                                     "email", "url", "detail"])

    def is_exist(self, **kwargs):
        required_check = ['username', 'email', 'url']
        result_all = self.select_all(decrypt=True)
        for lists in result_all:
            if all(kwargs[item] in lists for item in required_check):
                return True
        return False

    def __call__(self):

        self.passkey = get_input(msg='Password: ', password=True)
        self.cipobj = Cipher(self.passkey)
        self.decobj = self.cipobj
        # verify passkey
        self.verification = self._is_password_correct

        """Callable class"""

        kwargs = {x: self.argument[x]
                  for x in Setting.column_order['password_manager']}
        if not self.is_exist(**kwargs):
            return self.insert_data(**kwargs)
        else:
            print "Similar data exist, please check using finder."
            print "You can't insert same [username, email and url] "\
                  "which doesn't make sense."
            return True
        # from here is testing
        """
        from faker import Faker
        f = Faker()
        for i in range(100):
            kwargs = { 'unique_name': f.user_name(),
                       'username' : f.name(),
                       'password' : f.word(),
                       'detail'   : f.sentence(1),
                       'email'    : f.email(),
                       'url'      : f.uri(),
                     }
            self.insert_data(**kwargs)
       """ 


class Update(Finder):

    """Update user details."""

    def __init__(self, *args):
        super(Update, self).__init__(*args)

    def _update_data(self, _id, **kwargs):
        """Re-Encrypt data with new passkey and update data"""
        self.cipobj = Cipher(self   .passkey)
        encrypted_dict = {key: self.cipobj.encrypt(kwargs[key])
                          for key in kwargs.keys()}

        sql_cmd = "UPDATE %s SET " % Setting.table_name['password_manager']

        for c in Setting.column_order['password_manager']:
            try:
                sql_cmd += '%s = "%s", ' % (c, encrypted_dict[c])
            except:
                pass

        # removing one space and coma
        sql_cmd = sql_cmd[:-2]
        sql_cmd += ' WHERE id = %s' % _id
        self.execute(sql_cmd)

    def _update_all_details(self):
        all_result = self.select_all()
        self.passkey = self.new_passkey
        for lst in all_result:
            kwargs = {'unique_name': lst[1],
                      'username': lst[2],
                      'password': lst[3],
                      'email': lst[4],
                      'url': lst[5],
                      'detail': lst[6],
                      }
            _id = lst[0]
            self._update_data(_id, **kwargs)

        print 'Successfully updated all the user details with the new pass key'
        print 'Please verify using finder'

    def __call__(self):

        update_dict = {}
        self.passkey = get_input(msg='Password: ', password=True)
        self.cipobj = Cipher(self.passkey)
        # verify old passkey
        self.verification = self._is_password_correct

        for col in Setting.column_order['password_manager']:
            try:
                if self.argument[col]:
                    update_dict[col] = self.argument[col]
            except:
                pass
        if not update_dict:
            print 'Nothing to update'
            sys.exit(1)
        self._update_data(self.argument['id'], **update_dict)
        print 'Successfully updated.'


class Passkey(Update):

    """Create and Update passkey to unlock user details."""

    def __init__(self, *args):
        super(Passkey, self).__init__(*args)

    def _is_exist_passkey(self):
        sql_cmd = "SELECT * from passkey_manager ORDER BY ID DESC LIMIT 1"
        return self.execute(sql_cmd).fetchone()

    def _insert_passkey(self, pak):
        salt, digest = self.get_password_digest(pak)
        sql_cmd = "INSERT INTO passkey_manager (salt, digest) VALUES \
                  ('{0}', '{1}')".format(salt, digest)
        self.execute(sql_cmd)
        print "Successfully created new passkey"
        return True

    def _update_passkey(self):

        self.passkey = get_input(msg='Old Password: ', password=True)

        self.cipobj = Cipher(self.passkey)
        self.new_passkey = get_input('New Password: ', password=True)
        self.new_passkeys = get_input(msg='Type Again: ', password=True)

        if self.new_passkey != self.new_passkeys:
            print 'Error: passkey not matching'
            sys.exit(1)

        # verify old passkey
        self.verification = self._is_password_correct
        print 'Successfully verified old passkey'

        # updating passkey
        self._insert_passkey(self.new_passkey)

        # updating password_manager table with new passkey encryption
        self._update_all_details()

    def _create_passkey(self):
        # check is there any passkey already exists
        # if exists then request the user to update the passkey and
        # re-encrypt the whole user details.
        if not self._is_exist_passkey():
            passkey = get_input("Enter your new passkey: ", password=True)
            passkeys = get_input(msg='Type Again: ', password=True)

            if passkey != passkeys:
                print 'Error: passkey not matching'
                sys.exit(1)

            return self._insert_passkey(passkey)
        else:
            print "passkey already exists, please use [%s paskey --update]" % \
                __file__
            return False

    def __call__(self):
        """Callable Class"""
        if self.argument['create']:
            self._create_passkey()
        elif self.argument['update']:
            self._update_passkey()
        else:
            print "nothing to do, please check usage"

class Import(Insert):
    
    """Import users details fromt the json dump"""

    def __init__(self, *args):
        super(Import, self).__init__(*args)
        self.encrypt = None
        # verify passkey
        self.passkey = get_input(msg='Password: ', password=True)
        self.verification = self._is_password_correct
        self.decobj = Cipher(self.passkey)
        self.cipobj = self.decobj

    def _read_dumps(self):
        """read database dump from file"""
        try:
            with open(self._file_path, 'r') as json_data:
                data = json.load(json_data)
            return data
        except Exception as error:
            raise Exception (error)

    def __call__(self):

        self._format = self.argument['format']
        self._file_path = self.argument['file'] 
        self.json_docs = self._read_dumps()

        if self._format == 'encrypt':
            self.new_json_docs = list()
            for dics in sorted(self.json_docs, key=operator.itemgetter('url')):
                new_dics = dict()
                for d, v in dics.items():
                    if d != 'id':
                        new_dics[d] = self.decobj.decrypt(v)
                self.new_json_docs.append(new_dics)

            self.json_docs = self.new_json_docs

        for dics in sorted(self.json_docs, key=operator.itemgetter('url')):
            if not self.is_exist(**dics):
                self.insert_data(**dics)
            else:
                print "Similar data exist, please check using finder."
                print "You can't insert same [username, email and url] "\
                      "which doesn't make sense."

            
class Export(Finder):

    """Export user details to file { encrypt or decrypt } base on the users"""

    def __init__(self, *args):
        super(Export, self).__init__(*args)
        self.passkey = get_input(msg='Password: ', password=True)
        self.cipobj = Cipher(self.passkey)

    def __call__(self):

        # verify passkey
        self.verification = self._is_password_correct

        if self.argument['format'] == 'decrypt':
            result_all = self.select_all()
        else:
            result_all = self.select_all(decrypt=False)

        _col = Setting.column_order['password_manager']
        _col.insert(0, 'id')

        result_lod = []
        for all in result_all:
            result_lod.append((dict(zip(_col, all))))

        path = self.argument['path']
        export_file = '%s%s.json' % (path, str(time.time()).split('.')[0])

        # open export file
        with open(export_file, "w") as outfile:
            json.dump(result_lod, outfile, indent=4)

        print 'Succesfully exported user details into %s' % export_file


class Delete(Database, Cipher):

    """Delete user details from database using id """

    def __init__(self, *args):
        super(Delete, self).__init__(*args)
        self.passkey = get_input(msg='Password: ', password=True)
        self.cipobj = Cipher(self.passkey)
        self.verification = self._is_password_correct

    def __call__(self):

        _ids = self.argument['id']
        for _id in _ids:
            sql_cmd = ("DELETE from %s where id='%s'" %
                      ( Setting.table_name['password_manager'], _id ))
            self.execute(sql_cmd)
            print "Successfully deleted id=%d" % _id

def main():
    """Main function."""
    desc = "Personal Password Manager: "
    epi = "Life is easier when you remember less"

    # create top level parser
    parser = argparse.ArgumentParser(description=desc,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     epilog=epi,
                                     prog="%s" % os.path.basename(__file__))

    # create sub-parser
    subparsers = parser.add_subparsers(title="sub-commands",
                                       help="sub-command help")

    # create the parser for database command
    database_parser = subparsers.add_parser("database",
                                            help="database related commands.")

    database_mgroup = database_parser.add_mutually_exclusive_group(
        required=True)

    database_mgroup.add_argument("--create",
                                 action='store_true',
                                 help="creating the database, configure table.")

    database_mgroup.add_argument("--drop",
                                 action='store_true',
                                 help="drop database or destroy database.")

    database_parser.set_defaults(func=Database)

    # create the parser for insert command
    # do insert if not exist else update
    insert_parser = subparsers.add_parser("insert",
                                          help="insert related commands.")

    insert_parser.add_argument("--username", "-un",
                               type=str,
                               required=True,
                               help="login username.")

    insert_parser.add_argument("--password", "-p",
                               type=str,
                               required=True,
                               help="login password.")

    insert_parser.add_argument("--email",
                               type=str,
                               required=True,
                               help="email id.")

    insert_parser.add_argument("--unique-name", '-uqn',
                               metavar='unique_name',
                               type=str,
                               required=True,
                               help="unique name for the entry.")

    insert_parser.add_argument("--detail", '-d',
                               type=str,
                               default='no-details',
                               help="detail about the entry.")

    insert_parser.add_argument("--url",
                               type=str,
                               required=True,
                               help="login url.")

    insert_parser.set_defaults(func=Insert)

    # create the parser for finder command
    finder_parser = subparsers.add_parser("finder",
                                          help="find details.")

    finder_parser.add_argument("--username", "-un",
                               type=str,
                               help="match username.")

    finder_parser.add_argument("--email", '-e',
                               type=str,
                               help="match email id.")

    finder_parser.add_argument("--unique-name", '-uqn',
                               metavar='unique_name',
                               type=str,
                               help="match unique name.")

    finder_parser.add_argument("--detail", '-d',
                               type=str,
                               help="match detail.")

    finder_parser.add_argument("--url",
                               type=str,
                               help="match url.")

    finder_parser.add_argument("--any",
                               type=str,
                               help="match any string.")

    finder_parser.add_argument("--all",
                               action="store_true",
                               help="show all details")

    finder_parser.set_defaults(func=Finder)

    # create the parser for passkey command
    passkey_parser = subparsers.add_parser("passkey",
                                           help="passkey create or update")

    passkey_parser.add_argument("--create", "-c",
                                action='store_true',
                                help="create new passkey for the first time")

    passkey_parser.add_argument("--update", "-u",
                                action='store_true',
                                help="update passkey, this will also update the \
                                     user encryption details")

    passkey_parser.set_defaults(func=Passkey)

    # create the parser for update command
    update_parser = subparsers.add_parser("update",
                                          help="update user details.")

    update_parser.add_argument("--id",
                               type=int,
                               required=True,
                               help="id which is unique")

    update_parser.add_argument("--username", "-un",
                               type=str,
                               help="update username.")

    update_parser.add_argument("--password", "-p",
                               type=str,
                               help="update password.")

    update_parser.add_argument("--email", "-e",
                               type=str,
                               help="update email id.")

    update_parser.add_argument("--unique-name", '-uqn',
                               metavar='unique_name',
                               type=str,
                               help="update unique name.")

    update_parser.add_argument("--detail", "-d",
                               type=str,
                               help="update detail.")

    update_parser.add_argument("--url",
                               type=str,
                               help="update url.")

    update_parser.set_defaults(func=Update)

    # create the parser for export command
    export_parser = subparsers.add_parser("export",
                                          help="export user details options")

    # Common options for import and export
    export_parser.add_argument("--path",
                               type=str,
                               default='%s' % Setting.dump_path,
                               help="path to dump the database "
                                    "(default: %(default)s)")

    export_parser.add_argument("--format",
                               type=str,
                               choices=['decrypt', 'encrypt'],
                               default='encrypt',
                               help="export format, (default: %(default)s).")

    export_parser.set_defaults(func=Export)

    # create the parser for delete command
    delete_parser = subparsers.add_parser("delete",
                                          help="delete user details using id")
    delete_parser.add_argument("--id", '-id',
                               nargs='+',
                               type=int,
                               required=True,
                               help="ID to delete, support multiple ids")

    delete_parser.set_defaults(func=Delete)

    # create the parser for import command
    import_parser = subparsers.add_parser("import",
                                          help="import user details from file")
    import_parser.add_argument("--file", '-f',
                               required=True,
                               type=str,
                               help="full path to the import file.")

    import_parser.add_argument("--format",
                               required=True,
                               type=str,
                               choices=['decrypt', 'encrypt'],
                               help="current data format, if its encrypted or decrypted")

    import_parser.set_defaults(func=Import)

    args = parser.parse_args()
    args.func(vars(args))()

if __name__ == '__main__':
    main()
