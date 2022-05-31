# PyEncrypt

## what it does

it encrypts all your files in a folder so no one can read them without the key

## how to install

```bash
pip install -r requirements.txt
```

or:

```bash
pip install -e .
```

## how to use it

### lock your files (encrypt them)

```bash
python main.py lock
```

this will encrypt everything in the current folder and make a key file. 
DONT LOSE THE KEY FILE or your stuff is gone forever

### unlock your files

```bash
python main.py unlock
```

### other commands

```bash
python main.py status        # check if folder is locked
python main.py lock -r       # recursive mode (does subfolders too)
python main.py lock -d /path # encrypt a different directory
```

## using it in your code

```python
from pyencypt import FileEncryptor, KeyManager

# make encryptor
km = KeyManager(key_dir="./my_folder")
enc = FileEncryptor(key_manager=km)

# encrypt stuff
enc.lock("./my_folder")

# decrypt stuff  
enc.unlock("./my_folder")
```

## requirements

- python 3.10+
- cryptography library

## running tests

```bash
pytest
```

## important notes

- the key file is named `.pyencrypt.key` - its hidden on mac/linux
- if u delete the key u cant decrypt ur files.
- dont encrypt the same folder twice
