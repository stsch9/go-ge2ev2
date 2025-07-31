# go-ge2ev2

**WARNING**: This is just a PoC. Use at your own risk.

This is a tool for storing data on untrusted storage and sharing it with other people. The client-side encryption is only one necessary feature. The secure distribution of the keys is a much greater challenge (see https://securitycryptographywhatever.com/2025/05/19/e2ee-storage/). It should be possible to change the group of people who have access to the files at any time. With this tool, the distribution of keys is controlled completely by the group members. This is a difference to many other cloud storage providers. 
However, the administration of larger groups can become complex. This is where protocols such as [MLS](https://datatracker.ietf.org/doc/rfc9420/), which ensures the agreement and distribution of a shared key, would be of greater benefit.

For encryption and decryption [age](https://github.com/FiloSottile/age) is used. All information (the actual file name, the secert keys with which the files are encrypted and a random string under which the files are stored and all age recipients) are stored in a file called FileKeys. This file is then encrypted to the age recipients and stored on the storage. This means that anyone who can decrypt this file (all age recipients/group members) can also decrypt the files stored on the storage. If the age recipients (the group members) change, only this file needs to be re-encrypted. All age recipients are also included in the FileKeys file, because when a change is made (e.g. new files are uploaded) the FileKeys file must also be updated and re-encrypted. The FileKeys file is then encrypted to the age recipients contained in the FileKeys file.

Immudb

```
{
    "Version": <VERSION_OF_THIS_JSON>,
    "Keys": {
        "<FILE_NAME_1>": ["<FILE_KEY_1>", "<RANDOM_FILE_NAME_OF_STORED_FILE_1>"],
        "<FILE_NAME_2>": ["<FILE_KEY_2>", "<RANDOM_FILE_NAME_OF_STORED_FILE_2>"],
        ...
    },
    "Recipients": ["AGE_RECIPIENT_1", "AGE_RECIPIENT_2", ...]
}
```
Threat Model.

## How it works
### Dataroom creation
The user creates a dataroom directory `/PATH/TO/DATAROOM` and a  directory `/PATH/TO/DATAROOM/.meta` in which the file keys (for encrypting the file) and the file names are stored in encrypted form. In addition, a so-called dataroom ristretto255 key pair `(a, A)` is created, which is used to encrypt all data in the `.meta` directory:

The user creates a new file `Filekeys` with the content:

```
{
    "Version": 1,
    "Keys": {}
}
```
where `Version` is the version of the file and all filekeys are stored in `Keys`. For more details see below.

Then the user creates a random ristretto255 key pair `(e, E)` and calculates

```
shared_key = a * E
```

where * denotes the scalar multiplication over the elliptic curve ristretto255.
Then the user uses the HKDF function to create a symmetric key

```
k = hdkf(hash=sha256, secret=shared_key, salt=random(32), info=b'filekey')
```

Finally, the user encrypts the file Filekeys with `k`

```
Filekeys.enc = ascon(key=k, nonce=random(32), plaintext=Filekeys, ad=null)
```
and stores `Filekeys.enc` and `E` in `/PATH/TO/DATAROOM/.meta`.


### File upload to a dataroom
First, the user decrypts the file `Filekeys.enc` with the private dataroom key `a` and the ephemeral public `E` (see above).

Then the user creates a random filekey `fk` and a random(32) filename `fn` and stores this to `Filekeys`

```
{
    "Version": <VERSION> + 1,
    "Keys": {
        "<ACTUAL_FILENAME>": [fk, fn],
        ...
    }
}
```

The user encrypts the file with `fk`
```
fn = ascon(key=fk, nonce=random(32), plaintext=file, ad=null)
```
and stores the encrypted file with the name `fn` in `/PATH/TO/DATAROOM/fn`.

Finally, the user encrypts the file `Filekeys` with a new ephemaral public key `E` (see above) and stores `Filekeys.enc` and `E` in `/PATH/TO/DATAROOM/.meta`.

## List all files stored in the dataroom
The User the user decrypts the file `Filekeys.enc` with the private dataroom key `a` and the ephemeral public `E` (see above). This allows the user to query all file names that are listed in the Filekeys file and are therefore in the dataroom.

## File download
First, the user decrypts the file `Filekeys.enc` with the private dataroom key `a` and the ephemeral public `E` (see above).

The user then queries the filekey `fk` and the path to the encrypted file `fn` using the file filekeys.

The file can now be decrypted using the file path `fn` and the file key `fk`.

## Key Rotation

Suppose the user wants to renew the dataroom key `a`. He generates a new random ristretto255 dataroom key pair `(b, B)`. In addition, a so-called `factor` file is created, which contains the scalar product of the multiplicative inverse of `b` and `a`:

```
factor =  b^-1 * a (mod L)
```

where L is L the order of the ristretto255 group: (2^252 + 27742317777372353535851937790883648493).

The `factor` file is stored in the path `/PATH/TO/DATAROOM/.meta`.

## Rekey

The ephemeral public key `E` (stored in path `/PATH/TO/DATAROOM/.meta`) is multiplied by the `factor` generated during key rotation (see above):

```
F = factor * E
```
`E` is replaced by `F` in the path `/PATH/TO/DATAROOM/.meta`.

This allows the user to decrypt the file `Keyfiles.enc` with his new private key `b`, since the user receives the same `shared_key` as before:

```
b * F = b * (factor * E) = b * ((b^-1 * a) * E) = a * E = shared_key
```

Since neither the new private key `b` nor the old private key `a` can be calculated from the `factor`, the rekey operation can be executed by an untrusted third party.

## Usage
...