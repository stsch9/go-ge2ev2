# go-ge2ev2

**WARNING**: This is just a PoC. Use at your own risk.

This is a tool for storing data on untrusted storage and sharing it with other people. The client-side encryption is only one necessary feature. The secure distribution of the keys is a much greater challenge (see https://securitycryptographywhatever.com/2025/05/19/e2ee-storage/). It should be possible to change the group of people who have access to the files at any time. With this tool, the distribution of keys is controlled completely by the group members. This is a difference to many other cloud storage providers. 
However, the administration of larger groups can become complex. This is where protocols such as [MLS](https://datatracker.ietf.org/doc/rfc9420/), which ensures the agreement and distribution of a shared key, would be of greater benefit.

For encryption and decryption the tool [age](https://github.com/FiloSottile/age) is used. All meta information are stored in a file called `FileKeys`. This file is then encrypted to the age recipients (to all group memmbers) and stored on the storage. This means that anyone who can decrypt this file (all age recipients/group members) can also decrypt the files stored on the storage. 

The following information is stored in the FileKeys file:
- The Version of the FileKeys file
- The actual file names of the files stored on the storage
- The file keys that are used to encrypt the files
- The random file names used to save the files on the storage.
- All age Recipients (public age keys), i.e. all group members.

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

If the age recipients (the group members) change, only this file needs to be re-encrypted. All age recipients are also included in the `FileKeys` file, because when a change is made (e.g. new files are uploaded) the `FileKeys` file must also be updated and re-encrypted. The new `FileKeys` file is then encrypted to the age recipients contained in the FileKeys file.

In order to validate the change to the FileKeys file, the SHA256 hash is generated from the plain text FileKeys file and saved in [immudb](https://github.com/codenotary/immudb) each time a change is made. Immudb is used, since it is immutable: History is preserved and can't be changed without clients noticing.


## Possible attackers
- An attacker who has full access to the storage must obtain access to the encrypted FileKeys file in order to be able to read the stored data. If the attacker also has information about the age recipients (the age recipinets are also encrypted in the `Filekeys` file) and possibly also (partial) information about the stored files, he can simply add his age public to the FileKeys file and encrypt this modified FileKeys file to the age recipients. This would give the attacker access to all new uploaded files. However, since the hash of the FileKeys file is stored in the immudb, this attack is noticed. Any other manipulation of the files is also recognized by the age encryption properties. Of course, the deletion of files cannot be prevented.
- Since all data are client-side encrypted on the storage, an attacker who can monitor the network traffic cannot obtain any information.
- An attacker who can manipulate network traffic is also detected, as any changes to the encrypted files are also detected thanks to age encryption.


## How it works
### Dataroom creation
...
### File upload
...
### File download
...
### File deletion
...
### List files
...
### Change group members
...