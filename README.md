# go-ge2ev2

**WARNING**: This is just a PoC. Use at your own risk.
## Introduction
This is a tool for storing data on untrusted storage and sharing it with other people. Client-side encryption is therefore a necessary feature, but not the only one. The secure distribution of the keys is a much greater challenge (see https://securitycryptographywhatever.com/2025/05/19/e2ee-storage/). It should be possible to change the group of people who have access to the files at any time. With this tool, the distribution of keys is controlled completely by the group members. This is a difference to many other cloud storage providers. 
However, the administration of larger groups can become complex. This is where protocols such as [MLS](https://datatracker.ietf.org/doc/rfc9420/), which ensures the agreement and distribution of a shared key, would be of greater benefit:
> The core functionality of MLS is continuous group authenticated key exchange (AKE). As with other authenticated key exchange protocols (such as TLS), the participants in the protocol agree on a common secret value, and each participant can verify the identity of the other participants. That secret can then be used to protect messages sent from one participant in the group to the other participants using the MLS framing layer or can be exported for use with other protocols. ...

## Design
For encryption and decryption the tool [age](https://github.com/FiloSottile/age) is used. All meta information are stored in a file called `DataroomMeta`. This file is then encrypted to the age recipients (to all group members) and stored on the storage. This means that anyone who can decrypt this file (all age recipients/group members) can also decrypt the files stored on the storage. 

The following information is stored in the DataroomMeta file:
- The Version of the DataroomMeta file
- The actual file names of the files stored on the storage
- The file keys that are used to encrypt the files
- The random file names used to save the files on the storage.
- All age Recipients (public age keys), i.e. all group members.

```
{
    "Version": <VERSION_OF_THIS_JSON>,
    "Files": {
        "<FILE_NAME_1>": {
            "Id": <FILE_ID_1>,
            "Versionkeys": [
                {
                  "Filekey": "<FILE_KEY_11>",
                  "Filename": "<RANDOM_FILE_NAME_11>"
                },
                {
                  "Filekey": "<FILE_KEY_12>",
                  "Filename": "<RANDOM_FILE_NAME_12>"
                },
                ...
            ]
        },
        "<FILE_NAME_2>": {
            "Id": <FILE_ID_2>,
            "Versionkeys": [
                {
                  "Filekey": "<FILE_KEY_21>",
                  "Filename": "<RANDOM_FILE_NAME_21>"
                },
                {
                  "Filekey": "<FILE_KEY_22>",
                  "Filename": "<RANDOM_FILE_NAME_22>"
                },
                ...
            ]
        },
        ...
    },
    "Recipients": ["AGE_RECIPIENT_1", "AGE_RECIPIENT_2", ...]
}
```

If the age recipients (the group members) change, only this file needs to be re-encrypted. All age recipients are also included in the `DataroomMeta` file, because when a change is made (e.g. new files are uploaded) the `DataroomMeta` file must also be updated and re-encrypted. The new `DataroomMeta` file is then encrypted to the age recipients contained in the `DataroomMeta` file.

In order to validate the change to the `DataroomMeta` file, the SHA256 hash is generated from the plain text `DataroomMeta` file and saved in [immudb](https://github.com/codenotary/immudb) each time a change is made. Immudb is used, since it is immutable: History is preserved and can't be changed without clients noticing.

For file operations (upload, download, ...) with the storage, [rclone](https://rclone.org/) is used. Therefore a variety of providers (e.g. S3 storage, FTP server, ...) can be used.

## Possible attackers
- An attacker who has full access to the storage must obtain access to the encrypted `DataroomMeta` file in order to be able to read the stored data. If the attacker also has information about the age recipients (the age recipinets are also encrypted in the `DataroomMeta` file) and possibly also (partial) information about the stored files, he can simply add his age public to the `DataroomMeta` file and encrypt this modified `DataroomMeta` file to the age recipients. This would give the attacker access to all new uploaded files. However, since the hash of the `DataroomMeta` file is stored in the immudb, this attack is noticed. Any other manipulation of the files is also recognized by the age encryption properties. Of course, the deletion of files cannot be prevented.
- Since all data are client-side encrypted on the storage, an attacker who can monitor the network traffic cannot obtain any information.
- An attacker who can manipulate network traffic is also detected, as any changes to the encrypted files are also detected thanks to age encryption.

## Limitations
It must be ensured that there are no inconsistencies in the `DataroomMeta` file. As there is no service that controls file operations (upload, download, ...) on the storage and therefore also the adjustment of the `DataroomMeta` file, the `DataroomMeta` file must always be locked. This means that the upload in particular can always be blocked for larger groups. As already mentioned above, this tool is not designed for larger groups anyway, as the change of the recipients can be complex.

## Dependencies
You must install the [rclone](https://rclone.org/) tool. And you need a working [immudb](https://github.com/codenotary/immudb) installation.

## Installation
Clone the git Repository and and execute the command
```
cd go-ge2ev2 && go build -o go-ge2ev2 main.go
```
## Configuration
Before starting, a config file `config.toml` must be created
```
immudbserver = "127.0.0.1"               # IP or Domain of the Immudb Server
immmudbport = 3322                       # Immudb Server Port
immudbuser = "immudb"                    # username for immudb connetion
immudbpassword = "immudb"                # pasword of immudb user
rcloneremote = "test"                    # used rclone remote 
rcloneparameter = "--s3-no-check-bucket" # additional parameter for the rclone command                
agerecipientfile = "./recipient_file"    # File of all age recipients, which is read in when creating the dataroom and when changing the recipients
agekeyfile = "./key"                     # Path to personal private age key file
```
The path or the name can be changed with the `-c` parameter
```
go-ge2ev2 -c /PATH/TO/CONFIG/FILE ...
```

## How it works
### Dataroom creation
```
go-ge2ev2 mkdr DATAROOM_NAME
```
- Creating the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file
- Storing the SHA256 hash sum in immudb
- Encrypting the `DataroomMeta` file for all recipients
- Uploading the `DataroomMeta` file
### File upload
```
go-ge2ev2 upload /PATH/TO/LOCAL/FILE DATAROOM_NAME
```
- Generating a random file key (age private key) and a random file name and updating `DataroomMeta` file
- Uploading the `DataroomMeta` file and the file with the random file name
- Downloading and decrypting (withe the personal age key) the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file and comparing it with the hash sum stored in immudb.
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file
- Storing the SHA256 hash sum in immudb
- Encrypting the `DataroomMeta` file for all recipients
### File download
```
go-ge2ev2 download DATAROOM_NAME/FILE_NAME /LOCAL/PATH
```
- Downloading and decrypting (withe the personal age key) the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file and comparing it with the hash sum stored in immudb.
- Downloading the file the with the actual file name
### File deletion
```
go-ge2ev2 rm DATAROOM_NAME/FILE_NAME
```
- Downloading and decrypting (withe the personal age key) the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file and comparing it with the hash sum stored in immudb.
- Deleting file in `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file
- Storing the SHA256 hash sum in immudb
- Encrypting the `DataroomMeta` file for all recipients
- Uploading the `DataroomMeta` file
- Deleting the file on the storage
### List files
```
go-ge2ev2 ls DATAROOM_NAME
```
- Downloading and decrypting (withe the personal age key) the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file and comparing it with the hash sum stored in immudb.
- Listing all file in `DataroomMeta` file
### List Recipients
```
go-ge2ev2 lsrec DATAROOM_NAME
```
- Downloading and decrypting (withe the personal age key) the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file and comparing it with the hash sum stored in immudb.
- Listing all recipients in `DataroomMeta` file
### Change group members
```
go-ge2ev2 chrec DATAROOM_NAME
```
- Downloading and decrypting (withe the personal age key) the `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file and comparing it with the hash sum stored in immudb.
- Updating recipients in `DataroomMeta` file
- Computing the SHA256 hash sum of the cleartext `DataroomMeta` file
- Storing the SHA256 hash sum in immudb
- Encrypting the `DataroomMeta` file for all recipients
- Uploading the `DataroomMeta` file
