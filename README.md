# ftp-encrypted-storage
FTP server in Python that uses AES-CBC symmetric encryption to store files on the disk. Great for backing up personal files on a home network server

## Deployment and Usage instructions

1. Specify user and location in docker-compose.yaml
```sh -c 'python /ftpserveraes.py alex /ftp_data'```

2. Deploy ftp encrypted storage container on a local server
```docker-compose up -d```

3. Using any ftp client connect to the ftp server. Login using user and any password. Files will be stored encrypted using the password based AES key. Downloading files involves encryption, the same password must be given. 