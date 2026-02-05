
# Support Documentation for CTF-SIL765

## CTF Extract Tool

We have written a script `ctf-extract` to help you extract the flag and key from the system. You can use it as follows:

```bash
ctf-extract [P1|P2|P3|P4|P5]
```

It should only work if you have gained the required access for the problem. If you have, it will create a tarball in the correct format for submission.

## Creating the Tarball for Submission

To create a tarball for submission, you can use the following command:

```bash
tar -czvf [EntryNumber]-P1.tar.gz flag.txt key.txt
```

## Extracting your Tarball

To extract your tarball, you can use the following command:

```bash
scp -P [PORT] -i [IDENTITY_FILE] p1@localhost:[FILENAME] [DESTINATION]

```
