AWS Student Accounts
====================

Manage student AWS accounts in bulk.

-	Consumes a single `.fog` file of AWS accounts with master credentials
-	Creates/deletes temporary student IAM credentials
	-	Emits a `.fog` file for API access
	-	Emits a username/password file for AWS Console access
-	Cleans out all VMs, disk, elastic IPs, AMIs, VPCs from student accounts

Requires
--------

-	Ruby 1.9+
-	RubyGems

Installation
------------

Install using RubyGems:

```
$ gem install aws_student_accounts
```

Usage
-----

### Verify list of API credentials are valid

```
aws_student_accounts verify-credentials -C path/to/fog.yml
```

### Create student IAM access

Create a student IAM account for all AWS accounts

```
aws_student_accounts create-students -C path/to/fog.yml path/to/students
```

`path/to/students` will be a folder into which the following files are created:

-	`students-fog-api.yml` - the AWS credentials for all students' to access their allocated AWS accounts
-	`students-console-passwords.md` - the AWS console username/passwords for students' to access their allocated AWS accounts

### Delete student IAM access

Delete temporary student IAM accounts.

```
aws_student_accounts delete-students -C path/to/fog.yml
```

### Cleans accounts

Clean out all VMs, disk, elastic IPs, AMIs, VPCs from student accounts

```
aws_student_accounts clean-accounts -C path/to/fog.yml
```

### Options

All commands will perform the account upon all accounts listed in the `-C fog.yml` file provided.

You can filter to 1+ accounts with a comma separated list `-a student1,student2`.

You can ignore 1+ accounts from the `-C` list with `-i student19,student20`.

Experiment with these options using the read-only `aws_student_accounts verify-credentials` command.

Contributing
------------

1.	Fork it ( https://github.com/[my-github-username]/aws_student_accounts/fork )
2.	Create your feature branch (`git checkout -b my-new-feature`\)
3.	Commit your changes (`git commit -am 'Add some feature'`\)
4.	Push to the branch (`git push origin my-new-feature`\)
5.	Create a new Pull Request
