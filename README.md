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

TODO: Write usage instructions here

Contributing
------------

1.	Fork it ( https://github.com/[my-github-username]/aws_student_accounts/fork )
2.	Create your feature branch (`git checkout -b my-new-feature`\)
3.	Commit your changes (`git commit -am 'Add some feature'`\)
4.	Push to the branch (`git push origin my-new-feature`\)
5.	Create a new Pull Request
