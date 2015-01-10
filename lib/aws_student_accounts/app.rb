require "thor"

class AwsStudentAccounts::App < Thor
  include Thor::Actions

  desc "verify-credentials", "Verify AWS credentials"
  def verify_credentials
  end

  desc "create-students", "Create a student IAM account for all AWS accounts"
  def create_students
  end

  desc "delete-students", "Delete temporary student IAM accounts"
  def delete_students
  end

  desc "clean-accounts", "Clean out all VMs, disk, elastic IPs, AMIs, VPCs from student accounts"
  def clean_accounts
  end
end
