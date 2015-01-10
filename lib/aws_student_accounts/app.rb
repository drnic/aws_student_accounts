require "thor"
require "yaml"

class AwsStudentAccounts::App < Thor
  include Thor::Actions

  def self.common_options
    method_option :fog_file, desc: "Path to YAML file of fog credentials",
                    type: :string, aliases: "-C", required: true
  end

  desc "verify-credentials", "Verify AWS credentials"
  common_options
  def verify_credentials
    load_and_verify_options
  end

  desc "create-students", "Create a student IAM account for all AWS accounts"
  common_options
  def create_students
    load_and_verify_options
  end

  desc "delete-students", "Delete temporary student IAM accounts"
  common_options
  def delete_students
    load_and_verify_options
  end

  desc "clean-accounts", "Clean out all VMs, disk, elastic IPs, AMIs, VPCs from student accounts"
  common_options
  def clean_accounts
    load_and_verify_options
  end

  private
  def load_and_verify_options
    @fog_file = options["fog_file"]
    unless File.exists?(@fog_file)
      say "File #{@fog_file} does not exist", :red
      exit 1
    end
    @fog_credentials = YAML.load_file(@fog_file)
    if !@fog_credentials.is_a?(Hash) || @fog_credentials.first.is_a?(Hash)
      say "File #{@fog_file} does not match a .fog format (Hash of Hashes)", :red
      exit 1
    end
  end

end
