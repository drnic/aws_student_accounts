require "thor"
require "yaml"
require "fog"

class AwsStudentAccounts::App < Thor
  include Thor::Actions

  attr_reader :fog_credentials

  def self.common_options
    method_option :fog_file, desc: "Path to YAML file of fog credentials",
                    type: :string, aliases: "-C", required: true
  end

  desc "verify-credentials", "Verify AWS credentials"
  common_options
  def verify_credentials
    load_and_verify_options
    fog_credentials.each do |key, credentials|
      say "#{key}: "
      begin
        compute = Fog::Compute::AWS.new(credentials)
        server_count = compute.servers.size
        vpc_count = compute.vpcs.size
        say "OK ", :green
        say "(#{server_count} vm, #{vpc_count} vpcs)"
      rescue => e
        say e.message, :red
      end
    end
  end

  desc "create-students", "Create a student IAM account for all AWS accounts"
  common_options
  def create_students
    load_and_verify_options
    fog_credentials.each do |key, credentials|
      say "#{key}:"
      begin
        iam = Fog::AWS::IAM.new(credentials)
        username = key

        begin
          user_response = iam.create_user(username)
        rescue Fog::AWS::IAM::EntityAlreadyExists
          say "User #{username} exists, deleting..."

          access_keys_reponse = iam.list_access_keys('UserName' => username)
          access_keys_reponse.body['AccessKeys'].each do |key|
            user_response = iam.delete_access_key(key['AccessKeyId'], 'UserName' => username)
          end
          say "Deleted access keys", :yellow

          iam.delete_login_profile(username)
          say "Deleted user login profile", :yellow

          user_policies_reponse = iam.list_user_policies(username)
          user_policies_reponse.body['PolicyNames'].each do |policy_name|
            iam.delete_user_policy(username, policy_name)
          end
          say "Deleted user policies", :yellow

          user_response = iam.delete_user(username)
          say "Deleted user", :yellow

          user_response = iam.create_user(username)
        end
        say "Created user #{username}", :green
        key_response  = iam.create_access_key('UserName' => username)
        access_key_id     = key_response.body['AccessKey']['AccessKeyId']
        secret_access_key = key_response.body['AccessKey']['SecretAccessKey']

        say "Created access key #{access_key_id} #{secret_access_key}", :green

        say "TODO: generated and download SSH public key", :yellow

        password = generate_password
        iam.create_login_profile(username, password)
        say "Created login password #{password}"
        say "TODO: determine IAM users sign-in link, e.g. https://093368509744.signin.aws.amazon.com/console", :yellow

        arn = user_response.body['User']['Arn']
        iam.put_user_policy(username, 'UserKeyPolicy', iam_key_policy(arn))
        iam.put_user_policy(username, 'UserAllPolicy', iam_student_policy)
        say "Created user policies", :green

        user_credentials = {
          aws_access_key_id: access_key_id,
          aws_secret_access_key: secret_access_key
        }
        say "Verify credentials: "
        begin
          user_compute = Fog::Compute::AWS.new(user_credentials)
          server_count = user_compute.servers.size
          say "OK ", :green
          say "(#{server_count} vms)"
        rescue => e
          say e.message, :red
        end

        say "OK", :green
      rescue => e
        say "#{e.class}: #{e.message}", :red
      end
    end
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

    # TODO: filter @fog_credentials by filter/ignore list
  end

  # generated via http://awspolicygen.s3.amazonaws.com/policygen.html
  # Effect	Action   Resource	         Conditions
  # Allow	  ec2:*	   arn:aws:ec2:*:*:*	 None
  # Allow	  s3:*	   arn:aws:s3:::*	     None
  def iam_key_policy(arn)
    {
      'Statement' => [
        'Effect' => 'Allow',
        'Action' => 'iam:*AccessKey*',
        'Resource' => arn
      ]
    }
  end

  def iam_student_policy
    {
      "Statement" => [
        {
          "Effect" => "Allow",
          "Action" => "*",
          "Resource" => "*"
        },
      ]
    }
  end

  def generate_password
    "starkandwayne"
  end
end
