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
  method_option :signin_urls, desc: "File mapping usernames to account signin URLs",
    type: :string, aliases: "-s", required: true
  def create_students(path_to_student_folders="students")
    load_and_verify_options

    signin_urls = YAML.load_file(options[:signin_urls])

    users_credentials = {}
    users_passwords = {}

    FileUtils.mkdir_p(path_to_student_folders)
    FileUtils.chdir(path_to_student_folders) do
      fog_credentials.each do |username, credentials|
        unless account_signin_url = signin_urls[username]
          user_say username, "Username #{username} missing from #{options[:signin_urls]}, skipping", :red
          next
        end

        begin
          iam = Fog::AWS::IAM.new(credentials)

          begin
            user_response = iam.create_user(username)
          rescue Fog::AWS::IAM::EntityAlreadyExists
            user_say username, "User exists, deleting..."

            delete_user(iam, username)
            user_response = iam.create_user(username)
          end
          user_say username, "Created user #{username}", :green
          key_response  = iam.create_access_key('UserName' => username)
          access_key_id     = key_response.body['AccessKey']['AccessKeyId']
          secret_access_key = key_response.body['AccessKey']['SecretAccessKey']

          user_say username, "Created API access key", :green

          user_say username, "TODO: generated and download SSH public key", :yellow

          password = generate_password
          iam.create_login_profile(username, password)
          user_say username, "Created login password #{password}"

          arn = user_response.body['User']['Arn']
          iam.put_user_policy(username, 'UserKeyPolicy', iam_key_policy(arn))
          iam.put_user_policy(username, 'UserAllPolicy', iam_student_policy)
          user_say username, "Created user policies", :green

          user_credentials = {
            aws_access_key_id: access_key_id,
            aws_secret_access_key: secret_access_key
          }
          user_say username, "Verify credentials: "
          begin
            user_compute = Fog::Compute::AWS.new(user_credentials)
            server_count = user_compute.servers.size
            say "OK ", :green
            say "(#{server_count} vms)"
          rescue => e
            say e.message, :red
          end

          users_credentials[username.to_sym] = user_credentials
          user_login = {
            password: password,
            username: username.to_s,
            url: account_signin_url
          }
          users_passwords[username] = user_login

          write_fog_file(username, user_credentials)
          write_password_file(account_signin_url, user_login)
        rescue => e
          say "#{e.class}: #{e.message}", :red
        end
      end

      File.open("students-fog-api.yml", "w") do |f|
        f << users_credentials.to_yaml
      end
      say "Stored all user API credentials: #{File.expand_path('students-fog-api.yml')}"

      File.open("students-console-passwords.md", "w") do |f|
        f << "# Student AWS logins\n\n"
        fog_credentials.each do |username, credentials|
          if user_login = users_passwords[username]
            f << <<-EOS
## #{user_login[:username]}

* Sign-in URL: #{user_login[:url]}
* Username: #{user_login[:username]}
* Password: #{user_login[:password]}

            EOS
          end
        end
        say "Stored all user passwords: #{File.expand_path('students-console-passwords.md')}"
      end
    end
  end

  desc "delete-students", "Delete temporary student IAM accounts"
  common_options
  def delete_students
    load_and_verify_options
    fog_credentials.each do |key, credentials|
      begin
        iam = Fog::AWS::IAM.new(credentials)
        username = key
        delete_user(iam, username)
      end
    end
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

  def user_say(username, *args)
    say "[#{username}] "
    say *args
  end

  def delete_user(iam, username)
    access_keys_reponse = iam.list_access_keys('UserName' => username)
    access_keys_reponse.body['AccessKeys'].each do |key|
      user_response = iam.delete_access_key(key['AccessKeyId'], 'UserName' => username)
    end
    user_say username, "Deleted access keys", :yellow

    begin
      iam.delete_login_profile(username)
      user_say username, "Deleted user login profile", :yellow
    rescue Fog::AWS::IAM::NotFound
    end

    user_policies_reponse = iam.list_user_policies(username)
    user_policies_reponse.body['PolicyNames'].each do |policy_name|
      iam.delete_user_policy(username, policy_name)
    end
    user_say username, "Deleted user policies", :yellow

    user_response = iam.delete_user(username)
    user_say username, "Deleted user", :yellow
  end

  def write_fog_file(username, user_credentials)
    FileUtils.mkdir_p(username.to_s)
    File.open(File.join(username.to_s, "fog-api.yml"), "w") do |f|
      f << {
        username.to_sym => user_credentials
      }.to_yaml
    end
    user_say username, "Created fog-api.yml", :green
  end

  def write_password_file(account_signin_url, user_login)
    username = user_login[:username]
    FileUtils.mkdir_p(username)
    File.open(File.join(username, "console-passwords.md"), "w") do |f|
      f << <<-EOS
# #{username}

* Sign-in URL: #{user_login[:url]}
* Username: #{username}
* Password: #{user_login[:password]}
      EOS
    end
    user_say username, "Created fog-api.yml", :green

  end
end
