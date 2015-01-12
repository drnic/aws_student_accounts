require "thor"
require "yaml"
require "fog"
require "thread_safe"
require "parallel"

class AwsStudentAccounts::App < Thor
  include Thor::Actions

  attr_reader :fog_credentials

  def self.common_options
    method_option :fog_file, desc: "Path to YAML file of fog credentials",
                    type: :string, aliases: "-C", required: true
    method_option :only, desc: "Restrict to comma-separated list of fog keys",
                    type: :string, aliases: "-o"
  end

  desc "verify-credentials", "Verify AWS credentials"
  common_options
  def verify_credentials
    load_and_verify_options
    @io_semaphore = Mutex.new
    Parallel.each(fog_credentials, in_threads: 10) do |username, credentials|
      begin
        account = account_summary(credentials)
        server_count = account[:servers]
        @io_semaphore.synchronize do
          say "#{username}: "
          say "OK ", :green
          say "(#{server_count} vm)"
        end
      rescue => e
        @io_semaphore.synchronize do
          say "#{username}: "
          say e.message, :red
        end
      end
    end
  end

  desc "create-students", "Create a student IAM account for all AWS accounts"
  common_options
  def create_students(path_to_student_folders="students")
    load_and_verify_options
    @io_semaphore = Mutex.new

    @users_credentials = ThreadSafe::Hash.new
    @users_passwords = ThreadSafe::Hash.new

    FileUtils.mkdir_p(path_to_student_folders)
    FileUtils.chdir(path_to_student_folders) do
      Parallel.each(fog_credentials, in_threads: fog_credentials.size) do |username, credentials|
        create_student_user(username, credentials)
      end

      # don't rewrite the shared file if only re-creating credentials for one person
      # FIXME: update these files rather than rewriting?
      # TODO: make backups of shared files before rewriting
      unless options[:only]
        File.open("students-fog-api.yml", "w") do |f|
          f << @users_credentials.to_yaml
        end
        say "Stored all user API credentials: #{File.expand_path('students-fog-api.yml')}"

        File.open("students-console-passwords.md", "w") do |f|
          f << "# Student AWS logins\n\n"
          fog_credentials.each do |username, credentials|
            if user_login = @users_passwords[username]
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
  end

  desc "delete-students", "Delete temporary student IAM accounts"
  common_options
  def delete_students
    load_and_verify_options
    @io_semaphore = Mutex.new

    Parallel.each(fog_credentials, in_threads: fog_credentials.size) do |username, credentials|
      begin
        iam = Fog::AWS::IAM.new(credentials)
        delete_user(iam, username)
        @io_semaphore.synchronize do
          user_say username, "Deleted user", :green
        end
      rescue Fog::AWS::IAM::NotFound
        @io_semaphore.synchronize do
          user_say username, "Does not exist", :red
        end
      rescue => e
        @io_semaphore.synchronize do
          user_say username, e.message, :red
        end
      end
    end
  end

  desc "clean-accounts", "Clean out all VMs, disk, elastic IPs, AMIs, VPCs from student accounts"
  common_options
  def clean_accounts
    load_and_verify_options
    @io_semaphore = Mutex.new

    # Double check before unleashing devastation
    unless yes?("Do you really want to terminate all instances, disk, IPs, networks etc?", :red)
      say "Phew!", :green
      exit 1
    end
    Parallel.each(fog_credentials, in_threads: fog_credentials.size) do |account, credentials|
      all_regions = aws_regions(false)
      Parallel.each(all_regions, in_threads: all_regions.size) do |aws_region|
        compute = Fog::Compute::AWS.new(credentials.merge(region: aws_region))
        destroy_everything(account, aws_region, compute)
      end
    end
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

    if options["only"]
      only_specific_keys = options["only"].split(',')
      @fog_credentials = fog_credentials.keep_if { |key, value| only_specific_keys.include?(key.to_s) }
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

  def user_say_region(username, region, *args)
    say "[#{username}] [#{region}] "
    say *args
  end

  def create_student_user(account, admin_credentials)
    begin
      iam = Fog::AWS::IAM.new(admin_credentials)

      # create user with same name as we externally refer to the account; e.g. student15
      username = account

      begin
        user_response = iam.create_user(username)
      rescue Fog::AWS::IAM::EntityAlreadyExists
        @io_semaphore.synchronize do
          user_say username, "User exists, deleting..."
        end

        delete_user(iam, username)
        user_response = iam.create_user(username)
      rescue => e
        @io_semaphore.synchronize do
          user_say username, e.message, :red
        end
      end

      @io_semaphore.synchronize do
        user_say username, "Created user #{username}", :green
      end
      key_response  = iam.create_access_key('UserName' => username)
      access_key_id     = key_response.body['AccessKey']['AccessKeyId']
      secret_access_key = key_response.body['AccessKey']['SecretAccessKey']

      @io_semaphore.synchronize do
        user_say username, "Created API access key", :green
        user_say username, "TODO: generated and download SSH public key", :yellow
      end

      password = generate_password
      iam.create_login_profile(username, password)
      @io_semaphore.synchronize do
        user_say username, "Created login password", :green
      end

      arn = user_response.body['User']['Arn']
      iam.put_user_policy(username, 'UserKeyPolicy', iam_key_policy(arn))
      iam.put_user_policy(username, 'UserAllPolicy', iam_student_policy)
      @io_semaphore.synchronize do
        user_say username, "Created user policies", :green
      end

      user_credentials = {
        aws_access_key_id: access_key_id,
        aws_secret_access_key: secret_access_key
      }
      retries = 3
      signin_url = nil
      while retries > 0
        begin
          user_compute = Fog::Compute::AWS.new(user_credentials)
          p user_compute
          p user_credentials
          server_count = user_compute.servers.size
          @io_semaphore.synchronize do
            user_say username, "Verify credentials: "
            say "OK ", :green
            say "(#{server_count} vms)"
          end

          signin_url = account_signin_url(user_compute)

        rescue => e
          retries =- 1
          if retries <= 0
            @io_semaphore.synchronize do
              user_say username, "Verify credentials: "
              say e.message, :red
            end
          else
            @io_semaphore.synchronize do
              user_say username, "Verify credentials: "
              say "failed ", :yellow
              say "retrying..."
            end
            sleep 1
          end
        end
      end

      @users_credentials[username.to_sym] = user_credentials
      user_login = {
        password: password,
        username: username.to_s,
        url: signin_url
      }
      @users_passwords[username] = user_login

      write_fog_file(username, user_credentials)
      write_password_file(signin_url, user_login)
    rescue => e
      @io_semaphore.synchronize do
        say "#{e.class}: #{e.message}", :red
      end
    end

  end

  def delete_user(iam, username)
    access_keys_reponse = iam.list_access_keys('UserName' => username)
    access_keys_reponse.body['AccessKeys'].each do |key|
      user_response = iam.delete_access_key(key['AccessKeyId'], 'UserName' => username)
    end
    @io_semaphore.synchronize do
      user_say username, "Deleted access keys", :yellow
    end

    begin
      iam.delete_login_profile(username)
      @io_semaphore.synchronize do
        user_say username, "Deleted user login profile", :yellow
      end
    rescue Fog::AWS::IAM::NotFound
    end

    user_policies_reponse = iam.list_user_policies(username)
    user_policies_reponse.body['PolicyNames'].each do |policy_name|
      iam.delete_user_policy(username, policy_name)
    end
    @io_semaphore.synchronize do
      user_say username, "Deleted user policies", :yellow
    end

    user_response = iam.delete_user(username)
    @io_semaphore.synchronize do
      user_say username, "Deleted user", :yellow
    end
  end

  def write_fog_file(username, user_credentials)
    FileUtils.mkdir_p(username.to_s)
    File.open(File.join(username.to_s, "fog-api.yml"), "w") do |f|
      f << {
        default: user_credentials
      }.to_yaml
    end
    @io_semaphore.synchronize do
      user_say username, "Created fog-api.yml", :green
    end
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
    @io_semaphore.synchronize do
      user_say username, "Created console-passwords.md", :green
    end
  end

  def account_signin_url(aws_compute)
    any_sg = aws_compute.security_groups.first
    account_num = any_sg.owner_id
    "https://#{account_num}.signin.aws.amazon.com/console"
  end

  def destroy_everything(account, aws_region, compute)
    # First, destroy instances
    servers = compute.servers
    original_servers_count = servers.size
    if original_servers_count > 0
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "Destroying #{original_servers_count} instances"
      end
      Parallel.each(servers, in_threads: servers.size) do |server|
        @io_semaphore.synchronize do
          user_say_region account, aws_region, "Destroying #{server.id}"
        end
        server.destroy
        server.wait_for { state == "terminated" }
      end
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "Destroyed #{original_servers_count} instances"
      end
    else
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "No instances to destroy"
      end
    end

    # Destroy elastic IPs
    ips = compute.addresses
    ip_count = ips.size
    if ip_count > 0
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "Destroying #{ip_count} IPs"
      end
      Parallel.each(ips, in_threads: ip_count) do |ip|
        @io_semaphore.synchronize do
          user_say_region account, aws_region, "Destroying #{ip.public_ip}"
        end
        ip.destroy
      end
    else
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "No IP addresses to destroy"
      end
    end

    # Destroy elastic IPs
    ips = compute.addresses
    ip_count = ips.size
    if ip_count > 0
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "Destroying #{ip_count} IPs"
      end
      Parallel.each(ips, in_threads: ip_count) do |ip|
        @io_semaphore.synchronize do
          user_say_region account, aws_region, "Destroying #{ip.public_ip}"
        end
        ip.destroy
      end
    else
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "No IP addresses to destroy"
      end
    end

    # Destroy VPC security groups
    sg = compute.security_groups.select {|v| v.vpc_id}
    if sg.size > 0
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "Destroying #{sg.size} VPC security groups"
      end
      Parallel.each(sg, in_threads: sg.size) do |sg|
        @io_semaphore.synchronize do
          user_say_region account, aws_region, "Destroying #{sg.name}"
        end
        begin
          sg.destroy
        rescue Fog::Compute::AWS::Error
          # quietly ignore SGs we can't delete anyway
        rescue => e
          user_say_region account, aws_region, e.message, :red
        end
      end
    else
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "No VPC security groups to destroy"
      end
    end

    # Destroy subnets
    subnets = compute.subnets
    subnet_count = subnets.size
    if subnet_count > 0
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "Destroying #{subnet_count} subnets"
      end
      Parallel.each(subnets, in_threads: subnet_count) do |subnet|
        @io_semaphore.synchronize do
          user_say_region account, aws_region, "Destroying #{subnet.subnet_id} (#{subnet.cidr_block})"
        end
        subnet.destroy
      end
    else
      @io_semaphore.synchronize do
        user_say_region account, aws_region, "No subnets to destroy"
      end
    end

    # TODO: detach Internet Gtw from VPC
    # TODO: delete IG


    # TODO: figure out how to delete route tables; perhaps detact them first?
    # rts = compute.route_tables
    # @io_semaphore.synchronize do
    #   user_say_region account, aws_region, "Destroying #{rts.size} Route Tables"
    # end
    # retry_rts = ThreadSafe::Array.new
    # Parallel.each(rts, in_threads: rts.size) do |rt|
    #   @io_semaphore.synchronize do
    #     user_say_region account, aws_region, "Destroying #{rt.id}"
    #   end
    #   begin
    #     rt.routes.each do |route|
    #       begin
    #         compute.delete_route(rt.id, route["destinationCidrBlock"])
    #       rescue InvalidParameterValue
    #         # quietly ignore local routes that are implicitly deleted when we destroy rt
    #       end
    #     end
    #     rt.destroy
    #   rescue
    #     retry_rts << rt
    #   end
    # end
    #
    # Parallel.each(retry_rts, in_threads: retry_rts.size) do |rt|
    #   @io_semaphore.synchronize do
    #     user_say_region account, aws_region, "Trying again to destroy #{rt.id}"
    #   end
    #   begin
    #     rt.routes.each do |route|
    #       begin
    #         compute.delete_route(rt.id, route["destinationCidrBlock"])
    #       rescue InvalidParameterValue
    #         # quietly ignore local routes that are implicitly deleted when we destroy rt
    #       end
    #     end
    #     rt.destroy
    #   rescue => e
    #     user_say_region account, aws_region, e.message, :red
    #   end
    # end
    #
    # vpcs = compute.vpcs
    # original_vpc_count = vpcs.size
    # @io_semaphore.synchronize do
    #   user_say_region account, aws_region, "Destroying #{original_vpc_count} VPCs"
    # end
    # Parallel.each(vpcs, in_threads: vpcs.size) do |vpc|
    #   @io_semaphore.synchronize do
    #     user_say_region account, aws_region, "Destroying #{vpc.id} (#{vpc.cidr_block})"
    #   end
    #   begin
    #     vpc.destroy
    #   rescue => e
    #     user_say_region account, aws_region, e.message, :red
    #   end
    # end
  end

  def aws_regions(common_only=true)
    if common_only
      ["us-east-1", "us-west-2"]
    else
      ["eu-central-1", "sa-east-1", "ap-northeast-1",
      "eu-west-1", "us-east-1", "us-west-1", "us-west-2",
      "ap-southeast-2", "ap-southeast-1"]
    end
  end

  # returns { servers: num-of-servers-across-regions }
  def account_summary(credentials)
    region_server_summary = ThreadSafe::Hash.new
    Parallel.each(aws_regions, in_threads: aws_regions.size) do |aws_region|
      compute = Fog::Compute::AWS.new(credentials.merge(region: aws_region))
      count = compute.servers.select {|s| s.state != "terminated" }.size
      region_server_summary[aws_region] = count
    end
    summary = {}
    summary[:servers] = region_server_summary.inject(0) do |count, pair|
      region, servers = pair
      count + servers
    end
    summary
  end
end
