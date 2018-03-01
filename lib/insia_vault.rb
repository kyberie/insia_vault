require 'insia_vault/version'
require 'fiddle'
require 'vault'

module InsiaVault

  DEFAULT_TIMEOUT = 660

  @@pid_originator = nil
  @@pid_renewer = nil
  @@pipe_rd = nil
  @@pipe_wr = nil
  @@prctl = nil
  @@main_token = nil
  @@wrapped_token = nil
  @@got_token = false
  @@pwd = nil

  def self.pipe_wr
    @@pipe_wr
  end

  def self.pid_originator
    @@pid_originator
  end

  def self.pid_renewer
    @@pid_renewer
  end

  def self.main_token
    @@main_token
  end



  def self.alert(*s)
    begin
      IO.popen(['/etc/vault/gem_alert.sh', @@pwd.to_s, @@pid_originator.to_s, @@pid_renewer.to_s], mode='w') {|io|
        io.write(s.join("\n") + "\n\n")
        io.flush()
      }
    rescue
    end

  end


  def self.add_token(token, ttl=0)
    @@main_token ||= token
    if @@pipe_wr != nil then
      @@pipe_wr.syswrite('token ' + token.to_s + ' ' + ttl.to_s + "\n") rescue nil
    end
  end


  def self.add_lease(lease, ttl=0)
    if @@pipe_wr != nil then
      @@pipe_wr.syswrite('lease ' + lease.to_s + ' ' + ttl.to_s + "\n") rescue nil
    end
  end


  def self.log(msg)
    if @@pipe_wr != nil then
      @@pipe_wr.syswrite('log ' + msg.strip().gsub("\n", "\0") + "\n") rescue nil
    end
  end


  def self.setup_token
    if ENV['RAILS_ENV'] != 'production' then
      if Vault.token != nil then
        self.add_token(Vault.token)
        @@got_token = true
        return 1
      end
    end

    token = ttl = nil

    if @@wrapped_token != nil then
      token, ttl = self.unwrap_token(@@wrapped_token)
    elsif ENV['VAULT_WRAPPED_TOKEN_STDIN'] != nil then
      line = $stdin.gets()
      token, ttl = self.unwrap_token(line.chomp().strip()) if line
    end

    if token == nil || ttl == nil then
      token = ttl = nil
      env = ENV['VAULT_WRAPPED_TOKEN']
      if (env != nil) then
        token, ttl = self.unwrap_token(env)
      end
    end

    if token == nil || ttl == nil then
      token = ttl = nil
      env = ENV['VAULT_WRAPPED_TOKEN_FILE']
      if (env != nil) then
        if File.exists?(env) then
          line = File.read(env)
          token, ttl = self.unwrap_token(line.chomp().strip()) if line
        end
      end
    end

    if token != nil && ttl != nil then
      Vault.token = token
      self.add_token(token, ttl)
      @@got_token = true
      return 1
    end

    msg='Cannot obtain wrapped token!'
    $stderr.puts(msg)
    self.log(msg)
    exit!(1)
  end


  def self.early_stdin
    line = $stdin.gets()
    @@wrapped_token ||= line.chomp().strip() if line
  end


  # https://www.vaultproject.io/docs/concepts/response-wrapping.html#response-wrapping-token-validation
  def self.unwrap_token(wrapped)
    resp=nil
    old_token=Vault.token
    Vault.token = nil
    begin
      # do a lookup to check the token exists and the path checks
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        resp = Vault.logical.write('sys/wrapping/lookup', token: wrapped)
      end
      cr_path = resp.data[:creation_path]
      if !(cr_path == 'auth/approle/login' || cr_path == 'auth/cert/login' || cr_path =~ /^auth\/token\/create\/[^\/]+$/) then
        msg = "Suspicious creation_path '" + cr_path + "' on wrapped token" 
        $stderr.puts(msg)
        self.log(msg)
        self.alert(msg)
        exit!(1)
      end
      # extract creation time to determine real TTL
      cr_time = Time.parse(resp.data[:creation_time])
      # actually unwrap the token
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        Vault.token = wrapped
        resp = Vault.logical.write('sys/wrapping/unwrap')
      end
      # rescue Vault::HTTPClientError => e
      #   Vault.token = old_token
      #   return nil, nil
    rescue Exception => e
      msg = 'sys/wrapping/lookup failed'
      $stderr.puts(msg)
      self.log(msg)
      self.alert(msg, e.message, caller.join("\n"))
      return nil, nil
    ensure
      Vault.token = old_token
    end

    ttl = resp.auth.lease_duration - (Time.now() - cr_time).to_i

    msg = 'OK unwrapped token with ttl ' + ttl.to_s + ', policies: ' + resp.auth.policies.join(', ')
    $stderr.puts(msg)
    self.log(msg)
    msg = 'OK metadata: ' + resp.auth.metadata.to_json()
    $stderr.puts(msg)
    self.log(msg)
    Vault.token ||= resp.auth.client_token

    return resp.auth.client_token, ttl
  end


  def self.get_token_ttl(token)
    resp=nil
    old_token=Vault.token()
    Vault.token = token
    ttl=0
    begin
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        resp = Vault.logical.read('auth/token/lookup-self')
      end
      ttl = resp.data[:ttl]
    rescue Exception => e
      msg = 'auth/token/lookup-self failed'
      $stderr.puts(msg)
      self.alert(msg, e.message, caller.join("\n"))
      exit!(1)
    ensure
      Vault.token = old_token
    end

    puts('OK token ttl = ' + ttl.to_s)
    return ttl
  end


  def self.renew_token(token)
    resp=nil
    old_token=Vault.token()
    Vault.token = token
    ttl=nil
    begin
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        resp = Vault.logical.write('auth/token/renew-self')
      end
      ttl = resp.auth.lease_duration
    rescue Exception => e
      msg = 'auth/token/renew-self failed'
      $stderr.puts(msg)
      self.alert(msg, e.message, caller.join("\n"))
      exit!(1)
    ensure
      Vault.token = old_token
    end

    puts('OK renewed token for ' + ttl.to_s + ' seconds')
    return ttl
  end


  def self.revoke_token(token)
    resp=nil
    old_token=Vault.token()
    Vault.token = token
    begin
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        resp = Vault.logical.write('auth/token/revoke-self')
      end
    rescue Exception => e
      $stderr.puts('auth/token/revoke-self failed')
    ensure
      Vault.token = old_token
    end

    puts('OK revoked token')
  end


  def self.get_lease_ttl(lease)
    resp=nil
    ttl=0
    base=lease.split('/')[0..-2].join('/')
    begin
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        resp = Vault.logical.write('sys/leases/lookup', lease_id: lease)
      end
      ttl = resp.data[:ttl]
    rescue Exception => e
      msg = 'sys/leases/lookup for ' + base + ' failed'
      $stderr.puts(msg)
      self.alert(msg, e.message, caller.join("\n"))
      exit!(1)
    end

    puts('OK lease ' + base + ' ttl = ' + ttl.to_s)
    return ttl
  end


  def self.renew_lease(lease)
    resp=nil
    ttl=nil
    base=lease.split('/')[0..-2].join('/')
    begin
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        resp = Vault.logical.write('sys/leases/renew', lease_id: lease)
      end
      ttl = resp.lease_duration
    rescue Exception => e
      msg = 'sys/leases/renew failed for ' + base + ' failed'
      $stderr.puts(msg)
      self.alert(msg, e.message, caller.join("\n"))
      exit!(1)
    end

    puts('OK renewed lease ' + base + ' for '  + ttl.to_s + ' seconds')
    return ttl
  end


  # t, a = InsiaVault.fetch_wrapped_token('auth/token/create/wrapped_deploy_tool', { meta: { 'deploy_' => '' }}, { wrap_ttl: 60 } )
  # this is kinda universal, as it should be able to serve auth/approle/login as well
  def self.fetch_wrapped_token(path, data = {}, options = {})
    resp=nil
    begin
      Vault.with_retries(Vault::HTTPServerError, Vault::HTTPConnectionError, attempts: 5, base: 0.5, max_wait: 5) do
        # Vault.auth_token.create_with_role('wrapped_deploy_tool', meta: { 'a' => '1', 'b' => '2' }, wrap_ttl: 100
        # resp = Vault.auth_token.create_with_role(path, data)
        # Vault.logical.write('auth/token/create/wrapped_deploy_tool', { meta: { 'a' => '1', 'b' => '2' }}, wrap_ttl: 100)
        resp = Vault.logical.write(path, data, options)
      end
    rescue Exception => e
      msg = 'fetch_wrapped_token ' + path + ' failed'
      $stderr.puts(msg)
      self.log(msg)
      self.alert(msg, e.message, caller.join("\n"))
      return nil, nil
    end
    return resp.wrap_info.token, resp.wrap_info.wrapped_accessor
  end


  def self.init
    @@pwd ||= Dir.pwd()
    if @@prctl == nil then
      libc ||= Fiddle.dlopen(nil) rescue nil
      @@prctl ||= Fiddle::Function.new(libc['prctl'], [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG], Fiddle::TYPE_INT) rescue nil
      @@prctl.call(4, 0, 0, 0, 0) rescue nil
    end
  end


  def self.start_renewer
    @@pid_originator=Process.pid().to_s
    @@pipe_rd, @@pipe_wr = IO.pipe()
    @@pipe_rd.binmode()
    @@pipe_wr.binmode()
    pipe2_rd, pipe2_wr = IO.pipe()
    pipe2_rd.binmode()
    pipe2_wr.binmode()


    # XXX iterate over /proc/(p)pid/status and /proc/pid/cmdline (up to init)

    pid1 = fork()

    if pid1 != nil
      @@pipe_rd.close()
      pipe2_wr.close()
      # prevent a zombie
      Process.waitpid(pid1)
      # get renewer pid
      @@pid_renewer = pipe2_rd.sysread(100) rescue nil
      pipe2_rd.close()
      return
    else
      @@pipe_wr.close()
      pipe2_rd.close()

      pid2 = fork()
      self.after_fork()
      if pid2 != nil then
        exit! 0
      end

      @@pid_renewer = Process.pid().to_s
      pipe2_wr.syswrite(@@pid_renewer) rescue nil
      pipe2_wr.flush() rescue nil
      pipe2_wr.close() rescue nil

      # Tried using thuehlinger/daemons, but it closes the pipe. And monkey patching it was possibly even uglier.
      # The closing stuff is inspired by Daemonize.close_io()
      require 'daemons'
      require 'daemons/syslogio'

      begin; $stdin.reopen '/dev/null'; rescue ::Exception; end
      begin; $stdout.reopen '/dev/null'; rescue ::Exception; end
      begin; $stderr.reopen '/dev/null'; rescue ::Exception; end

      ObjectSpace.each_object(IO) do |io|
        ObjectSpace.each_object(IO) do |io|
          unless [$stdin, $stdout, $stderr, @@pipe_rd].include?(io)
            io.close() rescue nil
          end
        end
      end

      3.upto(20) do |i|
        unless i == @@pipe_rd.fileno()
          IO.for_fd(i).close() rescue nil
        end
      end

      $stdout = ::Daemons::SyslogIO.new('renewer_' + @@pid_originator, :local1, :info, :PID, $stdout)
      $stderr = ::Daemons::SyslogIO.new('renewer_' + @@pid_originator, :local1, :err, :PID, $stderr)

      Process.setsid() rescue nil
      Process.setproctitle('renewer_' + @@pid_originator)
      Dir.chdir('/')
      trap 'SIGHUP', 'IGNORE'
      trap 'SIGPIPE', 'IGNORE'

      puts('OK starting renewer (' + @@pid_renewer + ') for PID ' + @@pid_originator + ' in ' + @@pwd)

      got_eof=0
      buf=''
      leases = Hash.new()
      tokens = Hash.new()
      last_check = Time.now()
      minttl = DEFAULT_TIMEOUT
      partial = 0

      # the main loop
      loop do
        puts('OK will select for up to ' + minttl.to_s + ' seconds')
        err = IO.select([@@pipe_rd], nil, nil, minttl)
        begin
          loop do
            buf += @@pipe_rd.read_nonblock(4096)
          end
        rescue IO::WaitReadable
          #puts('OK IO::WaitReadable ' + pokus.to_s)
        rescue EOFError
          got_eof=1
        end

        now = Time.now()
        timediff = (now - last_check).to_i
        puts('OK timediff ' + timediff.to_s)

        lines = buf.each_line("\n") do |line|
          # partial line
          if(line[-1] != "\n") then
            buf = line
            partial = 1
          # whole line -> parse
          else
            partial=0
            if line.start_with?('log ') then 
              puts(line[4..-1].gsub("\0", "\n"))
            else
              cols = line.split(' ')
              if cols[0] == 'lease' && cols[2] =~ /^[0-9]+$/ then
                  puts('OK got a lease ' + cols[1].split('/')[0..-2].join('/') + ' with ttl ' + cols[2])
                  val = cols[2].to_i()
                  val += timediff if val != 0
                  leases[cols[1]] = val
              elsif cols[0] == 'token' && cols[2] =~ /^[0-9]+$/
                  puts('OK got a token with ttl ' + cols[2])
                  val = cols[2].to_i()
                  val += timediff if val != 0
                  tokens[cols[1]] = val
                  Vault.token ||= cols[1]
                  @@main_token ||= cols[1]
              end
            end
          end
        end

        break if got_eof == 1

        buf = '' if partial == 0   
        minttl = DEFAULT_TIMEOUT

        # check tokens
        tokens.each() do |token, ttl|
          ttl = ttl.to_i
          if(ttl == 0) then
            ttl = tokens[token] = self.get_token_ttl(token)
          else
            ttl = tokens[token] = tokens[token] - timediff
          end

          puts('OK token ttl ' + ttl.to_s)

          if (ttl < (DEFAULT_TIMEOUT + 60)) then
            puts('OK token ttl ' + ttl.to_s + ', will renew now')
            ttl = tokens[token] = self.renew_token(token)
          end

          minttl = ttl if ttl < minttl
        end

        # check leases
        leases.each() do |lease, ttl|
          ttl = ttl.to_i
          if(ttl == 0) then
            ttl = leases[lease] = self.get_lease_ttl(lease)
          else
            ttl = leases[lease] = leases[lease] - timediff
          end

          base = lease.split('/')[0..-2].join('/')
          puts('OK lease ' + base + ' ttl ' + ttl.to_s)

          if (ttl < (DEFAULT_TIMEOUT + 60)) then
            puts('OK lease ' + base + ' ttl ' + ttl.to_s + ', will renew now')
            ttl = leases[lease] = self.renew_lease(lease)
          end

          minttl = ttl if ttl < minttl
        end

        minttl -= 60
        minttl = 60 if minttl < 10
        minttl = DEFAULT_TIMEOUT if minttl > DEFAULT_TIMEOUT

        last_check = now

      end

      # revoke tokens. their leases should be revoked automatically
      if ENV['RAILS_ENV'] == 'production' then
        tokens.each_key() do |token|
           self.revoke_token(token)
        end
      end
      puts('OK renewer exit')
      exit! 0
    end
  end # start_renewer()


  def self.after_fork
    # only root will be able to ptrace() this process or read many /proc/pid/ files
    # prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    @@prctl.call(4, 0, 0, 0, 0) rescue nil
  end


  # XXX ugly?
  self.init()

end

