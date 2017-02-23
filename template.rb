#!/usr/bin/env ruby
# coding: ascii-8bit
require 'pwnlib'
require 'fsalib'
include Shellcode

host = 'localhost'
port = 8888

if(ARGV[0] == 'r')
  host = ''
  port = 0
end

PwnTube.open(host, port) do |t|
  # t.debug = true
end
