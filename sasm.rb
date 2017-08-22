#!/usr/bin/env ruby
require 'keystone'

class Sasm
  
  include Keystone
  attr_accessor :arch, :path
  
  def initialize(arch, syntax = nil)
    
    @arch = arch
    
    case arch
        
    when :x86
      @ks = Ks.new(KS_ARCH_X86, KS_MODE_32)
    when :x64
      @ks = Ks.new(KS_ARCH_X86, KS_MODE_64)
    when :arm
      @ks = Ks.new(KS_ARCH_ARM, KS_MODE_ARM)
    when :armbe
      @ks = Ks.new(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN)
    when :thumb
      @ks = Ks.new(KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB)
    when :thumbbe
      @ks = Ks.new(KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN)
    when :arm64
      @ks = Ks.new(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    when :mips
      @ks = Ks.new(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
    when :mipsel
      @ks = Ks.new(KS_ARCH_MIPS, KS_MODE_MIPS32)
    when :mips64
      @ks = Ks.new(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN)
    when :mips64el
      @ks = Ks.new(KS_ARCH_MIPS, KS_MODE_MIPS64)
    end
    @ks.syntax = syntax unless syntax.nil?
  end

  def as(code)
    encoding, count = @ks.asm(code)
    result = ""
    encoding.each_char do |i|
      result += "\\x%02x" % i.ord
    end
  end
  
end


