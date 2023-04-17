#!/usr/bin/env ruby
# frozen_string_literal: true

# BarbeMCR's OpenCipher for Ruby
# An encryption/decryption application designed to obfuscate files and text
# A Ruby API is provided to use in any of your Ruby applications

# DISCLAIMER: BarbeMCR's OpenCipher for Ruby is not meant for actual cryptographic purposes!
# It is not built to protect sensitive information. Use it only for futile work.
# While this application and its underlying API employ some security practices, you shouldn't trust either for securely encrypting things.

# Copyright (c) 2023  BarbeMCR
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# BarbeMCR's OpenCipher for Ruby is an encryption library usable for obfuscating files and text.

# Here is a list of documented methods in the OpenCipher module:
# OpenCipher.encrypt
# OpenCipher.encrypt_string
# OpenCipher.encrypt_key
# OpenCipher.authenticate
# OpenCipher.hash
# OpenCipher.decrypt
# OpenCipher.decrypt_string
# OpenCipher.decrypt_key
# OpenCipher.check_tampering
# OpenCipher.check_hash

# When using any OpenCipher.* method, you should wrap it in a begin-rescue that catches StandardError exceptions.
# This is because methods could raise many different kinds of exceptions, depending on the parameters given.
# For example, if a wrong key is used to decrypt a file, depending on the wrong key contents, different exceptions could be raised.
# In conclusion, wrap code like this:
# begin
#   OpenCipher.<method>(...)
#   ...
# rescue
#   ...
# end

require 'openssl'
require 'securerandom'
require 'stringio'

module OpenCipher
  def self._print_main_menu
    puts "Welcome to BarbeMCR's OpenCipher for Ruby!"
    puts "This is the actual application interface."
    puts %(For the API, write 'require_relative "opencipher"' in a Ruby interpreter or script.)
    puts "DISCLAIMER: do NOT use BarbeMCR's OpenCipher for Ruby for actual cryptographic purposes!"
    puts
    puts "Select an action from the list below:"
    puts "1. Encrypt file"
    puts "2. Decrypt file"
    puts "3. Encrypt user input"
    puts "4. Decrypt user input"
    puts "5. Authenticate and hash encrypted products"
    puts "6. Generate hash from products"
    puts "7. Check tampering (digest validity)"
    puts "8. Check corruption (hash validity)"
    puts "0. Exit"
    print "  ? "
    gets.strip
  end
  def self._encrypt_ui
    puts
    puts "Select a mode from the list below:"
    puts "1. Use single table"
    puts "2. Use multiple tables at single interval"
    puts "3. Use multiple tables at multiple intervals"
    print "  ? "
    choice = gets.strip
    puts
    print "Insert the path to the file to encrypt: "
    file = gets.strip
    print "Insert a secret key to use for authentication: "
    secret = gets.rstrip
    case choice
    when '1'
      encrypt(file, secret, multiple:false)
    when '2'
      encrypt(file, secret, multiple:true, intervals:false)
    when '3'
      encrypt(file, secret, multiple:true, intervals:true)
    else
      puts "Invalid choice. Using single table..."
      encrypt(file, secret)
    end
    puts "Finished!"
  end
  def self._decrypt_ui
    puts
    puts "Select the correct mode for your file from the list below:"
    puts "1. Use single table"
    puts "2. Use multiple tables at single interval"
    puts "3. Use multiple tables at multiple intervals"
    print "  ? "
    choice = gets.strip
    puts
    print "Insert the path to the file to decrypt: "
    file = gets.strip
    print "Insert the path to the file's key: "
    key = gets.strip
    print "Insert the path to the authentication file: "
    auth = gets.strip
    print "Insert the secret key used for authentication: "
    secret = gets.rstrip
    case choice
    when '1'
      decrypt(file, key, auth, secret, multiple:false)
    when '2'
      decrypt(file, key, auth, secret, multiple:true, intervals:false)
    when '3'
      decrypt(file, key, auth, secret, multiple:true, intervals:true)
    else
      puts "Invalid choice. Using single table..."
      decrypt(file, key, auth, secret)
    end
    puts "Finished!"
  end
  def self._encrypt_input_ui
    puts
    puts "Select a mode from the list below:"
    puts "1. Use single table"
    puts "2. Use multiple tables at single interval"
    puts "3. Use multiple tables at multiple intervals"
    print "  ? "
    choice = gets.strip
    puts
    print "Insert a secret key: "
    key = gets.rstrip
    puts
    puts "Now you can type the text (without international characters) you want to encrypt (hit 'return' to end input)."
    text = gets.rstrip
    puts
    case choice
    when '1'
      e = encrypt_string(text, key, multiple:false)
    when '2'
      e = encrypt_string(text, key, multiple:true, intervals:false)
    when '3'
      e = encrypt_string(text, key, multiple:true, intervals:true)
    else
      puts "Invalid choice. Using single table..."
      e = encrypt_string(text, key)
    end
    puts "The encrypted text is:"
    puts e
  end
  def self._decrypt_input_ui
    puts
    puts "Select a mode from the list below:"
    puts "1. Use single table"
    puts "2. Use multiple tables at single interval"
    puts "3. Use multiple tables at multiple intervals"
    print "  ? "
    choice = gets.strip
    puts
    print "Insert the secret key: "
    key = gets.rstrip
    puts
    puts "Now you can type the text you want to decrypt (hit 'return' to end input)."
    text = gets.rstrip
    puts
    case choice
    when '1'
      d = decrypt_string(text, key, multiple:false)
    when '2'
      d = decrypt_string(text, key, multiple:true, intervals:false)
    when '3'
      d = decrypt_string(text, key, multiple:true, intervals:true)
    else
      puts "Invalid choice. Using single table..."
      d = decrypt_string(text, key)
    end
    puts "The decrypted text is:"
    puts d
  end
  def self._authenticate_ui
    puts
    print "Insert the path to the .lock file: "
    file = gets.strip
    print "Insert the path to the .key file: "
    key = gets.strip
    print "Insert the secret key to use: "
    secret = gets.rstrip
    print "Insert the output path (should end with .auth): "
    auth = gets.strip
    authenticate(file, key, auth, secret)
    h = hash(file, key, auth)
    File.write(auth, h, mode:'a')
    puts "Finished!"
  end
  def self._hash_ui
    puts
    print "Insert the path to the .lock file: "
    file = gets.strip
    print "Insert the path to the .key file: "
    key = gets.strip
    print "Insert the path to the .auth file: "
    auth = gets.strip
    h = hash(file, key, auth)
    puts
    puts "The main hash is:"
    puts h
  end
  def self._check_tampering_ui
    puts
    print "Insert the path to the .lock file: "
    file = gets.strip
    print "Insert the path to the .key file: "
    key = gets.strip
    print "Insert the path to the .auth file: "
    auth = gets.strip
    print "Insert the secret key to use: "
    secret = gets.rstrip
    t = check_tampering(file, key, auth, secret)
    if t
      puts
      puts "The files haven't been tampered with."
    else
      puts
      puts "The files HAVE been tampered with."
    end
  end
  def self._check_corruption_ui
    puts
    print "Insert the path to the .lock file: "
    file = gets.strip
    print "Insert the path to the .key file: "
    key = gets.strip
    print "Insert the path to the .auth file: "
    auth = gets.strip
    c = check_hash(file, key, auth)
    if c
      puts
      puts "The files aren't corrupted."
    else
      puts
      puts "The files ARE corrupted."
    end
  end

  # Encrypt a file.
  # Gets called like this:
  # OpenCipher.encrypt(file, secret, [multiple:false], [intervals:false])
  # file: the path to the file to encrypt
  # secret: the secret key used for authentication
  # multiple: whether to use multiple tables
  # intervals: whether to use multiple intervals in multiple tables mode
  # Writes <path>.(lock, key, auth):
  # <path>.lock: the encrypted file
  # <path>.key: the encrypted key to decrypt the file
  # <path>.auth: the digests of the lock and the key and the hash of everything (including the digests)
  def self.encrypt(file, secret, multiple:false, intervals:false)
    raw_key = SecureRandom.random_bytes(SecureRandom.random_number(512)+1).unpack('C*').join.to_i
    prng = Random.new(raw_key)
    table = {}
    (0...256).each do |i|
      loop do
        table[i] = (0...256).to_a.sample(random:prng)
        break unless table.values[...-1].include?(table[i])
      end
    end
    unless multiple
      #File.open(file, 'rb:ASCII-8BIT') do |f|
        #File.open("#{file}.lock", 'wb:ASCII-8BIT') do |o|
      File.open(file, 'rb') do |f|
        File.open("#{file}.lock", 'wb') do |o|
          f.each_byte { |b| o.write([table[b]].pack('C*')) }
        end
      end
    else
      interval = prng.rand((1..16))
      File.open(file, 'rb') do |f|
        File.open("#{file}.lock", 'wb') do |o|
        i = f.size
        f.rewind
        while i > 0
            f.read(interval).unpack('C*').each { |b| o.write([table[b]].pack('C*')) }
            table = {}
            (0...256).each do |n|
              loop do
                table[n] = (0...256).to_a.sample(random:prng)
                break unless table.values[...-1].include?(table[n])
              end
            end
            i -= interval
            interval = prng.rand((1..16)) if intervals
          end
        end
      end
    end
    encrypt_key(raw_key, "#{file}.key", secret)
    authenticate("#{file}.lock", "#{file}.key", "#{file}.auth", secret)
    h = hash("#{file}.lock", "#{file}.key", "#{file}.auth")
    File.write("#{file}.auth", h, mode:'a')
  end

  # Encrypt a string.
  # Gets called like this:
  # OpenCipher.encrypt_string(string, secret, [multiple:false], [intervals:false])
  # string: the string to encrypt
  # secret: the secret key used for authentication
  # multiple: whether to use multiple tables
  # intervals: whether to use multiple intervals in multiple tables mode
  # Return the encrypted string.
  def self.encrypt_string(string, secret, multiple:false, intervals:false)
    prng = Random.new(secret.unpack('C*').join.to_i)
    table = {}
    (0...256).each do |i|
      loop do
        table[i] = (0...256).to_a.sample(random:prng)
        break unless table.values[...-1].include?(table[i])
      end
    end
    array_enc_string = []
    bstring = string.unpack('C*')
    unless multiple
      bstring.each { |b| array_enc_string << '0x'+table[b].to_s(16) }
    else
      interval = prng.rand((1..16))
      i = string.size
      p_ = 0
      while i > 0
        bstring[p_...p_+interval].each { |b| array_enc_string << '0x'+table[b].to_s(16) }
        table = {}
        (0...256).each do |n|
          loop do
            table[n] = (0...256).to_a.sample(random:prng)
            break unless table.values[...-1].include?(table[n])
          end
        end
        i -= interval
        p_ += interval
        interval = prng.rand((1..16)) if intervals
      end
    end
    array_enc_string.join(':')
  end

  # Encrypt an OpenCipher key.
  # Gets called like this:
  # OpenCipher.encrypt_key(raw_key, key, secret)
  # raw_key: the unencrypted key object (the prng seed)
  # key: the path to write the encrypted key to
  # secret: the secret key used for authentication
  # Writes <path>.key: the encrypted key
  def self.encrypt_key(raw_key, key, secret)
    prng = Random.new(secret.unpack('C*').join.to_i)
    table = {}
    (0...256).each do |i|
      loop do
        table[i] = (0...256).to_a.sample(random:prng)
        break unless table.values[...-1].include?(table[i])
      end
    end
    File.open(key, 'wb') do |k|
      Marshal.dump(raw_key).each_byte { |b| k.write([table[b]].pack('C*')) }
    end
  end

  # Decrypt a file.
  # Gets called like this:
  # OpenCipher.decrypt(file, key, auth, secret, [multiple:false], [intervals:false])
  # file: the path to the file to decrypt
  # key: the path to key used to decrypt the file
  # auth: the path to the authentication file
  # secret: the secret key used for authentication
  # multiple: whether to use multiple tables
  # intervals: whether to use multiple intervals in multiple tables mode
  # Writes <path> from <path>.lock
  def self.decrypt(file, key, auth, secret, multiple:false, intervals:false)
    if check_hash(file, key, auth) && check_tampering(file, key, auth, secret)
      raw_key = decrypt_key(key, secret)
      prng = Random.new(raw_key)
      table = {}
      (0...256).each do |i|
        loop do
          table[i] = (0...256).to_a.sample(random:prng)
          break unless table.values[...-1].include?(table[i])
        end
      end
      unless multiple
        File.open(file, 'rb') do |o|
          File.open(file.delete_suffix('.lock'), 'wb') do |f|
            o.each_byte do |b|
              table.each { |k, v| f.write([k].pack('C*')) if b == v }
            end
          end
        end
      else
        interval = prng.rand((1..16))
        File.open(file, 'rb') do |o|
          File.open(file.delete_suffix('.lock'), 'wb') do |f|
            i = o.size
            o.rewind
            while i > 0
              o.read(interval).unpack('C*').each do |b|
                table.each { |k, v| f.write([k].pack('C*')) if b == v }
              end
              table = {}
              (0...256).each do |n|
                loop do
                  table[n] = (0...256).to_a.sample(random:prng)
                  break unless table.values[...-1].include?(table[n])
                end
              end
              i -= interval
              interval = prng.rand((1..16)) if intervals
            end
          end
        end
      end
    end
  end

  # Decrypt a string.
  # Gets called like this:
  # OpenCipher.decrypt_string(enc_string, secret, [multiple:false], [intervals:false])
  # enc_string: the string to decrypt
  # secret: the secret key used for authentication
  # multiple: whether to use multiple tables
  # intervals: whether to use multiple intervals in multiple tables mode
  # Return the decrypted string.
  def self.decrypt_string(enc_string, secret, multiple:false, intervals:false)
    prng = Random.new(secret.unpack('C*').join.to_i)
    table = {}
    (0...256).each do |i|
      loop do
        table[i] = (0...256).to_a.sample(random:prng)
        break unless table.values[...-1].include?(table[i])
      end
    end
    bstring = enc_string.split(':')
    array_string = []
    unless multiple
      bstring.each do |b|
        table.each { |k, v| array_string << k if b.delete_prefix('0x').to_i(16) == v }
      end
    else
      interval = prng.rand((1..16))
      i = enc_string.size
      p_ = 0
      while i > 0
        bstring[p_...p_+interval].each do |b|
          table.each { |k, v| array_string << k if b.delete_prefix('0x').to_i(16) == v }
        end unless bstring[p_...p_+interval].nil?
        table = {}
        (0...256).each do |n|
          loop do
            table[n] = (0...256).to_a.sample(random:prng)
            break unless table.values[...-1].include?(table[n])
          end
        end
        i -= interval
        p_ += interval
        interval = prng.rand((1..16)) if intervals
      end
    end
    string = array_string.pack('C*')
  end

  # Decrypt an OpenCipher key.
  # Gets called like this:
  # OpenCipher.decrypt_key(key, secret)
  # key: the path to read the encrypted key from
  # secret: the secret key used for authentication
  # Return raw_key (an unencrypted prng seed).
  def self.decrypt_key(key, secret)
    prng = Random.new(secret.unpack('C*').join.to_i)
    table = {}
    r = StringIO.open(mode:'w+b')
    (0...256).each do |i|
      loop do
        table[i] = (0...256).to_a.sample(random:prng)
        break unless table.values[...-1].include?(table[i])
      end
    end
    File.open(key, 'rb') do |e|
      e.each_byte do |b|
        table.each { |k, v| r.write([k].pack('C*')) if b == v }
      end
    end
    r.rewind
    raw_key = Marshal.load(r.read)
  end

  # Generate digests for lock and key with secret.
  # Gets called like this:
  # OpenCipher.authenticate(lock, key, auth, secret)
  # lock: the path to the encrypted file
  # key: the path to the encrypted key to the encrypted file
  # auth: the path to write the digests to
  # secret: the secret key to use
  # Writes <path>.auth: the digests storage
  def self.authenticate(lock, key, auth, secret)
    lock_digest = nil
    key_digest = nil
    File.open(lock, 'rb') do |l|
      File.open(key, 'rb') do |k|
        lock_digest = OpenSSL::HMAC.hexdigest('SHA512', secret, l.read)
        key_digest = OpenSSL::HMAC.hexdigest('SHA512', secret, k.read)
      end
    end
    File.open(auth, 'w') do |a|
      a.write(lock_digest)
      a.write(key_digest)
    end
  end

  # Generate a single hash for lock, key and auth.
  # Gets called like this:
  # OpenCipher.hash(lock, key, auth)
  # lock: the path to the encrypted file
  # key: the path to the encrypted key to the encrypted file
  # auth: the path to the digests
  # Return h: the computed SHA-512 hash
  def self.hash(lock, key, auth)
    all = nil
    File.open(lock, 'rb') do |l|
      File.open(key, 'rb') do |k|
        File.open(auth, 'rb') do |a|
          all = l.read + k.read + a.read(256)
        end
      end
    end
    h = OpenSSL::Digest.digest('SHA512', all)
  end

  # Compare actual digests with stored digests for lock and key.
  # Gets called like this:
  # OpenCipher.check_tampering(lock, key, auth, secret)
  # lock: the path to the encrypted file
  # key: the path to the encrypted key to the encrypted file
  # auth: the path to read the digests from
  # secret: the secret key to use
  # Return true if the digests are the same or false if they aren't.
  def self.check_tampering(lock, key, auth, secret)
    stored_lock_digest = nil
    stored_key_digest = nil
    lock_digest = nil
    key_digest = nil
    File.open(auth, 'r') do |a|
      a.rewind
      stored_lock_digest = a.read(128)
      a.seek(128)
      stored_key_digest = a.read(128)
    end
    File.open(lock, 'rb') do |l|
      File.open(key, 'rb') do |k|
        lock_digest = OpenSSL::HMAC.hexdigest('SHA512', secret, l.read)
        key_digest = OpenSSL::HMAC.hexdigest('SHA512', secret, k.read)
      end
    end
    stored_lock_digest==lock_digest && stored_key_digest==key_digest
  end

  # Compare actual hash with stored hash for lock, key and auth.
  # Gets called like this:
  # OpenCipher.check_hash(lock, key, auth)
  # lock: the path to the encrypted file
  # key: the path to the encrypted key to the encrypted file
  # auth: the path to the digests
  # Return true if the hashes are the same or false if they aren't.
  def self.check_hash(lock, key, auth)
    stored_h = nil
    all = nil
    File.open(auth, 'r') do |a|
      a.seek(256)
      stored_h = a.read(128).delete("\r")
    end
    File.open(lock, 'rb') do |l|
      File.open(key, 'rb') do |k|
        File.open(auth, 'rb') do |a|
          a.rewind
          all = l.read + k.read + a.read(256)
        end
      end
    end
    h = OpenSSL::Digest.digest('SHA512', all).delete("\r")
    stored_h == h
  end
end

if __FILE__ == $0
  choice = OpenCipher._print_main_menu
  case choice
  when '1'
    OpenCipher._encrypt_ui
  when '2'
    OpenCipher._decrypt_ui
  when '3'
    OpenCipher._encrypt_input_ui
  when '4'
    OpenCipher._decrypt_input_ui
  when '5'
    OpenCipher._authenticate_ui
  when '6'
    OpenCipher._hash_ui
  when '7'
    OpenCipher._check_tampering_ui
  when '8'
    OpenCipher._check_corruption_ui
  else
    exit
  end
end
