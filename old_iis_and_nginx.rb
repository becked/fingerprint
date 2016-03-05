#!/usr/bin/env ruby

# Print URLs (and whether they are directory listable) that are:
#   NGINX version 1.2 or IIS version 7.0

require 'csv'
require 'optparse'
require_relative 'fingerprint'

# Get a list of URLs from the command line through a file or as an argument
urls = []
file = nil
ARGV.options do |opts|
  opts.on('-f', '--file FILENAME', "File with a list of URLs or IP addreses, one per line") { |f| file = f }
  opts.on("--urls 10.1.2.3,example.com", Array, "Comma separated list of URLs or IP Addresses to fingerprint") { |url| urls = url }
  opts.parse!
end
urls = CSV.read(file).flatten if file
if urls.empty?
  puts "A list of URLs or IP addresses is required to run." if urls.empty?
  exit
end

# Loop through the URLs printing when we match
urls.each do |url|
  fingerprint = Fingerprint.new(url)
  vendor = fingerprint.vendor
  version = fingerprint.send("#{vendor}_version".to_sym)
  directory_listable = fingerprint.directory_listable? ? "Directory listable - " : " "
  if vendor == "IIS" and version =~ /^7\.0/
    puts "IIS version 7.0 - " + directory_listable + url
  elsif vendor == "NGINX" and version =~ /^1\.2/
    puts "NGINX version 1.2 - " + directory_listable + url
  end
end


