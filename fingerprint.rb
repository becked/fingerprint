require 'csv'
require 'curb'
require 'optparse'

class Fingerprint
  attr_reader :body, :headers

  # Use regexes for server types and versions
  IIS = /Microsoft-IIS\/([\d\.]+)/i
  NGINX = /nginx\/([\d\.]+)/i

  # Fingerprint uses Curl (through the Ruby Curb gem) to fingerprint a web server
  # We use Curl since it doesn't mind an IP address and it's fast and ubiquitous.
  # Unfortunately, the Curb gem doesn't nicely parse HTTP headers into a hash, so
  # we need to do this ourselves from the header_str using regexes.
  def initialize(url)
    curl = Curl::Easy.http_get(url)
    @body = curl.body_str
    response, *headers = curl.header_str.split(/[\r\n]+/).map(&:strip)
    @headers = Hash[headers.flat_map{ |s| s.scan(/^(\S+): (.+)/) }]
  end
  
  def vendor
    return "IIS" if @headers["Server"].match(IIS)
    return "NGINX" if @headers["Server"].match(NGINX)
    @headers["Server"].capitalize
  end

  # Seems like web directory listings always have this link near the top
  def directory_listable?
    @body.match(/\[To Parent Directory\]<\/A>/i)
  end

  # Dynamically determine server version if we have a regex to match with.
  def method_missing(method, *arguments, &block)
    super unless method.to_s =~ /(\w+)_version$/
    begin
      regex = Object.const_get("Fingerprint::#{$1.upcase}")
      return unless server = @headers["Server"].match(regex)
      server[1] 
    rescue
      #super
    end
  end
end

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

# Print URLs (and whether they are directory listable) that are:
#   NGINX version 1.2 or IIS version 7.0
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


