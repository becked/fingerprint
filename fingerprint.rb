require 'curb'

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

