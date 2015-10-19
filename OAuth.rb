require 'uri'
require 'base64'
require 'openssl'

# To use this formula just pass in your consumer key, consumer secret, URL you're 
# requesting and finally the params you want to pass in as a hash. 

def sign(key, secret, request_url, hash_params = {}, token_secret = nil, token = nil)
	tstamp = generate_timestamp
	nonce = generate_nonce

	parameters = {
		"oauth_signature_method" => 'HMAC-SHA1',
		"oauth_consumer_key" => key,
		"oauth_timestamp" => tstamp,
		"oauth_nonce" => nonce,
		"oauth_version" => '1.0',
		"oauth_token" => token
	}

	sorted_hash = {}
	params_keys = hash_params.keys.sort

	params_keys.each do |param_key|
		sorted_hash.merge!(Hash[CGI.escape(param_key), CGI.escape(hash_params[param_key])])
	end

	sorted_keys = parameters.keys.sort

	sorted_keys.each do |sorted_key|
		sorted_hash.merge!(Hash[CGI.escape(sorted_key), CGI.escape(parameters[sorted_key])])
	end

	output_string = sorted_hash.keys.map {|k| "#{k}=#{sorted_hash[k]}"}.join('&')
	
	sig_string = "POST&#{CGI.escape(request_url)}&#{CGI.escape(output_string)}"
	sig_key = "#{CGI.escape(secret)}&"
	digester = OpenSSL::Digest.new('sha1')
	hmac_code = OpenSSL::HMAC.digest(digester, sig_key, sig_string)
	finished_sig = Base64.encode64(hmac_code).chomp.gsub(/\n/, '')

  return output_string + '&oauth_signature=' + CGI.escape(finished_sig)
end

# Generate a one time unique nonce
def generate_nonce
	OpenSSL::Random.random_bytes(16).unpack('H*')[0]
end

# Generates a timestamp for the current time
def generate_timestamp
	Time.now.to_i.to_s
end