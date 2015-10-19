require 'uri'
require 'base64'
require 'openssl'

 
class Signer

	# To use this formula just pass in your consumer key, consumer secret, URL you're 
	# requesting and finally the params you want to pass in as a hash.
	# The of return of sign is your completed OAuth body. 

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

		# This sorts the hash params if any were passed in
		params_keys.each { |param_key| sorted_hash.merge!(Hash[CGI.escape(param_key), CGI.escape(hash_params[param_key])]) }

		#This sorts the parameters defined above that oauth needs
		sorted_keys = parameters.keys.sort

		sorted_keys.each { |sorted_key| sorted_hash.merge!(Hash[CGI.escape(sorted_key), CGI.escape(parameters[sorted_key])]) }

		output_string = sorted_hash.keys.map {|k| "#{k}=#{sorted_hash[k]}"}.join('&')
		
		sig_string = "POST&#{CGI.escape(request_url)}&#{CGI.escape(output_string)}"

		# If you don't need a token secret, this will skip it but the & is necessary.

		sig_key = "#{CGI.escape(secret)}&#{CGI.escape(token_secret) if token_secret != nil)}"
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
end
