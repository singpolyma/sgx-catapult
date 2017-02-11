#!/usr/bin/env ruby
#
# Copyright (C) 2017  Denver Gingerich <denver@ossguy.com>
#
# This file is part of sgx-catapult.
#
# sgx-catapult is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# sgx-catapult is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with sgx-catapult.  If not, see <http://www.gnu.org/licenses/>.

$stdout.sync = true

puts "Soprani.ca/MMS Proxy for XMPP - Catapult        v0.005\n\n"

require 'goliath'
require 'net/http'
require 'redis/connection/hiredis'
require 'uri'

if ARGV.size != 3 then
	puts "Usage: mpx-catapult.rb <http_listen_port> " +
		"<redis_hostname> <redis_port>"
	exit 0
end

t = Time.now
puts "LOG %d.%09d: starting...\n\n" % [t.to_i, t.nsec]

class WebhookHandler < Goliath::API
	def response(env)
		puts 'ENV: ' + env.to_s
		puts 'path: ' + env['REQUEST_PATH']
		puts 'method: ' + env['REQUEST_METHOD']
		puts 'BODY: ' + Rack::Request.new(env).body.read

		cred_key = "catapult_cred-"+env['REQUEST_PATH'].split('/', 3)[1]

		# TODO: connect at start of program instead
		conn = Hiredis::Connection.new
		begin
			conn.connect(ARGV[1], ARGV[2].to_i)
		rescue => e
			puts 'ERROR: Redis connection failed: ' + e.inspect
			return [500, {'Content-Type' => 'text/plain'},
				e.inspect]
		end

		conn.write ["EXISTS", cred_key]
		if conn.read == 0
			conn.disconnect

			puts 'ERROR: invalid path rqst: ' + env['REQUEST_PATH']
			return [404, {'Content-Type' => 'text/plain'},
				'not found']
		end

		conn.write ["LRANGE", cred_key, 0, 3]
		# we don't actually use users_num, but easier to read so left in
		user_id, api_token, api_secret, users_num = conn.read
		conn.disconnect

		uri = URI.parse('https://api.catapult.inetwork.com')
		http = Net::HTTP.new(uri.host, uri.port)
		http.use_ssl = true
		request = ''
		if env['REQUEST_METHOD'] == 'GET'
			request = Net::HTTP::Get.new('/v1/users/' + user_id +
				'/media/' +env['REQUEST_PATH'].split('/', 3)[2])
		elsif env['REQUEST_METHOD'] == 'HEAD'
			request = Net::HTTP::Head.new('/v1/users/' + user_id +
				'/media/' +env['REQUEST_PATH'].split('/', 3)[2])
		else
			puts 'ERROR: received non-HEAD/-GET request'
			return [500, {'Content-Type' => 'text/plain'},
				e.inspect]
		end
		request.basic_auth api_token, api_secret
		response = http.request(request)

		puts 'API response to send: ' + response.to_s + ' with code ' +
			response.code + ', body <omitted_due_to_length>'

		if response.code != '200'
			puts 'ERROR: unexpected return code ' + response.code

			if response.code == '404'
				return [404, {'Content-Type' => 'text/plain'},
					'not found']
			end

			return [response.code, {'Content-Type' => 'text/plain'},
				'unexpected error']
		end

		# TODO: maybe need to reflect more headers (multi-part?)
		[200, {'Content-Length' => response['content-length']},
			response.body]
	end
end

EM.run do
	server = Goliath::Server.new('0.0.0.0', ARGV[0].to_i)
	server.api = WebhookHandler.new
	server.app = Goliath::Rack::Builder.build(server.api.class, server.api)
	server.logger = Log4r::Logger.new('goliath')
	server.logger.add(Log4r::StdoutOutputter.new('console'))
	server.logger.level = Log4r::INFO
	server.start
end
