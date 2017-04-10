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

puts "Soprani.ca/MMS Proxy for XMPP - Catapult\n"\
	"==>> last commit of this version is " + `git rev-parse HEAD` + "\n"

require 'em-hiredis'
require 'em-http-request'
require 'goliath'
require 'uri'

require_relative 'em_promise'

t = Time.now
puts "LOG %d.%09d: starting...\n\n" % [t.to_i, t.nsec]

EM.next_tick do
	REDIS = EM::Hiredis.connect
end

class WebhookHandler < Goliath::API
	def media_request(env, user_id, token, secret, method, media_id)
		if ![:get, :head].include?(method)
			env.logger.debug 'ERROR: received non-HEAD/-GET request'
			return EMPromise.reject(405)
		end

		EM::HttpRequest.new(
			"https://api.catapult.inetwork.com/v1/users/"\
			"#{user_id}/media/#{media_id}"
		).public_send(
			method,
			head: {
				'Authorization' => [token, secret]
			}
		).then { |http|
			env.logger.debug "API response code to send: " +
				http.response_header.status.to_s

			case http.response_header.status
			when 200
				http
			else
				EMPromise.reject(http.response_header.status)
			end
		}
	end

	def response(env)
		env.logger.debug 'ENV: ' + env.to_s
		env.logger.debug 'path: ' + env['REQUEST_PATH']
		env.logger.debug 'method: ' + env['REQUEST_METHOD']
		env.logger.debug 'BODY: ' + Rack::Request.new(env).body.read

		jid, media_id = env['REQUEST_PATH'].split('/')[-2..-1]
		cred_key = "catapult_cred-#{URI.unescape(jid)}"

		REDIS.lrange(cred_key, 0, 2).then { |creds|
			if creds.length < 3
				EMPromise.reject(404)
			else
				media_request(
					env,
					*creds,
					env['REQUEST_METHOD'].downcase.to_sym,
					media_id
				)
			end
		}.then { |http|
			clength = http.response_header['content-length']
			[200, {'Content-Length' => clength}, http.response]
		}.catch { |code|
			if code.is_a?(Integer)
				EMPromise.reject(code)
			else
				env.logger.error("ERROR: #{code.inspect}")
				EMPromise.reject(500)
			end
		}.catch { |code|
			[
				code,
				{'Content-Type' => 'text/plain;charset=utf-8'},
				case code
				when 404
					"not found\n"
				when 405
					"only HEAD and GET are allowed\n"
				else
					"unexpected error\n"
				end
			]
		}.sync
	end
end
