#!/usr/bin/env ruby
#
# Copyright (C) 2017  Denver Gingerich <denver@ossguy.com>
# Copyright (C) 2017  Stephen Paul Weber <singpolyma@singpolyma.net>
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

require 'blather/client/dsl'
require 'json'
require 'net/http'
require 'redis/connection/hiredis'
require 'uri'

require 'goliath/api'
require 'goliath/server'
require 'log4r'

if ARGV.size != 8 then
	puts "Usage: sgx-catapult.rb <component_jid> <component_password> " +
		"<server_hostname> <server_port> " +
		"<redis_hostname> <redis_port> <delivery_receipt_url> " +
		"<http_listen_port>"
	exit 0
end

module SGXcatapult
	extend Blather::DSL

	def self.run
		client.run
	end

	# so classes outside this module can write messages, too
	def self.write(stanza)
		client.write(stanza)
	end

	def self.error_msg(orig, query_node, type, name, text = nil)
		if not query_node.nil?
			orig.add_child(query_node)
			orig.type = :error
		end

		error = Nokogiri::XML::Node.new 'error', orig.document
		error['type'] = type
		orig.add_child(error)

		suberr = Nokogiri::XML::Node.new name, orig.document
		suberr['xmlns'] = 'urn:ietf:params:xml:ns:xmpp-stanzas'
		error.add_child(suberr)

		# TODO: add some explanatory xml:lang='en' text (see text param)
		puts "RESPONSE3: #{orig.inspect}"
		return orig
	end

	setup ARGV[0], ARGV[1], ARGV[2], ARGV[3]

	message :chat?, :body do |m|
		num_dest = m.to.to_s.split('@', 2)[0]

		if num_dest[0] != '+'
			# TODO: add text re number not (yet) supported/implmnted
			write_to_stream error_msg(m.reply, m.body, :cancel,
				'item-not-found')
			next
		end

		bare_jid = m.from.to_s.split('/', 2)[0]
		cred_key = "catapult_cred-" + bare_jid

		conn = Hiredis::Connection.new
		conn.connect(ARGV[4], ARGV[5].to_i)

		conn.write ["EXISTS", cred_key]
		if conn.read == 0
			conn.disconnect

			# TODO: add text re credentials not being registered
			write_to_stream error_msg(m.reply, m.body, :auth,
				'registration-required')
			next
		end

		conn.write ["LRANGE", cred_key, 0, 3]
		user_id, api_token, api_secret, users_num = conn.read
		conn.disconnect

		uri = URI.parse('https://api.catapult.inetwork.com')
		http = Net::HTTP.new(uri.host, uri.port)
		http.use_ssl = true
		request = Net::HTTP::Post.new('/v1/users/' + user_id +
			'/messages')
		request.basic_auth api_token, api_secret
		request.add_field('Content-Type', 'application/json')
		request.body = JSON.dump({
			'from'			=> users_num,
			'to'			=> num_dest,
			'text'			=> m.body,
			'tag'			=> m.id, # TODO: message has it?
			'receiptRequested'	=> 'all',
			'callbackUrl'		=> ARGV[6]
		})
		response = http.request(request)

		puts 'API response to send: ' + response.to_s + ' with code ' +
			response.code + ', body "' + response.body + '"'

		if response.code != '201'
			# TODO: add text re unexpected code; mention code number
			write_to_stream error_msg(m.reply, m.body, :cancel,
				'internal-server-error')
			next
		end
	end

	def self.user_cap_identities()
		[{:category => 'client', :type => 'sms'}]
	end

	def self.user_cap_features()
		# TODO: add more features
		["urn:xmpp:receipts"]
	end

	presence :subscribe? do |p|
		puts "PRESENCE1: #{p.inspect}"

		msg = Blather::Stanza::Presence.new
		msg.to = p.from
		msg.from = p.to
		msg.type = :subscribed

		puts "RESPONSE5: #{msg.inspect}"
		write_to_stream msg
	end

	presence :probe? do |p|
		puts 'PRESENCE2: ' + p.inspect

		caps = Blather::Stanza::Capabilities.new
		# TODO: user a better node URI (?)
		caps.node = 'http://catapult.sgx.soprani.ca/'
		caps.identities = user_cap_identities()
		caps.features = user_cap_features()

		msg = caps.c
		msg.to = p.from
		msg.from = p.to.to_s + '/sgx'

		puts 'RESPONSE6: ' + msg.inspect
		write_to_stream msg
	end

	iq '/iq/ns:query', :ns =>
		'http://jabber.org/protocol/disco#items' do |i, xpath_result|

		write_to_stream i.reply
	end

	iq '/iq/ns:query', :ns =>
		'http://jabber.org/protocol/disco#info' do |i, xpath_result|

		if i.to.to_s.include? '@'
			# TODO: confirm the node URL is expected using below
			#puts "XR[node]: #{xpath_result[0]['node']}"

			msg = i.reply
			msg.identities = user_cap_identities()
			msg.features = user_cap_features()

			puts 'RESPONSE7: ' + msg.inspect
			write_to_stream msg
			next
		end

		msg = i.reply
		msg.identities = [{:name =>
			'Soprani.ca Gateway to XMPP - Catapult',
			:type => 'sms-ctplt', :category => 'gateway'}]
		msg.features = ["jabber:iq:register",
			"jabber:iq:gateway", "jabber:iq:private",
			"http://jabber.org/protocol/disco#info",
			"http://jabber.org/protocol/commands",
			"http://jabber.org/protocol/muc"]
		write_to_stream msg
	end

	iq '/iq/ns:query', :ns => 'jabber:iq:register' do |i, qn|
		puts "IQ: #{i.inspect}"

		if i.type == :set
			xn = qn.children.find { |v| v.element_name == "x" }

			user_id = ''
			api_token = ''
			api_secret = ''
			phone_num = ''

			if xn.nil?
				user_id = qn.children.find {
					|v| v.element_name == "nick" }
				api_token = qn.children.find {
					|v| v.element_name == "username" }
				api_secret = qn.children.find {
					|v| v.element_name == "password" }
				phone_num = qn.children.find {
					|v| v.element_name == "phone" }
			else
				for field in xn.children
					if field.element_name == "field"
						val = field.children.find { |v|
						v.element_name == "value" }

						case field['var']
						when 'nick'
							user_id = val.text
						when 'username'
							api_token = val.text
						when 'password'
							api_secret = val.text
						when 'phone'
							phone_num = val.text
						else
							# TODO: error
							puts "?: " +field['var']
						end
					end
				end
			end

			if phone_num[0] != '+'
				# TODO: add text re number not (yet) supported
				write_to_stream error_msg(i.reply, qn, :cancel,
					'item-not-found')
				next
			end

			uri = URI.parse('https://api.catapult.inetwork.com')
			http = Net::HTTP.new(uri.host, uri.port)
			http.use_ssl = true
			request = Net::HTTP::Get.new('/v1/users/' + user_id +
				'/phoneNumbers/' + phone_num)
			request.basic_auth api_token, api_secret
			response = http.request(request)

			puts 'API response: ' + response.to_s + ' with code ' +
				response.code + ', body "' + response.body + '"'

			if response.code == '200'
				params = JSON.parse response.body
				if params['numberState'] == 'enabled'
					num_key = "catapult_num-" + phone_num

					bare_jid = i.from.to_s.split('/', 2)[0]
					cred_key = "catapult_cred-" + bare_jid

					# TODO: pre-validate ARGV[5] is integer
					conn = Hiredis::Connection.new
					conn.connect(ARGV[4], ARGV[5].to_i)

					conn.write ["EXISTS", num_key]
					if conn.read == 1
						conn.disconnect

						# TODO: add txt re num exists
						write_to_stream error_msg(
							i.reply, qn, :cancel,
							'conflict')
						next
					end

					conn.write ["EXISTS", cred_key]
					if conn.read == 1
						conn.disconnect

						# TODO: add txt re already exist
						write_to_stream error_msg(
							i.reply, qn, :cancel,
							'conflict')
						next
					end

					conn.write ["RPUSH",num_key,bare_jid]
					if conn.read != 1
						conn.disconnect

						# TODO: catch/relay RuntimeError
						# TODO: add txt re push failure
						write_to_stream error_msg(
							i.reply, qn, :cancel,
							'internal-server-error')
						next
					end

					conn.write ["RPUSH",cred_key,user_id]
					conn.write ["RPUSH",cred_key,api_token]
					conn.write ["RPUSH",cred_key,api_secret]
					conn.write ["RPUSH",cred_key,phone_num]

					for n in 1..4 do
						# TODO: catch/relay RuntimeError
						result = conn.read
						if result != n
							conn.disconnect

							write_to_stream(
							error_msg(
							i.reply, qn, :cancel,
							'internal-server-error')
							)
							next
						end
					end
					conn.disconnect

					write_to_stream i.reply
				else
					# TODO: add text re number disabled
					write_to_stream error_msg(i.reply, qn,
						:modify, 'not-acceptable')
				end
			elsif response.code == '401'
				# TODO: add text re bad credentials
				write_to_stream error_msg(i.reply, qn, :auth,
					'not-authorized')
			elsif response.code == '404'
				# TODO: add text re number not found or disabled
				write_to_stream error_msg(i.reply, qn, :cancel,
					'item-not-found')
			else
				# TODO: add text re misc error, and mention code
				write_to_stream error_msg(i.reply, qn, :modify,
					'not-acceptable')
			end

		elsif i.type == :get
			orig = i.reply

			msg = Nokogiri::XML::Node.new 'query',orig.document
			msg['xmlns'] = 'jabber:iq:register'
			n1 = Nokogiri::XML::Node.new 'instructions',msg.document
			n1.content= "Enter the information from your Account " +
				"page as well as the Phone Number\nin your " +
				"account you want to use (ie. '+12345678901')" +
				".\nUser Id is nick, API Token is username, " +
				"API Secret is password, Phone Number is phone"+
				".\n\nThe source code for this gateway is at " +
				"https://github.com/ossguy/sgx-catapult ." +
				"\nCopyright (C) 2017  Denver Gingerich and " +
				"others, licensed under AGPLv3+."
			n2 = Nokogiri::XML::Node.new 'nick',msg.document
			n3 = Nokogiri::XML::Node.new 'username',msg.document
			n4 = Nokogiri::XML::Node.new 'password',msg.document
			n5 = Nokogiri::XML::Node.new 'phone',msg.document
			msg.add_child(n1)
			msg.add_child(n2)
			msg.add_child(n3)
			msg.add_child(n4)
			msg.add_child(n5)

			x = Blather::Stanza::X.new :form, [
				{:required => true, :type => :"text-single",
				:label => 'User Id', :var => 'nick'},
				{:required => true, :type => :"text-single",
				:label => 'API Token', :var => 'username'},
				{:required => true, :type => :"text-private",
				:label => 'API Secret', :var => 'password'},
				{:required => true, :type => :"text-single",
				:label => 'Phone Number', :var => 'phone'}
			]
			x.title= 'Register for ' +
				'Soprani.ca Gateway to XMPP - Catapult'
			x.instructions= "Enter the details from your Account " +
				"page as well as the Phone Number\nin your " +
				"account you want to use (ie. '+12345678901')" +
				".\n\nThe source code for this gateway is at " +
				"https://github.com/ossguy/sgx-catapult ." +
				"\nCopyright (C) 2017  Denver Gingerich and " +
				"others, licensed under AGPLv3+."
			msg.add_child(x)

			orig.add_child(msg)
			puts "RESPONSE2: #{orig.inspect}"
			write_to_stream orig
			puts "SENT"
		end
	end

	subscription(:request?) do |s|
		# TODO: are these the best to return?  really need '!' here?
		#write_to_stream s.approve!
		#write_to_stream s.request!
	end
end

[:INT, :TERM].each do |sig|
	trap(sig) {
		puts 'Shutting down gateway...'
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'

		EM.stop
	}
end

class ReceiptMessage < Blather::Stanza
	def self.new(to = nil)
		node = super :message
		node.to = to
		node
	end
end

class WebhookHandler < Goliath::API
	def response(env)
		puts 'ENV: ' + env.to_s
		body = Rack::Request.new(env).body.read
		puts 'BODY: ' + body
		params = JSON.parse body

		users_num = ''
		others_num = ''
		if params['direction'] == 'in'
			users_num = params['to']
			others_num = params['from']
		elsif params['direction'] == 'out'
			users_num = params['from']
			others_num = params['to']
		else
			# TODO: exception or similar
			puts "big problem: '" + params['direction'] + "'"
			return [200, {}, "OK"]
		end

		num_key = "catapult_num-" + users_num

		# TODO: validate that others_num starts with '+' or is shortcode

		conn = Hiredis::Connection.new
		conn.connect(ARGV[4], ARGV[5].to_i)

		conn.write ["EXISTS", num_key]
		if conn.read == 0
			conn.disconnect

			puts "num_key (#{num_key}) DNE; Catapult misconfigured?"

			# TODO: likely not appropriate; give error to Catapult?
			# TODO: add text re credentials not being registered
			#write_to_stream error_msg(m.reply, m.body, :auth,
			#	'registration-required')
			return [200, {}, "OK"]
		end

		conn.write ["LRANGE", num_key, 0, 0]
		bare_jid = conn.read[0]
		conn.disconnect

		msg = ''
		case params['direction']
		when 'in'
			text = ''
			case params['eventType']
			when 'sms'
				text = params['text']
			when 'mms'
				text = "MMS (pic not implemented) with text: " +
					params['text']
			else
				text = "unknown type (#{params['eventType']})" +
					" with text: " + params['text']

				# TODO log/notify of this properly
				puts text
			end

			msg = Blather::Stanza::Message.new(bare_jid, text)
		else # per prior switch, this is:  params['direction'] == 'out'
			msg = ReceiptMessage.new(bare_jid)
			msg['id'] = params['tag']

			case params['deliveryState']
			when 'not-delivered'
				# TODO: add text re deliveryDescription reason
				msg = SGXcatapult.error_msg(msg, nil, :cancel,
					'service-unavailable')
				return [200, {}, "OK"]
			when 'delivered'
				# TODO: send only when requested per XEP-0184
				rcvd = Nokogiri::XML::Node.new 'received',
					msg.document
				rcvd['xmlns'] = 'urn:xmpp:receipts'
				rcvd['id'] = params['tag']
				msg.add_child(rcvd)
			when 'waiting'
				# can't really do anything with it; nice to know
				puts "message with id #{params['id']} waiting"
				return [200, {}, "OK"]
			else
				# TODO: notify somehow of unknown state receivd?
				puts "message with id #{params['id']} has " +
					"other state #{params['deliveryState']}"
				return [200, {}, "OK"]
			end

			puts "RESPONSE4: #{msg.inspect}"
		end

		msg.from = others_num + '@' + ARGV[0]
		SGXcatapult.write(msg)

		[200, {}, "OK"]
	end
end

EM.run do
	SGXcatapult.run

	server = Goliath::Server.new('0.0.0.0', ARGV[7].to_i)
	server.api = WebhookHandler.new
	server.app = Goliath::Rack::Builder.build(server.api.class, server.api)
	server.logger = Log4r::Logger.new('goliath')
	server.logger.add(Log4r::StdoutOutputter.new('console'))
	server.logger.level = Log4r::INFO
	server.start
end
