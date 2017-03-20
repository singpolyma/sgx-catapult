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
require 'em-hiredis'
require 'em-http-request'
require 'json'
require 'net/http'
require 'redis/connection/hiredis'
require 'securerandom'
require 'time'
require 'uri'
require 'webrick'

require 'goliath/api'
require 'goliath/server'
require 'log4r'

require_relative 'em_promise'

$stdout.sync = true

puts "Soprani.ca/SMS Gateway for XMPP - Catapult\n"\
	"==>> last commit of this version is " + `git rev-parse HEAD` + "\n"

if ARGV.size != 9
	puts "Usage: sgx-catapult.rb <component_jid> <component_password> "\
		"<server_hostname> <server_port> "\
		"<redis_hostname> <redis_port> <delivery_receipt_url> "\
		"<http_listen_port> <mms_proxy_prefix_url>"
	exit 0
end

t = Time.now
puts "LOG %d.%09d: starting...\n\n" % [t.to_i, t.nsec]

def panic(e)
	puts "Shutting down gateway due to exception: #{e.message}"
	puts e.backtrace
	SGXcatapult.shutdown
	puts 'Gateway has terminated.'
	EM.stop
end

def extract_shortcode(dest)
	num, context = dest.split(';', 2)
	num if context && context == 'phone-context=ca-us.phone-context.soprani.ca'
end

module SGXcatapult
	extend Blather::DSL

	@jingle_sids = {}
	@jingle_fnames = {}
	@partial_data = {}

	def self.run
		client.run
	end

	# so classes outside this module can write messages, too
	def self.write(stanza)
		client.write(stanza)
	end

	def self.error_msg(orig, query_node, type, name, text=nil)
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

	rescue Exception => e
		puts 'Shutting down gateway due to exception 000: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end

	setup ARGV[0], ARGV[1], ARGV[2], ARGV[3]

	def self.pass_on_message(m, users_num, jid)
		# setup delivery receipt; similar to a reply
		rcpt = ReceiptMessage.new(m.from.stripped)
		rcpt.from = m.to

		# pass original message (before sending receipt)
		m.to = jid
		m.from = "#{users_num}@#{ARGV[0]}"

		puts 'XRESPONSE0: ' + m.inspect
		write_to_stream m

		# send a delivery receipt back to the sender
		# TODO: send only when requested per XEP-0184
		# TODO: pass receipts from target if supported

		# TODO: put in member/instance variable
		rcpt['id'] = SecureRandom.uuid
		rcvd = Nokogiri::XML::Node.new 'received', rcpt.document
		rcvd['xmlns'] = 'urn:xmpp:receipts'
		rcvd['id'] = m.id
		rcpt.add_child(rcvd)

		puts 'XRESPONSE1: ' + rcpt.inspect
		write_to_stream rcpt
	end

	def self.call_catapult(token, secret, m, pth, body, head={}, code=[200])
		EM::HttpRequest.new(
			"https://api.catapult.inetwork.com/#{pth}"
		).public_send(
			m,
			head: {
				'Authorization' => [token, secret]
			}.merge(head),
			body: body
		).then { |http|
			puts "API response to send: #{http.response} with code"\
				" response.code #{http.response_header.status}"

			if code.include?(http.response_header.status)
				http.response
			else
				# TODO: add text; mention code number
				EMPromise.reject(
					[:cancel, 'internal-server-error']
				)
			end
		}
	end

	def self.to_catapult(s, murl, num_dest, user_id, token, secret, usern)
		extra = if murl
			{
				media: murl
			}
		else
			{
				receiptRequested: 'all',
				callbackUrl:      ARGV[6]
			}
		end

		call_catapult(
			token,
			secret,
			:post,
			"v1/users/#{user_id}/messages",
			JSON.dump(extra.merge(
				from: usern,
				to:   num_dest,
				text: s.respond_to?(:body) ? s.body : '',
				tag:
					# callbacks need id and resourcepart
					WEBrick::HTTPUtils.escape(s.id.to_s) +
					' ' +
					WEBrick::HTTPUtils.escape(
						s.from.resource.to_s
					)
			)),
			{'Content-Type' => 'application/json'},
			[201]
		)
	end

	def self.validate_num(num)
		EMPromise.resolve(num.to_s).then { |num_dest|
			if num_dest =~ /\A\+?[0-9]+(?:;.*)?\Z/
				next num_dest if num_dest[0] == '+'
				shortcode = extract_shortcode(num_dest)
				next shortcode if shortcode
			end
			# TODO: text re num not (yet) supportd/implmentd
			EMPromise.reject([:cancel, 'item-not-found'])
		}
	end

	def self.fetch_catapult_cred_for(jid)
		cred_key = "catapult_cred-#{jid.stripped}"
		REDIS.lrange(cred_key, 0, 3).then { |creds|
			if creds.length < 4
				# TODO: add text re credentials not registered
				EMPromise.reject(
					[:auth, 'registration-required']
				)
			else
				creds
			end
		}
	end

	message :chat?, :body do |m|
		EMPromise.all([
			validate_num(m.to.node),
			fetch_catapult_cred_for(m.from)
		]).then { |(num_dest, creds)|
			jid_key = "catapult_jid-#{num_dest}"
			REDIS.get(jid_key).then { |jid|
				[jid, num_dest] + creds
			}
		}.then { |(jid, num_dest, *creds)|
			# if destination user is in the system pass on directly
			if jid
				pass_on_message(m, creds.last, jid)
			else
				to_catapult(m, nil, num_dest, *creds)
			end
		}.catch { |e|
			if e.is_a?(Array) && e.length == 2
				write_to_stream error_msg(m.reply, m.body, *e)
			else
				EMPromise.reject(e)
			end
		}.catch(&method(:panic))
	end

	def self.user_cap_identities
		[{category: 'client', type: 'sms'}]
	end

	def self.user_cap_features
		[
			"urn:xmpp:receipts",
			"urn:xmpp:jingle:1", "urn:xmpp:jingle:transports:ibb:1",

			# TODO: add more efficient file transfer mechanisms
			#"urn:xmpp:jingle:transports:s5b:1",

			# TODO: MUST add all reasonable vers of file-transfer
			#"urn:xmpp:jingle:apps:file-transfer:4"
			"urn:xmpp:jingle:apps:file-transfer:3"
		]
	end

	presence :subscribe? do |p|
	begin
		puts "PRESENCE1: #{p.inspect}"

		# subscriptions are allowed from anyone - send reply immediately
		msg = Blather::Stanza::Presence.new
		msg.to = p.from
		msg.from = p.to
		msg.type = :subscribed

		puts 'RESPONSE5a: ' + msg.inspect
		write_to_stream msg

		# send a <presence> immediately; not automatically probed for it
		# TODO: refactor so no "presence :probe? do |p|" duplicate below
		caps = Blather::Stanza::Capabilities.new
		# TODO: user a better node URI (?)
		caps.node = 'http://catapult.sgx.soprani.ca/'
		caps.identities = user_cap_identities
		caps.features = user_cap_features

		msg = caps.c
		msg.to = p.from
		msg.from = p.to.to_s + '/sgx'

		puts 'RESPONSE5b: ' + msg.inspect
		write_to_stream msg

		# need to subscribe back so Conversations displays images inline
		msg = Blather::Stanza::Presence.new
		msg.to = p.from.to_s.split('/', 2)[0]
		msg.from = p.to.to_s.split('/', 2)[0]
		msg.type = :subscribe

		puts 'RESPONSE5c: ' + msg.inspect
		write_to_stream msg

	rescue Exception => e
		puts 'Shutting down gateway due to exception 002: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	presence :probe? do |p|
	begin
		puts 'PRESENCE2: ' + p.inspect

		caps = Blather::Stanza::Capabilities.new
		# TODO: user a better node URI (?)
		caps.node = 'http://catapult.sgx.soprani.ca/'
		caps.identities = user_cap_identities
		caps.features = user_cap_features

		msg = caps.c
		msg.to = p.from
		msg.from = p.to.to_s + '/sgx'

		puts 'RESPONSE6: ' + msg.inspect
		write_to_stream msg

	rescue Exception => e
		puts 'Shutting down gateway due to exception 003: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	iq '/iq/ns:jingle', ns: 'urn:xmpp:jingle:1' do |i, jn|
	begin
		puts "IQj: #{i.inspect}"

		if jn[0]['action'] == 'transport-accept'
			puts "REPLY0: #{i.reply.inspect}"
			write_to_stream i.reply
			next
		elsif jn[0]['action'] == 'session-terminate'
			# TODO: unexpected (usually we do this; handle?)
			puts "TERMINATED"
			next
		elsif jn[0]['action'] == 'transport-info'
			# TODO: unexpected, but should handle in a nice way
			puts "FAIL!!!"
			next
		elsif i.type == :error
			# TODO: do something, maybe terminating the connection
			puts 'ERROR!!!'
			next
		end

		# TODO: should probably confirm we got session-initiate here

		write_to_stream i.reply
		puts "RESPONSE8: #{i.reply.inspect}"

		msg = Blather::Stanza::Iq.new :set
		msg.to = i.from
		msg.from = i.to

		cn = jn.children.find { |v| v.element_name == "content" }
		puts 'CN-name: ' + cn['name']
		puts 'JN-sid: ' + jn[0]['sid']

		ibb_found = false
		last_sid = ''
		cn.children.each do |child|
			if child.element_name == 'transport'
				puts 'TPORT: ' + child.namespace.href
				last_sid = child['sid']
				if 'urn:xmpp:jingle:transports:ibb:1' ==
					child.namespace.href

					ibb_found = true
					break
				end
			end
		end

		j = Nokogiri::XML::Node.new 'jingle', msg.document
		j['xmlns'] = 'urn:xmpp:jingle:1'
		j['sid'] = jn[0]['sid']
		msg.add_child(j)

		content = Nokogiri::XML::Node.new 'content', msg.document
		content['name'] = cn['name']
		content['creator'] = 'initiator'
		j.add_child(content)

		transport = Nokogiri::XML::Node.new 'transport', msg.document
		# TODO: make block-size more variable and/or dependent on sender
		transport['block-size'] = '4096'
		transport['xmlns'] = 'urn:xmpp:jingle:transports:ibb:1'
		if ibb_found
			transport['sid'] = last_sid
			j['action'] = 'session-accept'
			j['responder'] = i.from

			dsc = Nokogiri::XML::Node.new 'description', msg.document
			dsc['xmlns'] = 'urn:xmpp:jingle:apps:file-transfer:3'
			content.add_child(dsc)
		else
			# for Conversations - it tries s5b even if caps ibb-only
			transport['sid'] = SecureRandom.uuid
			j['action'] = 'transport-replace'
			j['initiator'] = i.from
		end
		content.add_child(transport)

		@jingle_sids[transport['sid']] = jn[0]['sid']

		# TODO: save <date> as well? Gajim sends, Conversations does not
		# TODO: save/validate <size> with eventual full received length
		fname =
			cn
			.children.find { |v| v.element_name == "description" }
			.children.find { |w| w.element_name == "offer" }
			.children.find { |x| x.element_name == "file" }
			.children.find { |y| y.element_name == "name" }
		@jingle_fnames[transport['sid']] = fname.text

		puts "RESPONSE9: #{msg.inspect}"
		write_to_stream msg

	rescue Exception => e
		puts 'Shutting down gateway due to exception 004: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	iq '/iq/ns:open', ns:	'http://jabber.org/protocol/ibb' do |i, on|
	begin
		puts "IQo: #{i.inspect}"

		@partial_data[on[0]['sid']] = ''
		write_to_stream i.reply

	rescue Exception => e
		puts 'Shutting down gateway due to exception 005: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	iq '/iq/ns:data', ns:	'http://jabber.org/protocol/ibb' do |i, dn|
	begin
		@partial_data[dn[0]['sid']] += Base64.decode64(dn[0].text)
		write_to_stream i.reply

	rescue Exception => e
		puts 'Shutting down gateway due to exception 006: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	iq '/iq/ns:close', ns:	'http://jabber.org/protocol/ibb' do |i, cn|
		puts "IQc: #{i.inspect}"
		write_to_stream i.reply

		EMPromise.all([
			validate_num(i.to.node),
			fetch_catapult_cred_for(i.from)
		]).then { |(num_dest, creds)|
			# Gajim bug: <close/> has Jingle (not transport) sid; fix later
			if not @jingle_fnames.key? cn[0]['sid']
				puts 'ERROR: Not found in filename map: ' + cn[0]['sid']

				next EMPromise.reject(:done)
				# TODO: in case only Gajim's <data/> bug fixed, add map:
				#cn[0]['sid'] = @jingle_tsids[cn[0]['sid']]
			end

			# upload cached data to server (before success reply)
			media_name =
				"#{Time.now.utc.iso8601}_#{SecureRandom.uuid}"\
				"_#{@jingle_fnames[cn[0]['sid']]}"
			puts 'name to save: ' + media_name

			path = "/v1/users/#{creds.first}/media/#{media_name}"

			EMPromise.all([
				call_catapult(
					*creds[1..2],
					:put,
					path,
					@partial_data[cn[0]['sid']]
				),
				to_catapult(
					i,
					"https://api.catapult.inetwork.com/" +
						path,
					num_dest,
					*creds
				)
			])
		}.then {
			@partial_data[cn[0]['sid']] = ''

			# received the complete file so now close the stream
			msg = Blather::Stanza::Iq.new :set
			msg.to = i.from
			msg.from = i.to

			j = Nokogiri::XML::Node.new 'jingle', msg.document
			j['xmlns'] = 'urn:xmpp:jingle:1'
			j['action'] = 'session-terminate'
			j['sid'] = @jingle_sids[cn[0]['sid']]
			msg.add_child(j)

			r = Nokogiri::XML::Node.new 'reason', msg.document
			s = Nokogiri::XML::Node.new 'success', msg.document
			r.add_child(s)
			j.add_child(r)

			puts 'RESPONSE1: ' + msg.inspect
			write_to_stream msg
		}.catch { |e|
			if e.is_a?(Array) && e.length == 2
				write_to_stream error_msg(i.reply, nil, *e)
			elsif e != :done
				EMPromise.reject(e)
			end
		}.catch(&method(:panic))
	end

	iq '/iq/ns:query', ns:	'http://jabber.org/protocol/disco#items' do |i|
	begin
		write_to_stream i.reply

	rescue Exception => e
		puts 'Shutting down gateway due to exception 008: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	iq '/iq/ns:query', ns:	'http://jabber.org/protocol/disco#info' do |i|
	begin
		# respond to capabilities request for an sgx-catapult number JID
		if i.to.node
			# TODO: confirm the node URL is expected using below
			#puts "XR[node]: #{xpath_result[0]['node']}"

			msg = i.reply
			msg.identities = user_cap_identities
			msg.features = user_cap_features

			puts 'RESPONSE7: ' + msg.inspect
			write_to_stream msg
			next
		end

		# respond to capabilities request for sgx-catapult itself
		msg = i.reply
		msg.identities = [{
			name: 'Soprani.ca Gateway to XMPP - Catapult',
			type: 'sms', category: 'gateway'
		}]
		msg.features = [
			"jabber:iq:register",
			"jabber:iq:gateway",
			"jabber:iq:private",
			"http://jabber.org/protocol/disco#info",
			"http://jabber.org/protocol/commands",
			"http://jabber.org/protocol/muc"
		]
		write_to_stream msg

	rescue Exception => e
		puts 'Shutting down gateway due to exception 009: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
	end

	def self.check_then_register(user_id, api_token, api_secret, phone_num,
		i, qn)

		jid_key = "catapult_jid-" + phone_num

		bare_jid = i.from.to_s.split('/', 2)[0]
		cred_key = "catapult_cred-" + bare_jid

		# TODO: pre-validate ARGV[5] is integer
		conn = Hiredis::Connection.new
		conn.connect(ARGV[4], ARGV[5].to_i)

		conn.write ["GET", jid_key]
		existing_jid = conn.read

		if not existing_jid.nil? and existing_jid != bare_jid
			conn.disconnect

			# TODO: add/log text re credentials exist already
			write_to_stream error_msg(
				i.reply, qn, :cancel,
				'conflict')
			return false
		end

		# ASSERT: existing_jid is nil or equal to bare_jid

		conn.write ["EXISTS", cred_key]
		creds_exist = conn.read
		if 1 == creds_exist
			conn.write ["LRANGE", cred_key, 0, 3]
			if [user_id, api_token, api_secret, phone_num] !=
				conn.read

				conn.disconnect

				# TODO: add/log txt re credentials exist already
				write_to_stream error_msg(
					i.reply, qn, :cancel,
					'conflict')
				return false
			end
		end

		# ASSERT: cred_key does not exist or its value equals input vals

		# not necessary if existing_jid non-nil, but easier to do anyway
		conn.write ["SET", jid_key, bare_jid]
		if conn.read != 'OK'
			conn.disconnect

			# TODO: catch/relay RuntimeError
			# TODO: add txt re push failure
			write_to_stream error_msg(
				i.reply, qn, :cancel,
				'internal-server-error')
			return false
		end

		if 1 == creds_exist
			# per above ASSERT, cred_key value equals input already
			conn.disconnect
			write_to_stream i.reply
			return true
		end

		conn.write ["RPUSH", cred_key, user_id]
		conn.write ["RPUSH", cred_key, api_token]
		conn.write ["RPUSH", cred_key, api_secret]
		conn.write ["RPUSH", cred_key, phone_num]

		# TODO: confirm cred_key list size == 4

		(1..4).each do |n|
			# TODO: catch/relay RuntimeError
			result = conn.read
			if result != n
				conn.disconnect

				write_to_stream error_msg(
					i.reply, qn, :cancel,
					'internal-server-error')
				return false
			end
		end
		conn.disconnect

		write_to_stream i.reply

		return true

	rescue Exception => e
		puts 'Shutting down gateway due to exception 010: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end

	iq '/iq/ns:query', ns: 'jabber:iq:register' do |i, qn|
	begin
		puts "IQ: #{i.inspect}"

		if i.type == :set
			rn = qn.children.find { |v| v.element_name == "remove" }
			if not rn.nil?
				puts "received <remove/> - ignoring for now..."
				next
			end

			xn = qn.children.find { |v| v.element_name == "x" }

			user_id = ''
			api_token = ''
			api_secret = ''
			phone_num = ''

			if xn.nil?
				user_id = qn.children.find { |v|
					v.element_name == "nick"
				}
				api_token = qn.children.find { |v|
					v.element_name == "username"
				}
				api_secret = qn.children.find { |v|
					v.element_name == "password"
				}
				phone_num = qn.children.find { |v|
					v.element_name == "phone"
				}
			else
				xn.children.each do |field|
					if field.element_name == "field"
						val = field.children.find { |v|
							v.element_name == "value"
						}

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
				write_to_stream error_msg(
					i.reply, qn, :cancel,
					'item-not-found'
				)
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
					if not check_then_register(
						user_id, api_token, api_secret,
						phone_num, i, qn
					)
						next
					end
				else
					# TODO: add text re number disabled
					write_to_stream error_msg(
						i.reply, qn,
						:modify, 'not-acceptable'
					)
				end
			elsif response.code == '401'
				# TODO: add text re bad credentials
				write_to_stream error_msg(
					i.reply, qn, :auth,
					'not-authorized'
				)
			elsif response.code == '404'
				# TODO: add text re number not found or disabled
				write_to_stream error_msg(
					i.reply, qn, :cancel,
					'item-not-found'
				)
			else
				# TODO: add text re misc error, and mention code
				write_to_stream error_msg(
					i.reply, qn, :modify,
					'not-acceptable'
				)
			end

		elsif i.type == :get
			orig = i.reply

			bare_jid = i.from.to_s.split('/', 2)[0]
			cred_key = "catapult_cred-" + bare_jid

			conn = Hiredis::Connection.new
			conn.connect(ARGV[4], ARGV[5].to_i)
			conn.write(["LINDEX", cred_key, 3])
			existing_number = conn.read
			conn.disconnect

			msg = Nokogiri::XML::Node.new 'query', orig.document
			msg['xmlns'] = 'jabber:iq:register'

			if existing_number
				msg.add_child(
					Nokogiri::XML::Node.new('registered', msg.document)
				)
			end

			n1 = Nokogiri::XML::Node.new 'instructions', msg.document
			n1.content= "Enter the information from your Account "\
				"page as well as the Phone Number\nin your "\
				"account you want to use (ie. '+12345678901')"\
				".\nUser Id is nick, API Token is username, "\
				"API Secret is password, Phone Number is phone"\
				".\n\nThe source code for this gateway is at "\
				"https://gitlab.com/ossguy/sgx-catapult ."\
				"\nCopyright (C) 2017  Denver Gingerich and "\
				"others, licensed under AGPLv3+."
			n2 = Nokogiri::XML::Node.new 'nick', msg.document
			n3 = Nokogiri::XML::Node.new 'username', msg.document
			n4 = Nokogiri::XML::Node.new 'password', msg.document
			n5 = Nokogiri::XML::Node.new 'phone', msg.document
			n5.content = existing_number.to_s
			msg.add_child(n1)
			msg.add_child(n2)
			msg.add_child(n3)
			msg.add_child(n4)
			msg.add_child(n5)

			x = Blather::Stanza::X.new :form, [
				{
					required: true, type: :"text-single",
					label: 'User Id', var: 'nick'
				},
				{
					required: true, type: :"text-single",
					label: 'API Token', var: 'username'
				},
				{
					required: true, type: :"text-private",
					label: 'API Secret', var: 'password'
				},
				{
					required: true, type: :"text-single",
					label: 'Phone Number', var: 'phone',
					value: existing_number.to_s
				}
			]
			x.title= 'Register for '\
				'Soprani.ca Gateway to XMPP - Catapult'
			x.instructions= "Enter the details from your Account "\
				"page as well as the Phone Number\nin your "\
				"account you want to use (ie. '+12345678901')"\
				".\n\nThe source code for this gateway is at "\
				"https://gitlab.com/ossguy/sgx-catapult ."\
				"\nCopyright (C) 2017  Denver Gingerich and "\
				"others, licensed under AGPLv3+."
			msg.add_child(x)

			orig.add_child(msg)
			puts "RESPONSE2: #{orig.inspect}"
			write_to_stream orig
			puts "SENT"
		end

	rescue Exception => e
		puts 'Shutting down gateway due to exception 011: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
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
	def self.new(to=nil)
		node = super :message
		node.to = to
		node
	end
end

class WebhookHandler < Goliath::API
	def send_media(from, to, media_url)
		# we assume media_url is of the form (always the case so far):
		#  https://api.catapult.inetwork.com/v1/users/[uid]/media/[file]

		# the caller must guarantee that 'to' is a bare JID
		proxy_url = ARGV[8] + to + '/' + media_url.split('/', 8)[7]

		puts 'ORIG_URL: ' + media_url
		puts 'PROX_URL: ' + proxy_url

		# put URL in the body (so Conversations will still see it)...
		msg = Blather::Stanza::Message.new(to, proxy_url)
		msg.from = from

		# ...but also provide URL in XEP-0066 (OOB) fashion
		# TODO: confirm client supports OOB or don't send this
		x = Nokogiri::XML::Node.new 'x', msg.document
		x['xmlns'] = 'jabber:x:oob'

		urln = Nokogiri::XML::Node.new 'url', msg.document
		urlc = Nokogiri::XML::Text.new proxy_url, msg.document

		urln.add_child(urlc)
		x.add_child(urln)
		msg.add_child(x)

		SGXcatapult.write(msg)

	rescue Exception => e
		puts 'Shutting down gateway due to exception 012: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end

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

		jid_key = "catapult_jid-" + users_num

		if others_num[0] != '+'
			# TODO: check that others_num actually a shortcode first
			others_num +=
				';phone-context=ca-us.phone-context.soprani.ca'
		end

		conn = Hiredis::Connection.new
		conn.connect(ARGV[4], ARGV[5].to_i)

		conn.write ["EXISTS", jid_key]
		if conn.read == 0
			conn.disconnect

			puts "jid_key (#{jid_key}) DNE; Catapult misconfigured?"

			# TODO: likely not appropriate; give error to Catapult?
			# TODO: add text re credentials not being registered
			#write_to_stream error_msg(m.reply, m.body, :auth,
			#	'registration-required')
			return [200, {}, "OK"]
		end

		conn.write ["GET", jid_key]
		bare_jid = conn.read
		conn.disconnect

		msg = ''
		case params['direction']
		when 'in'
			text = ''
			case params['eventType']
			when 'sms'
				text = params['text']
			when 'mms'
				has_media = false
				params['media'].each do |media_url|
					if not media_url.end_with?(
						'.smil', '.txt', '.xml'
					)

						has_media = true
						send_media(
							others_num + '@' +
							ARGV[0],
							bare_jid, media_url
						)
					end
				end

				if params['text'].empty?
					if not has_media
						text = '[suspected group msg '\
							'with no text (odd)]'
					end
				else
					text = if has_media
						# TODO: write/use a caption XEP
						params['text']
					else
						'[suspected group msg '\
						'(recipient list not '\
						'available) with '\
						'following text] ' +
						params['text']
					end
				end

				# ie. if text param non-empty or had no media
				if not text.empty?
					msg = Blather::Stanza::Message.new(
						bare_jid, text)
					msg.from = others_num + '@' + ARGV[0]
					SGXcatapult.write(msg)
				end

				return [200, {}, "OK"]
			else
				text = "unknown type (#{params['eventType']})"\
					" with text: " + params['text']

				# TODO: log/notify of this properly
				puts text
			end

			msg = Blather::Stanza::Message.new(bare_jid, text)
		else # per prior switch, this is:  params['direction'] == 'out'
			tag_parts = params['tag'].split(/ /, 2)
			id = WEBrick::HTTPUtils.unescape(tag_parts[0])
			resourcepart = WEBrick::HTTPUtils.unescape(tag_parts[1])

			case params['deliveryState']
			when 'not-delivered'
				# create a bare message like the one user sent
				msg = Blather::Stanza::Message.new(
					others_num + '@' + ARGV[0])
				msg.from = bare_jid + '/' + resourcepart
				msg['id'] = id

				# create an error reply to the bare message
				msg = Blather::StanzaError.new(
					msg,
					'recipient-unavailable',
					:wait
				).to_node
			when 'delivered'
				msg = ReceiptMessage.new(bare_jid)

				# TODO: put in member/instance variable
				msg['id'] = SecureRandom.uuid

				# TODO: send only when requested per XEP-0184
				rcvd = Nokogiri::XML::Node.new(
					'received',
					msg.document
				)
				rcvd['xmlns'] = 'urn:xmpp:receipts'
				rcvd['id'] = id
				msg.add_child(rcvd)
			when 'waiting'
				# can't really do anything with it; nice to know
				puts "message with id #{id} waiting"
				return [200, {}, "OK"]
			else
				# TODO: notify somehow of unknown state receivd?
				puts "message with id #{id} has "\
					"other state #{params['deliveryState']}"
				return [200, {}, "OK"]
			end

			puts "RESPONSE4: #{msg.inspect}"
		end

		msg.from = others_num + '@' + ARGV[0]
		SGXcatapult.write(msg)

		[200, {}, "OK"]

	rescue Exception => e
		puts 'Shutting down gateway due to exception 013: ' + e.message
		SGXcatapult.shutdown
		puts 'Gateway has terminated.'
		EM.stop
	end
end

EM.run do
	REDIS = EM::Hiredis.connect("redis://#{ARGV[4]}:#{ARGV[5]}/0")

	SGXcatapult.run

	# required when using Prosody otherwise disconnects on 6-hour inactivity
	EM.add_periodic_timer(3600) do
		msg = Blather::Stanza::Iq::Ping.new(:get, 'localhost')
		msg.from = ARGV[0]
		SGXcatapult.write(msg)
	end

	server = Goliath::Server.new('0.0.0.0', ARGV[7].to_i)
	server.api = WebhookHandler.new
	server.app = Goliath::Rack::Builder.build(server.api.class, server.api)
	server.logger = Log4r::Logger.new('goliath')
	server.logger.add(Log4r::StdoutOutputter.new('console'))
	server.logger.level = Log4r::INFO
	server.start
end
