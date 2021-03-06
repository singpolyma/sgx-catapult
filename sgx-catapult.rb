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
require 'securerandom'
require 'time'
require 'uri'
require 'webrick'

require 'goliath/api'
require 'goliath/server'
require 'log4r'

require_relative 'em_promise'

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

class SGXClient < Blather::Client
	def register_handler(type, *guards, &block)
		super(type, *guards) { |*args| wrap_handler(*args, &block) }
	end

	def register_handler_before(type, *guards, &block)
		check_handler(type, guards)
		handler = lambda { |*args| wrap_handler(*args, &block) }

		@handlers[type] ||= []
		@handlers[type].unshift([guards, handler])
	end

protected

	def wrap_handler(*args, &block)
		v = block.call(*args)
		v.catch(&method(:panic)) if v.is_a?(Promise)
		true # Do not run other handlers unless throw :pass
	rescue Exception => e
		panic(e)
	end
end

module SGXcatapult
	extend Blather::DSL

	@jingle_sids = {}
	@jingle_fnames = {}
	@partial_data = {}
	@client = SGXClient.new
	@gateway_features = [
		"http://jabber.org/protocol/disco#info",
		"jabber:iq:register"
	]

	def self.run
		client.run
	end

	# so classes outside this module can write messages, too
	def self.write(stanza)
		client.write(stanza)
	end

	def self.before_handler(type, *guards, &block)
		client.register_handler_before(type, *guards, &block)
	end

	def self.send_media(from, to, media_url, desc=nil, subject=nil)
		# we assume media_url is of the form (always the case so far):
		#  https://api.catapult.inetwork.com/v1/users/[uid]/media/[file]

		# the caller must guarantee that 'to' is a bare JID
		proxy_url = ARGV[6] + to + '/' + media_url.split('/', 8)[7]

		puts 'ORIG_URL: ' + media_url
		puts 'PROX_URL: ' + proxy_url

		# put URL in the body (so Conversations will still see it)...
		msg = Blather::Stanza::Message.new(to, proxy_url)
		msg.from = from
		msg.subject = subject if subject

		# ...but also provide URL in XEP-0066 (OOB) fashion
		# TODO: confirm client supports OOB or don't send this
		x = Nokogiri::XML::Node.new 'x', msg.document
		x['xmlns'] = 'jabber:x:oob'

		urln = Nokogiri::XML::Node.new 'url', msg.document
		urlc = Nokogiri::XML::Text.new proxy_url, msg.document
		urln.add_child(urlc)
		x.add_child(urln)

		if desc
			descn = Nokogiri::XML::Node.new('desc', msg.document)
			descc = Nokogiri::XML::Text.new(desc, msg.document)
			descn.add_child(descc)
			x.add_child(descn)
		end

		msg.add_child(x)

		write(msg)
	rescue Exception => e
		panic(e)
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
	end

	# workqueue_count MUST be 0 or else Blather uses threads!
	setup ARGV[0], ARGV[1], ARGV[2], ARGV[3], nil, nil, workqueue_count: 0

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

	def self.call_catapult(
		token, secret, m, pth, body=nil,
		head={}, code=[200], respond_with=:body
	)
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
				case respond_with
				when :body
					http.response
				when :headers
					http.response_header
				else
					http
				end
			else
				EMPromise.reject(http.response_header.status)
			end
		}
	end

	def self.to_catapult(s, murl, num_dest, user_id, token, secret, usern)
		body = s.respond_to?(:body) ? s.body : ''
		if murl.to_s.empty? && body.to_s.strip.empty?
			return EMPromise.reject(
				[:modify, 'policy-violation']
			)
		end

		extra = if murl
			{
				media: murl
			}
		else
			{
				receiptRequested: 'all',
				callbackUrl:      ARGV[4]
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
				text: body,
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
		).catch {
			# TODO: add text; mention code number
			EMPromise.reject(
				[:cancel, 'internal-server-error']
			)
		}
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

	message :body do |m|
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
		}
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

	def self.add_gateway_feature(feature)
		@gateway_features << feature
		@gateway_features.uniq!
	end

	subscription :request? do |p|
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
	end

	presence :probe? do |p|
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
	end

	iq '/iq/ns:jingle', ns: 'urn:xmpp:jingle:1' do |i, jn|
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
	end

	iq '/iq/ns:open', ns:	'http://jabber.org/protocol/ibb' do |i, on|
		puts "IQo: #{i.inspect}"

		@partial_data[on[0]['sid']] = ''
		write_to_stream i.reply
	end

	iq '/iq/ns:data', ns:	'http://jabber.org/protocol/ibb' do |i, dn|
		@partial_data[dn[0]['sid']] += Base64.decode64(dn[0].text)
		write_to_stream i.reply
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
				).catch {
					EMPromise.reject([
						:cancel, 'internal-server-error'
					])
				},
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
		}
	end

	iq '/iq/ns:query', ns:	'http://jabber.org/protocol/disco#info' do |i|
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
		msg.features = @gateway_features
		write_to_stream msg
	end

	def self.check_then_register(i, *creds)
		jid_key = "catapult_jid-#{creds.last}"
		bare_jid = i.from.stripped
		cred_key = "catapult_cred-#{bare_jid}"

		REDIS.get(jid_key).then { |existing_jid|
			if existing_jid && existing_jid != bare_jid
				# TODO: add/log text: credentials exist already
				EMPromise.reject([:cancel, 'conflict'])
			end
		}.then {
			REDIS.lrange(cred_key, 0, 3)
		}.then { |existing_creds|
			# TODO: add/log text: credentials exist already
			if existing_creds.length == 4 && creds != existing_creds
				EMPromise.reject([:cancel, 'conflict'])
			elsif existing_creds.length < 4
				REDIS.rpush(cred_key, *creds).then { |length|
					if length != 4
						EMPromise.reject([
							:cancel,
							'internal-server-error'
						])
					end
				}
			end
		}.then {
			# not necessary if existing_jid non-nil, easier this way
			REDIS.set(jid_key, bare_jid)
		}.then { |result|
			if result != 'OK'
				# TODO: add txt re push failure
				EMPromise.reject(
					[:cancel, 'internal-server-error']
				)
			end
		}.then {
			write_to_stream i.reply
		}
	end

	def self.creds_from_registration_query(qn)
		xn = qn.children.find { |v| v.element_name == "x" }

		if xn
			xn.children.each_with_object({}) do |field, h|
				next if field.element_name != "field"
				val = field.children.find { |v|
					v.element_name == "value"
				}

				case field['var']
				when 'nick'
					h[:user_id] = val.text
				when 'username'
					h[:api_token] = val.text
				when 'password'
					h[:api_secret] = val.text
				when 'phone'
					h[:phone_num] = val.text
				else
					# TODO: error
					puts "?: #{field['var']}"
				end
			end
		else
			qn.children.each_with_object({}) do |field, h|
				case field.element_name
				when "nick"
					h[:user_id] = field.text
				when "username"
					h[:api_token] = field.text
				when "password"
					h[:api_secret] = field.text
				when "phone"
					h[:phone_num] = field.text
				end
			end
		end.values_at(:user_id, :api_token, :api_secret, :phone_num)
	end

	def self.process_registration(i, qn)
		EMPromise.resolve(
			qn.children.find { |v| v.element_name == "remove" }
		).then { |rn|
			if rn
				puts "received <remove/> - ignoring for now..."
				EMPromise.reject(:done)
			else
				creds_from_registration_query(qn)
			end
		}.then { |user_id, api_token, api_secret, phone_num|
			if phone_num[0] == '+'
				[user_id, api_token, api_secret, phone_num]
			else
				# TODO: add text re number not (yet) supported
				EMPromise.reject([:cancel, 'item-not-found'])
			end
		}.then { |user_id, api_token, api_secret, phone_num|
			call_catapult(
				api_token,
				api_secret,
				:get,
				"v1/users/#{user_id}/phoneNumbers/#{phone_num}"
			).then { |response|
				params = JSON.parse(response)
				if params['numberState'] == 'enabled'
					check_then_register(
						i,
						user_id,
						api_token,
						api_secret,
						phone_num
					)
				else
					# TODO: add text re number disabled
					EMPromise.reject([:modify, 'not-acceptable'])
				end
			}
		}.catch { |e|
			EMPromise.reject(case e
			when 401
				# TODO: add text re bad credentials
				[:auth, 'not-authorized']
			when 404
				# TODO: add text re number not found or disabled
				[:cancel, 'item-not-found']
			when Integer
				[:modify, 'not-acceptable']
			else
				e
			end)
		}
	end

	def self.registration_form(orig, existing_number=nil)
		msg = Nokogiri::XML::Node.new 'query', orig.document
		msg['xmlns'] = 'jabber:iq:register'

		if existing_number
			msg.add_child(
				Nokogiri::XML::Node.new(
					'registered', msg.document
				)
			)
		end

		n1 = Nokogiri::XML::Node.new(
			'instructions', msg.document
		)
		n1.content = "Enter the information from your Account "\
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
		x.title = 'Register for '\
			'Soprani.ca Gateway to XMPP - Catapult'
		x.instructions = "Enter the details from your Account "\
			"page as well as the Phone Number\nin your "\
			"account you want to use (ie. '+12345678901')"\
			".\n\nThe source code for this gateway is at "\
			"https://gitlab.com/ossguy/sgx-catapult ."\
			"\nCopyright (C) 2017  Denver Gingerich and "\
			"others, licensed under AGPLv3+."
		msg.add_child(x)

		orig.add_child(msg)

		return orig
	end

	iq '/iq/ns:query', ns: 'jabber:iq:register' do |i, qn|
		puts "IQ: #{i.inspect}"

		case i.type
		when :set
			process_registration(i, qn)
		when :get
			bare_jid = i.from.stripped
			cred_key = "catapult_cred-#{bare_jid}"
			REDIS.lindex(cred_key, 3).then { |existing_number|
				reply = registration_form(i.reply, existing_number)
				puts "RESPONSE2: #{reply.inspect}"
				write_to_stream reply
			}
		else
			# Unknown IQ, ignore for now
			EMPromise.reject(:done)
		end.catch { |e|
			if e.is_a?(Array) && e.length == 2
				write_to_stream error_msg(i.reply, qn, *e)
			elsif e != :done
				EMPromise.reject(e)
			end
		}.catch(&method(:panic))
	end

	iq :get? do |i|
		write_to_stream error_msg(i.reply, i.children, 'cancel', 'feature-not-implemented')
	end

	iq :set? do |i|
		write_to_stream error_msg(i.reply, i.children, 'cancel', 'feature-not-implemented')
	end
end

class ReceiptMessage < Blather::Stanza
	def self.new(to=nil)
		node = super :message
		node.to = to
		node
	end
end

class WebhookHandler < Goliath::API
	use Goliath::Rack::Params

	def response(env)
		puts 'ENV: ' + env.reject{ |k| k == 'params' }.to_s

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
			puts "big problem: '" + params['direction'] + "'" + body
			return [200, {}, "OK"]
		end

		puts 'BODY - messageId: ' + params['messageId'] +
			', eventType: ' + params['eventType'] +
			', time: ' + params['time'] +
			', direction: ' + params['direction'] +
			', state: ' + params['state'] +
			', deliveryState: ' + (params['deliveryState'] ?
				params['deliveryState'] : 'NONE') +
			', deliveryCode: ' + (params['deliveryCode'] ?
				params['deliveryCode'] : 'NONE') +
			', deliveryDesc: ' + (params['deliveryDescription'] ?
				params['deliveryDescription'] : 'NONE') +
			', tag: ' + (params['tag'] ? params['tag'] : 'NONE') +
			', media: ' + (params['media'] ? params['media'].to_s :
				'NONE')

		if others_num[0] != '+'
			# TODO: check that others_num actually a shortcode first
			others_num +=
				';phone-context=ca-us.phone-context.soprani.ca'
		end

		jid_key = "catapult_jid-#{users_num}"
		bare_jid = REDIS.get(jid_key).promise.sync

		if !bare_jid
			puts "jid_key (#{jid_key}) DNE; Catapult misconfigured?"

			# TODO: likely not appropriate; give error to Catapult?
			# TODO: add text re credentials not being registered
			#write_to_stream error_msg(m.reply, m.body, :auth,
			#	'registration-required')
			return [200, {}, "OK"]
		end

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
						SGXcatapult.send_media(
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

at_exit do
	$stdout.sync = true

	puts "Soprani.ca/SMS Gateway for XMPP - Catapult\n"\
		"==>> last commit of this version is " + `git rev-parse HEAD` + "\n"

	if ARGV.size != 7
		puts "Usage: sgx-catapult.rb <component_jid> "\
			"<component_password> <server_hostname> "\
			"<server_port> <delivery_receipt_url> "\
			"<http_listen_port> <mms_proxy_prefix_url>"
		exit 0
	end

	t = Time.now
	puts "LOG %d.%09d: starting...\n\n" % [t.to_i, t.nsec]

	EM.run do
		REDIS = EM::Hiredis.connect

		SGXcatapult.run

		# required when using Prosody otherwise disconnects on 6-hour inactivity
		EM.add_periodic_timer(3600) do
			msg = Blather::Stanza::Iq::Ping.new(:get, 'localhost')
			msg.from = ARGV[0]
			SGXcatapult.write(msg)
		end

		server = Goliath::Server.new('0.0.0.0', ARGV[5].to_i)
		server.api = WebhookHandler.new
		server.app = Goliath::Rack::Builder.build(server.api.class, server.api)
		server.logger = Log4r::Logger.new('goliath')
		server.logger.add(Log4r::StdoutOutputter.new('console'))
		server.logger.level = Log4r::INFO
		server.start do
			["INT", "TERM"].each do |sig|
				trap(sig) do
					EM.defer do
						puts 'Shutting down gateway...'
						SGXcatapult.shutdown

						puts 'Gateway has terminated.'
						EM.stop
					end
				end
			end
		end
	end
end
