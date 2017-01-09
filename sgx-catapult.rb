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

require 'blather/client/dsl'

if ARGV.size != 4 then
	puts "Usage: sgx-catapult.rb <component_jid> <component_password> " +
		"<server_hostname> <server_port>"
	exit 0
end

module SGXcatapult
	extend Blather::DSL

	def self.run
		client.run
	end

	setup ARGV[0], ARGV[1], ARGV[2], ARGV[3]

	message :chat?, :body do |m|
		begin
			puts "#{m.from.to_s} -> #{m.to.to_s} #{m.body}"
			msg = Blather::Stanza::Message.new(m.from, 'thx for "' +
				m.body + '"')
			msg.from = m.to
			write_to_stream msg
		rescue => e
			# TODO: do something better with this info
			say m.from, e.inspect
		end
	end

	iq do |i|
		puts "IQ: #{i.inspect}"

		if i.type == :set
			puts "received set, likely for jabber:iq:register"

			# success (for now)
			msg = Blather::Stanza::Iq.new
			msg.id = i.id
			msg.to = i.from
			msg.type = 'result'

			puts "RESPONSE3: #{msg.inspect}"
			write_to_stream msg
			puts "SENT"

			# TODO: implement this (verify/save data, return result)
			next
		end

		query_node = i.children.find { |v| v.element_name == "query" }
		if query_node.namespace.href ==
			'http://jabber.org/protocol/disco#items'

			msg = Blather::Stanza::Iq::DiscoItems.new
			msg.id = i.id
			msg.to = i.from
			msg.type = 'result'

			puts "RESPONSE0: #{msg.inspect}"
			write_to_stream msg
			puts "SENT"
		elsif query_node.namespace.href ==
			'http://jabber.org/protocol/disco#info'

			msg = Blather::Stanza::Iq::DiscoInfo.new
			msg.id = i.id
			msg.to = i.from
			msg.type = 'result'

			msg.identities = [{:name =>
				'Soprani.ca Gateway to XMPP - Catapult',
				:type => 'sms-ctplt', :category => 'gateway'}]
			msg.features = ["jabber:iq:register",
				"jabber:iq:gateway", "jabber:iq:private",
				"http://jabber.org/protocol/disco#info",
				"http://jabber.org/protocol/commands",
				"http://jabber.org/protocol/muc"]
			puts "RESPONSE1: #{msg.inspect}"
			write_to_stream msg
			puts "SENT"
		elsif query_node.namespace.href == 'jabber:iq:register'
			orig = Blather::Stanza::Iq.new
			orig.id = i.id
			orig.to = i.from
			orig.type = 'result'

			msg = Nokogiri::XML::Node.new 'query',orig.document
			msg['xmlns'] = 'jabber:iq:register'
			n1 = Nokogiri::XML::Node.new 'instructions',msg.document
			n1.content= "Enter the information from your Account " +
				"page as well as the Phone Number\nin your " +
				"account you want to use (ie. '+12345678901')" +
				".\n\nThe source code for this gateway is at " +
				"https://github.com/ossguy/sgx-catapult ." +
				"\nCopyright (C) 2017  Denver Gingerich, " +
				"licensed under AGPLv3+."
			n2 = Nokogiri::XML::Node.new 'user_id',msg.document
			n3 = Nokogiri::XML::Node.new 'api_token',msg.document
			n4 = Nokogiri::XML::Node.new 'api_secret',msg.document
			n5 = Nokogiri::XML::Node.new 'phone_number',msg.document
			msg.add_child(n1)
			msg.add_child(n2)
			msg.add_child(n3)
			msg.add_child(n4)
			msg.add_child(n5)

			x = Nokogiri::XML::Node.new 'x',orig.document
			x['xmlns'] = 'jabber:x:data'
			x['type'] = 'form'
			msg.add_child(x)

			title = Nokogiri::XML::Node.new 'title',orig.document
			title.content= 'Register for ' +
				'Soprani.ca Gateway to XMPP - Catapult'
			x.add_child(title)

			instr = Nokogiri::XML::Node.new 'instructions',
				orig.document
			instr.content= "Enter the details from your Account " +
				"page as well as the Phone Number\nin your " +
				"account you want to use (ie. '+12345678901')" +
				".\n\nThe source code for this gateway is at " +
				"https://github.com/ossguy/sgx-catapult ." +
				"\nCopyright (C) 2017  Denver Gingerich, " +
				"licensed under AGPLv3+."
			x.add_child(instr)

			f1 = Nokogiri::XML::Node.new 'field',orig.document
			f1['type'] = 'hidden'
			f1['var'] = 'FORM_TYPE'
			v1 = Nokogiri::XML::Node.new 'value',orig.document
			v1.content= 'jabber:iq:register'
			f1.add_child(v1)
			x.add_child(f1)

			f2 = Nokogiri::XML::Node.new 'field',orig.document
			f2['type'] = 'text-single'
			f2['label'] = 'User Id'
			f2['var'] = 'user_id'
			v2 = Nokogiri::XML::Node.new 'required',orig.document
			f2.add_child(v2)
			x.add_child(f2)

			f3 = Nokogiri::XML::Node.new 'field',orig.document
			f3['type'] = 'text-single'
			f3['label'] = 'API Token'
			f3['var'] = 'api_token'
			v3 = Nokogiri::XML::Node.new 'required',orig.document
			f3.add_child(v3)
			x.add_child(f3)

			f4 = Nokogiri::XML::Node.new 'field',orig.document
			f4['type'] = 'text-private'
			f4['label'] = 'API Secret'
			f4['var'] = 'api_secret'
			v4 = Nokogiri::XML::Node.new 'required',orig.document
			f4.add_child(v4)
			x.add_child(f4)

			f5 = Nokogiri::XML::Node.new 'field',orig.document
			f5['type'] = 'text-single'
			f5['label'] = 'Phone Number'
			f5['var'] = 'phone_number'
			v5 = Nokogiri::XML::Node.new 'required',orig.document
			f5.add_child(v5)
			x.add_child(f5)

			orig.add_child(msg)
			puts "RESPONSE2: #{orig.inspect}"
			write_to_stream orig
			puts "SENT"
		end
	end

	subscription(:request?) do |s|
		# TODO: fix these - they don't actual work; write does not exist
		#write(s.approve!)
		#write(s.request!)
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

EM.run do
	SGXcatapult.run
end
