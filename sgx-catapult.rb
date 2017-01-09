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

	iq '/iq/ns:query', :ns =>
		'http://jabber.org/protocol/disco#items' do |i, xpath_result|

		write_to_stream i.reply
	end

	iq '/iq/ns:query', :ns =>
		'http://jabber.org/protocol/disco#info' do |i, xpath_result|

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

			if xn.nil?
				puts "id: " + qn.children.find {
					|v| v.element_name == "nick" }
				puts "token: " + qn.children.find {
					|v| v.element_name == "username" }
				puts "secret: " + qn.children.find {
					|v| v.element_name == "password" }
				puts "phone num: " + qn.children.find {
					|v| v.element_name == "phone" }
				next
			end

			for field in xn.children
				if field.element_name == "field"
					val = field.children.find { |v|
						v.element_name == "value" }

					case field['var']
					when 'nick'
						puts "id: " + val.text
					when 'username'
						puts "token: " + val.text
					when 'password'
						puts "secret: " + val.text
					when 'phone'
						puts "phone num: " + val.text
					when 'FORM_TYPE'
						puts "FORM_TYPE: " + val.text
					else
						# TODO: error
						puts "weird var: " +field['var']
					end
				end
			end

			# success (for now)
			write_to_stream i.reply

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
				"\nCopyright (C) 2017  Denver Gingerich, " +
				"licensed under AGPLv3+."
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
				"\nCopyright (C) 2017  Denver Gingerich, " +
				"licensed under AGPLv3+."
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

EM.run do
	SGXcatapult.run
end
