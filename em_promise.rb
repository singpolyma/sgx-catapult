#!/usr/bin/env ruby
#
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

require "eventmachine"
require "promise"

class EMPromise < Promise
	def initialize(deferrable=nil)
		super()
		fulfill(deferrable) if deferrable
	end

	def fulfill(value, bind_defer=true)
		if bind_defer && value.is_a?(EM::Deferrable)
			value.callback { |x| fulfill(x, false) }
			value.errback(&method(:reject))
		else
			super(value)
		end
	end

	def defer
		EM.next_tick { yield }
	end

	def wait
		fiber = Fiber.current
		resume = proc do |arg|
			defer { fiber.resume(arg) }
		end

		self.then(resume, resume)
		Fiber.yield
	end

	def self.reject(e)
		new.tap { |promise| promise.reject(e) }
	end

	def self.all(enumerable)
		super(enumerable.map { |input|
			if input.respond_to?(:promise)
				input.promise
			else
				input
			end
		})
	end
end

module EventMachine
	module Deferrable
		def promise
			EMPromise.new(self)
		end

		[:then, :rescue, :catch].each do |method|
			define_method(method) do |*args, &block|
				promise.public_send(method, *args, &block)
			end
		end
	end
end
