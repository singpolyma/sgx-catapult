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
