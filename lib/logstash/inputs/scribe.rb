require "logstash/inputs/base"
require "logstash/namespace"
require "scribe"
require "thread"
require "time"

class ScribeHandler
  def initialize(target_buffer_size)
    @target_buffer_size = target_buffer_size
    @internal_queue = Queue.new()
    @queue_lock = Mutex.new()
  end


  # Doing anything potentially time consuming inside of a Scribe Log() call can
  # lead to nasty situations where a temporary slowdown will cause repeated
  # attempts to retry the call, pushing ever more duplicate messages into
  # memory. At the same time we don't have a solid upper bound on the size of a
  # batch that we might receive, and if we refuse to handle a very large batch
  # it will block processing indefinitely while it is retried.
  #
  # The solution to both of these problems is to push messages into an
  # unbounded queue (which must therefore be separate from the logstash
  # output_queue) that is processed asynchronously, but to reject new messages
  # when that queue exceeds a defined size.
  #
  def Log(entries)
    @queue_lock.synchronize do
      if @internal_queue.length() < @target_buffer_size
        entries.each {|entry| @internal_queue << entry }
        return ScribeThrift::ResultCode::OK
      else
        return ScribeThrift::ResultCode::TRY_LATER
      end
    end
  end

  def pop()
    return @internal_queue.pop()
  end
end


class ScribeCompatibleBinaryProtocolFactory < Thrift::BinaryProtocolFactory
  def get_protocol(trans)
    return Thrift::BinaryProtocol.new(trans, false, false)
  end
end


# Implement a Scribe interface to receive gelf or logstash formatted events.
class LogStash::Inputs::Scribe < LogStash::Inputs::Base

  config_name "scribe"
  plugin_status "experimental"

  # The address to listen on.
  config :host, :validate => :string, :default => "0.0.0.0"

  # The port to listen on.
  config :port, :validate => :number, :required => true

  # Whether to operate in gelf mode.
  config :gelf_mode, :validate => :boolean, :default => false

  # How many messages to buffer before telling scribe to try later
  config :target_scribe_buffer_size, :validate => :number, :default => 1024

  def initialize(*args)
    super(*args)
  end

  public
  def register
    @logger.info("Starting scribe input listener", :address => "#{@host}:#{@port}")
    @handler = ScribeHandler.new(@target_scribe_buffer_size)
    processor = ScribeThrift::Processor.new(@handler)
    transport = Thrift::ServerSocket.new(@host, @port)
    transport_factory = Thrfit::FramedTransportFactory.new()
    protocol_factory = ScribeCompatibleProtocolFactory.new()
    @server = Thrift::NonblockingServer.new(processor, transport, transport_factory, protocol_factory)
  end

  public
  def run(output_queue)
    pusher = Thread.start(@handler) do |h|
      loop do
        entry = h.pop

        if @gelf_mode
          output_queue << to_gelf_event(entry.message)
        else
          output_queue << to_event(entry.message, entry.category)
        end
      end
    end

    @server.serve
    pusher.kill
  end

  private
  def to_gelf_event(message)
    # TODO: complete implementation of gelf -> logstash transformation
    event = LogStash::Event.new
    gelf = JSON.parse(message.force_encoding("UTF-8"))

    event.message = gelf["full_message"] || gelf["short_message"]
    event.source_host = gelf["host"]
    event.source_path = gelf["facility"]
    event.source = "gelf://#{event.source_host}/#{event.source_path}"

    return event
  end

  public
  def teardown
    @server.shutdown
  end
end
