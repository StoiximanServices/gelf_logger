defmodule Logger.Backends.Gelf do
  @moduledoc """
  Gelf Logger Backend
  # GelfLogger [![Build Status](https://travis-ci.org/jschniper/gelf_logger.svg?branch=master)](https://travis-ci.org/jschniper/gelf_logger)

  A logger backend that will generate Graylog Extended Log Format messages. The
  current version only supports UDP messages.

  ## Configuration

  In the config.exs, add gelf_logger as a backend like this:

  ```
  config :logger,
    backends: [:console, {Logger.Backends.Gelf, :gelf_logger}]
  ```

  In addition, you'll need to pass in some configuration items to the backend
  itself:

  ```
  config :logger, :gelf_logger,
    host: "127.0.0.1",
    port: 12201,
    application: "myapp",
    compression: :gzip, # Defaults to :gzip, also accepts :zlib or :raw
    metadata: [:request_id, :function, :module, :file, :line],
    hostname: "hostname-override",
    tags: [
      list: "of",
      extra: "tags"
    ]
  ```

  In addition to the backend configuration, you might want to check the
  [Logger configuration](https://hexdocs.pm/logger/Logger.html) for other
  options that might be important for your particular environment. In
  particular, modifying the `:utc_log` setting might be necessary
  depending on your server configuration.

  ## Usage

  Just use Logger as normal.

  ## Improvements

  - [x] Tests
  - [ ] TCP Support
  - [x] Options for compression (none, zlib)
  - [x] Send timestamp instead of relying on the Graylog server to set it
  - [x] Find a better way of pulling the hostname

  And probably many more. This is only out here because it might be useful to
  someone in its current state. Pull requests are always welcome.

  ## Notes

  Credit where credit is due, this would not exist without
  [protofy/erl_graylog_sender](https://github.com/protofy/erl_graylog_sender).
  """

  use GenEvent

  @gelf_spec_version "1.1"
  @max_size 1047040
  @max_packet_size 8192
  @max_payload_size 8180
  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})

  def init({__MODULE__, name}) do
    if user = Process.whereis(:user) do
      Process.group_leader(self(), user)
      {:ok, configure(name, [])}
    else
      {:error, :ignore}
    end
  end

  def handle_call({:configure, options}, state) do
    {:ok, :ok, configure(state[:name], options)}
  end

  def handle_event({_level, gl, _event}, state) when node(gl) != node() do
    {:ok, state}
  end

  def handle_event({level, _gl, {Logger, msg, ts, md}}, %{level: min_level} = state) do
    if is_nil(min_level) or Logger.compare_levels(level, min_level) != :lt do
      log_event(level, to_string(msg), ts, md, state)
    end
    {:ok, state}
  end

  ## Helpers

  defp configure(name, options) do
    config = Keyword.merge(Application.get_env(:logger, name, []), options)
    Application.put_env(:logger, name, config)

    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
    {:ok, hostname} = :inet.gethostname

    hostname        = Keyword.get(config, :hostname, hostname)
    gl_host         = Keyword.get(config, :host) |> to_char_list
    port            = Keyword.get(config, :port)
    application     = Keyword.get(config, :application)
    level           = Keyword.get(config, :level)
    metadata        = Keyword.get(config, :metadata, [])
    compression     = Keyword.get(config, :compression, :gzip)
    tags            = Keyword.get(config, :tags, [])

    %{name: name, gl_host: gl_host, host: to_string(hostname), port: parse_port(port), metadata: metadata, level: level, application: application, socket: socket, compression: compression, tags: tags}
  end

  defp log_event(level, msg, ts, md, %{host: host, application: application, compression: compression} = state) do
    %{
      short_message: String.slice(msg, 0..79),
      version:       @gelf_spec_version,
      host:          host,
      level:         level_to_int(level),
      timestamp:     format_timestamp(ts),
      _facility:     application
    }
    |> full_message(msg)
    |> additional_fields(md, state)
    |> Poison.encode!()
    |> compress(compression)
    |> send_to_graylog(state)
  end

  defp send_to_graylog(data, state), do: do_send(data, byte_size(data), state)

  defp do_send(_data, size, _state) when size > @max_size do
    raise ArgumentError, message: "message too large"
  end
  defp do_send(data, size, %{socket: socket, gl_host: gl_host, port: port}) when size > @max_packet_size do
    num = div(size, @max_packet_size)
    num = if (num * @max_packet_size) < size, do: num + 1, else: num
    id = :crypto.strong_rand_bytes(8)

    send_chunks(socket, gl_host, port, data, id, :binary.encode_unsigned(num), 0, size)
  end
  defp do_send(data, _size, %{socket: socket, gl_host: gl_host, port: port}) do
    :gen_udp.send(socket, gl_host, port, data)
  end

  defp send_chunks(socket, host, port, data, id, num, seq, size) when size > @max_payload_size do
    <<payload :: binary - size(@max_payload_size), rest :: binary >> = data

    :gen_udp.send(socket, host, port, make_chunk(payload, id, num, seq))

    send_chunks(socket, host, port, rest, id, num, seq + 1, byte_size(rest))
  end

  defp send_chunks(socket, host, port, data, id, num, seq, _size) do
    :gen_udp.send(socket, host, port, make_chunk(data, id, num, seq))
  end

  defp make_chunk(payload, id, num, seq) do
    bin = :binary.encode_unsigned(seq)

    << 0x1e, 0x0f, id :: binary - size(8), bin :: binary - size(1), num :: binary - size(1), payload :: binary >>
  end

  defp parse_port(port) when is_binary(port) do
    {val, ""} = Integer.parse(to_string(port))
    val
  end
  defp parse_port(port), do: port

  defp additional_fields(data, metadata, %{metadata: metadata_fields, tags: tags}) do
    fields =
      metadata
      |> Keyword.take(metadata_fields)
      |> Keyword.merge(tags)
      |> Map.new(fn({k,v}) -> {"_#{k}", to_string(v)} end)
      |> Map.drop(["_id"]) # http://docs.graylog.org/en/2.2/pages/gelf.html "Libraries SHOULD not allow to send id as additional field (_id). Graylog server nodes omit this field automatically."
    Map.merge(data, fields)
  end

  defp full_message(data, msg) when byte_size(msg) > 80, do: Map.put(data, :full_message, msg)
  defp full_message(data, _msg), do: data

  defp compress(data, :gzip), do: :zlib.gzip(data)
  defp compress(data, :zlib), do: :zlib.compress(data)
  defp compress(data, _),     do: data

  defp format_timestamp({{year, month, day}, {hour, min, sec, milli}}) do
    {{year, month, day}, {hour, min, sec}}
      |> :calendar.datetime_to_gregorian_seconds()
      |> Kernel.-(@epoch)
      |> Kernel.+(milli / 1000)
      |> Float.round(3)
  end

  defp level_to_int(:debug), do: 7
  defp level_to_int(:info),  do: 6
  defp level_to_int(:warn),  do: 4
  defp level_to_int(:error), do: 3

end
